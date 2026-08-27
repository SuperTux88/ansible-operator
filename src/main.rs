//! # Ansible Operator
//!
//! A Kubernetes operator that runs Ansible playbooks against your cluster's own Nodes and against
//! arbitrary external hosts, on a schedule, idempotently, without a standing privileged agent on
//! your nodes.
//!
//! This is the generated **API reference** for the operator binary's internals. The narrative
//! **user & operator guide** — what the operator does, how to author `PlaybookPlan`s and
//! inventories, and how to deploy and secure it — is a separate mdBook under `docs/` (build it with
//! `just docs`, or read the published site). Start there unless you are working on the operator
//! itself.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use futures_util::StreamExt as _;
use kube::CustomResourceExt as _;
use kube::config::KubeConfigOptions;
use kube::runtime::controller::Error as ControllerError;
use tokio::join;
use tracing::{debug, info, warn};
use tracing_subscriber::util::SubscriberInitExt as _;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt as _};

use v1beta1::ca::CertificateAuthority;

mod config;
mod utils;
mod v1beta1;

use config::OperatorConfig;

#[derive(Parser)]
#[command(
    name = "ansible-operator",
    about = "Kubernetes operator for running Ansible playbooks against cluster nodes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the operator control loop (the normal in-cluster entrypoint).
    Run(RunArgs),
    /// Print the CRD manifests (YAML) to stdout and exit.
    Crds,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Path to the operator config file (enrolled namespaces, see R1). In-cluster this is the
    /// chart-rendered ConfigMap mounted at the default path; override it for local runs.
    #[arg(long, short, default_value = config::DEFAULT_CONFIG_PATH)]
    config: String,
}

#[tokio::main]
async fn main() {
    match Cli::parse().command {
        Command::Crds => print!("{}", render_crds()),
        Command::Run(args) => run(args).await,
    }
}

/// Renders all CRDs as a single multi-document YAML string for chart generation and `kubectl apply`.
/// See `chart/README.md` for how the bundled snapshot is regenerated.
fn render_crds() -> String {
    let playbookplan = v1beta1::PlaybookPlan::crd();
    let play = v1beta1::Play::crd();
    let cluster_inventory = v1beta1::ClusterInventory::crd();
    let static_inventory = v1beta1::StaticInventory::crd();
    let node_access_policy = v1beta1::NodeAccessPolicy::crd();
    [
        serde_yaml::to_string(&playbookplan).unwrap(),
        serde_yaml::to_string(&play).unwrap(),
        serde_yaml::to_string(&cluster_inventory).unwrap(),
        serde_yaml::to_string(&static_inventory).unwrap(),
        serde_yaml::to_string(&node_access_policy).unwrap(),
    ]
    .join("---\n")
}

async fn run(args: RunArgs) {
    setup_tracing();

    let operator_namespace = std::env::var("POD_NAMESPACE").expect("POD_NAMESPACE must be set");

    // Enrollment allowlist (R1 / T-INFO-1): the operator only reads/writes Secrets and creates Jobs
    // in namespaces it is enrolled for. Read once at startup from the config file (the Helm-rendered
    // ConfigMap in-cluster, default path); a change to it rolls this pod (checksum/config annotation)
    // rather than being hot-reloaded. Override the path with `run --config <path>` for local runs.
    let operator_config = OperatorConfig::load(&args.config)
        .unwrap_or_else(|e| panic!("failed to load operator config: {e}"));
    let enrolled_namespaces = operator_config.enrolled_namespaces(&operator_namespace);
    tracing::info!(
        "enrolled namespaces (Secret/Job access is scoped to these): {:?}",
        enrolled_namespaces
    );

    // Managed-ssh proxy image (T-ESC-5): set via the chart's `managedSsh.proxyImage`, surfaced here
    // through the config file. There is NO built-in default for this node-root image — it must be an
    // explicit admin choice — so a missing/empty value is a fatal startup error. Pin to a trusted
    // digest in production.
    let proxy_image = operator_config
        .require_proxy_image()
        .unwrap_or_else(|e| panic!("{e}"))
        .to_string();

    // Adaptive readiness-grace policy for managed-ssh proxy pods on NotReady nodes, from the chart's
    // `managedSsh.readiness`. `ProxyGracePolicy::new` clamps `aggressiveness` and converts days→secs.
    let proxy_grace = v1beta1::playbookplancontroller::ProxyGracePolicy::new(
        operator_config.managed_ssh.grace_seconds,
        operator_config.managed_ssh.aggressiveness,
        operator_config.managed_ssh.threshold_days,
    );

    // Connect to the cluster only after the static config has validated — fail fast on a bad/missing
    // config (e.g. no proxy_image) before any network I/O.
    let client = kube::client::Client::try_from(discover_kubernetes_config().await).unwrap();

    // Ephemeral, in-memory CA: a fresh keypair per operator process, never persisted to the
    // cluster. Restarting the operator rotates the CA and invalidates all outstanding certs.
    let ca = Arc::new(
        CertificateAuthority::generate()
            .expect("failed to generate the operator's ephemeral SSH certificate authority"),
    );

    let playbookplan_controller = v1beta1::playbookplancontroller::reconciler::new(
        client.clone(),
        operator_namespace,
        enrolled_namespaces,
        ca,
        proxy_image,
        proxy_grace,
        v1beta1::playbookplancontroller::reconciler::WorkloadEgressPolicies {
            playbook: operator_config.playbook_network_policy_egress,
            managed_ssh: operator_config.managed_ssh_network_policy_egress,
        },
    )
    .for_each(|outcome| async move { report_outcome("PlaybookPlan", outcome) });

    let inventory_controller = v1beta1::clusterinventorycontroller::new(client.clone())
        .for_each(|outcome| async move { report_outcome("ClusterInventory", outcome) });

    let node_access_policy_controller = v1beta1::nodeaccesspolicycontroller::new(client)
        .for_each(|outcome| async move { report_outcome("NodeAccessPolicy", outcome) });

    join!(
        playbookplan_controller,
        inventory_controller,
        node_access_policy_controller
    );
}

/// Reports what one controller made of one object, for the three controllers that share a
/// reconcile loop shape.
///
/// `ObjectNotFound` is deliberately not a warning. It means a reconcile was scheduled for an object
/// that is no longer in the local store by the time the runner reached it — which is what deleting a
/// resource looks like from here, and also what a watch mapping that names a resource someone else
/// has since removed looks like. Nothing was attempted and nothing needs attention, so reporting it
/// as a failed reconcile invited a reader to hunt for a problem that does not exist. It is still
/// worth an `info!`: it corresponds to something a person did, and the operator falling silent on a
/// deletion is its own kind of confusing.
///
/// Everything else keeps `warn!` but is rendered through `Display` rather than `Debug`: the error
/// types already say which object they concern, and the debug form spelled out the whole
/// `ObjectRef` — API group, version, plural, UID — around a message that was usually one line.
fn report_outcome<T, E, Q>(kind: &str, outcome: Result<T, ControllerError<E, Q>>)
where
    T: std::fmt::Debug,
    E: std::error::Error + 'static,
    Q: std::error::Error + 'static,
{
    match outcome {
        Ok(object) => debug!(controller = kind, "reconciled {object:?}"),
        Err(ControllerError::ObjectNotFound(object)) => {
            info!(
                controller = kind,
                "{object} no longer exists; nothing to reconcile"
            )
        }
        Err(error) => warn!(controller = kind, "{error}"),
    }
}

fn setup_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .try_init()
        .expect("tracing-subscriber setup failed");
}

async fn discover_kubernetes_config() -> kube::Config {
    let from_default_kubeconfig =
        kube::Config::from_kubeconfig(&KubeConfigOptions::default()).await;

    if let Ok(config) = from_default_kubeconfig {
        return config;
    }

    let from_incluster_env = kube::Config::incluster_env();

    if let Ok(config) = from_incluster_env {
        return config;
    }

    panic!("Failed to find a suitable Kubernetes client config.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_parses_config_flag() {
        let cli =
            Cli::try_parse_from(["ansible-operator", "run", "--config", "/etc/foo.toml"]).unwrap();
        match cli.command {
            Command::Run(args) => assert_eq!(args.config, "/etc/foo.toml"),
            Command::Crds => panic!("expected the run subcommand"),
        }
    }

    #[test]
    fn run_config_defaults_to_the_mounted_path() {
        let cli = Cli::try_parse_from(["ansible-operator", "run"]).unwrap();
        match cli.command {
            Command::Run(args) => assert_eq!(args.config, config::DEFAULT_CONFIG_PATH),
            Command::Crds => panic!("expected the run subcommand"),
        }
    }

    #[test]
    fn crds_subcommand_parses() {
        let cli = Cli::try_parse_from(["ansible-operator", "crds"]).unwrap();
        assert!(matches!(cli.command, Command::Crds));
    }

    #[test]
    fn a_missing_subcommand_is_an_error() {
        assert!(Cli::try_parse_from(["ansible-operator"]).is_err());
    }
}
