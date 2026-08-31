# Variables and files

A playbook usually needs data: variables (often secret) and sometimes files (configs, binaries,
archives). Both are supplied under `spec.template` and are folded into the
[execution hash](./scheduling-and-modes.md#drift-detection), so changing them re-triggers the
affected hosts.

## Variables

`template.variables` is a list; each entry is one of two shapes. Every entry is passed to Ansible as
`--extra-vars`, so later entries win over earlier ones on key collisions, exactly as with
`ansible-playbook`.

### Inline

Literal values written straight into the plan. Good for non-secret configuration.

```yaml
template:
  variables:
    - inline:
        package_state: latest
        reboot_allowed: false
        nested:
          key: value
```

### From a Secret

Pull variables from a Kubernetes Secret in the plan's namespace — the right choice for credentials,
tokens, or anything you would not commit in plaintext. The Secret **must** contain a data key named
exactly **`variables.yaml`**, whose value is a YAML mapping of variables:

```yaml
template:
  variables:
    - secretRef:
        name: playbook-secrets
```

Create such a Secret from a YAML file:

```sh
kubectl create secret generic playbook-secrets \
  --namespace my-team \
  --from-file=variables.yaml=./secret-vars.yaml
```

You can combine both kinds — e.g. inline non-secret defaults plus a `secretRef` for the sensitive
values. Because the operator watches referenced Secrets, editing the Secret changes the execution
hash and re-applies the plan.

## Files

`template.files` makes blobs available inside the run's **workspace** — the directory
`/run/ansible-operator`, which is also the playbook's working directory. Each entry has a `name`
(which becomes a subdirectory under `files/`) and a source. A file entry named `my-assets` is mounted
at:

```text
/run/ansible-operator/files/my-assets/...
```

so the playbook can read it there, or via the relative path `files/my-assets/...`.

The `name` is that one directory, so it has to be a single path component: not empty, not `.` or
`..`, and with no `/`, `:` or control characters in it. Anything else is refused with a message on
the plan and no run is started — a name that is a *path* would mount your Secret somewhere else in
the run's pod entirely. Two entries may not share a name either: they would claim one directory, and
the operator will not pick between them for you. Letters, digits, dots, dashes and underscores are
all fine, in any case: `TLS_certs` and `assets.v2` are valid names.

### From a Secret

Mounts a Secret's keys as files under the entry's directory — the way to ship certificates, config
files, or small credentials to the run:

```yaml
template:
  files:
    - name: tls
      secretRef:
        name: some-configs        # each key of this Secret becomes a file under files/tls/
```

### From another Kubernetes volume

Any entry that is **not** a `secretRef` is passed through as a raw Kubernetes
[Volume](https://kubernetes.io/docs/concepts/storage/volumes/): whatever fields you put next to
`name` are interpreted as a volume source. This makes larger, non-secret blobs available without
rebaking them into your Ansible `image`. The main use is an
[image volume](https://kubernetes.io/docs/tasks/configure-pod-container/image-volumes/), which mounts
the contents of an OCI image (binaries, archives, static assets):

```yaml
template:
  files:
    - name: binary-assets
      image:
        reference: my.registry.example.com/the-assets:v2
        pullPolicy: IfNotPresent
```

The playbook then reads them from `/run/ansible-operator/files/binary-assets/...`.

Each entry must name exactly one volume source that the operator's Kubernetes API version
recognizes, and its fields must survive typed decoding intact. The operator performs this check
before it records a new run or acquires host locks, so an unknown source or a nested typo such as
`configMap.nmae` is refused on the `PlaybookPlan` instead of leaving an uncreatable Job holding its
hosts.

> **Note:** image volumes are a newer Kubernetes feature and are not yet supported by every container
> runtime. If your runtime lacks support, ship the blob a different way (a Secret file, or bake it
> into the `image`). Because the field is a pass-through, an unsupported volume may still fail when
> Kubernetes starts the Job even after its shape passes the operator's preflight check.

## Requirements (collections)

Distinct from files and variables, `template.requirements` is an Ansible `requirements.yml` installed
before the playbook runs — see
[Playbook plans → choosing the image](./playbook-plans.md#choosing-the-image).
