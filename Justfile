# ansible-operator task runner. Run `just` to list recipes.

# Deny broken intra-doc links / bare URLs in the API reference (rustdoc).
export RUSTDOCFLAGS := "-D rustdoc::broken_intra_doc_links -D rustdoc::bare_urls"

# List available recipes.
default:
    @just --list

# Build the user & operator guide (the mdBook under docs/) to docs/book/.
docs:
    mdbook build docs

# Serve the guide locally with live reload (http://localhost:3000) and open it.
docs-serve:
    mdbook serve docs --open

# Build the generated API reference (rustdoc) for the operator's internals.
apidoc:
    cargo doc --no-deps --document-private-items

# Compile the operator.
build:
    cargo build

# Run the unit tests.
test:
    cargo test

# Lint (must stay clean — see AGENTS.md).
clippy:
    cargo clippy

# The full pre-change gate: build + test + clippy + guide + API docs.
check: build test clippy docs apidoc

# Dump all CRDs (PlaybookPlan, Play, ClusterInventory, StaticInventory, NodeAccessPolicy) to stdout.
crds:
    cargo run --quiet -- crds

# Regenerate the CRD templates in the built-in Helm subchart.
generate-crds:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    cat > "$tmp_dir/annotation" <<'ANNOTATION'
      {{{{- if .Values.keep }}
      annotations:
        helm.sh/resource-policy: keep
      {{{{- end }}
    ANNOTATION
    cargo run --quiet -- crds > "$tmp_dir/all-crds.yaml"
    csplit -z -f "$tmp_dir/crd-" "$tmp_dir/all-crds.yaml" '/^---$/' '{*}' > /dev/null
    # The recipe is authoritative for the directory: a CRD removed or renamed in the Rust
    # source must not keep shipping as a leftover template.
    rm -f chart/charts/crds/templates/*.yaml
    for file in "$tmp_dir"/crd-*; do
        name="$(grep -m1 '^  name:' "$file" | awk '{print $2}')"
        sed -i '/^---$/d' "$file"
        # Opt-in retention: without this Helm garbage-collects the CRDs on `helm uninstall`,
        # taking every custom resource in the cluster with them.
        sed -i "/^metadata:$/r $tmp_dir/annotation" "$file"
        cp "$file" "chart/charts/crds/templates/${name}.yaml"
    done
