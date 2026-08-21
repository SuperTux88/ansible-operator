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

# Set the release version in Cargo and both chart metadata files, commit it and tag it.
# Nothing is pushed — review, then `git push --follow-tags`.
# The tag is what the release workflow builds from.
release $version:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
        echo "expected a semver version without the leading v, e.g. 1.2.3 — got '$version'" >&2
        exit 1
    fi
    if ! git diff --quiet HEAD; then
        echo "working tree has uncommitted changes; commit or stash them first" >&2
        exit 1
    fi
    if git rev-parse -q --verify "refs/tags/v$version" > /dev/null; then
        echo "tag v$version already exists" >&2
        exit 1
    fi
    sed -i -E "0,/^version = .*/s//version = \"$version\"/" Cargo.toml
    # Keeps Cargo.lock in step so a --locked build of the tag does not fail.
    cargo update --workspace --offline
    sed -i -E "s/^version: .* # VERSION$/version: $version # VERSION/" chart/Chart.yaml
    sed -i -E "s/^appVersion: .*/appVersion: \"$version\"/" chart/Chart.yaml
    sed -i -E "s/^    version: .* # VERSION$/    version: $version # VERSION/" chart/Chart.yaml
    sed -i -E "s/^version: .* # VERSION$/version: $version # VERSION/" chart/charts/crds/Chart.yaml
    git add Cargo.toml Cargo.lock chart/Chart.yaml chart/charts/crds/Chart.yaml
    git commit -m "chore(release): v$version"
    git tag -a "v$version" -m "v$version"
    echo "committed and tagged v$version — push with: git push --follow-tags"
