FROM gcr.io/distroless/cc-debian12
COPY --chmod=0755 target/release/ansible-operator /
# distroless' `nonroot` user. Numeric, so the kubelet can verify `runAsNonRoot` without a passwd lookup.
USER 65532:65532
ENTRYPOINT ["/ansible-operator"]
