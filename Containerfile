FROM gcr.io/distroless/cc-debian12
COPY --chmod=0755 target/release/ansible-operator /
ENTRYPOINT ["/ansible-operator"]
