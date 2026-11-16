# Release image: the static musl binary from the release build on distroless
# (CA certificates for --system-roots, no shell, unprivileged user 65532).
# The build context holds one binary per architecture as ARCH/testls
# (amd64, arm64); see the container job in .github/workflows/release.yml.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
ARG TARGETARCH
COPY --chmod=755 ${TARGETARCH}/testls /usr/local/bin/testls
LABEL org.opencontainers.image.source="https://github.com/kjpopov/testls" \
      org.opencontainers.image.description="TLS/SSL scanner for the web era, inspired by testssl.sh." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
ENTRYPOINT ["/usr/local/bin/testls"]
