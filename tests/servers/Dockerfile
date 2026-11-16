FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
# Run unprivileged: 4433 needs no root, and only the server user may read the key.
COPY --chown=nobody:nogroup --chmod=0400 server.pem server.key /
USER nobody
ENTRYPOINT ["openssl", "s_server", "-www", "-cert", "/server.pem", "-key", "/server.key", "-accept", "4433"]
