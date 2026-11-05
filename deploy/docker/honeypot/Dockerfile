# Honeypot image (F11 discovery): a vulnerable decoy server that runs injected commands under
# strace, so attack syscalls are captured for the rule-generation loop to mine. Isolated use only.
# Self-contained build context (deploy/docker/honeypot) so the repo-root .dockerignore does not apply.
FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 strace ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /app/server.py
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["python3", "/app/server.py"]
