# The decentralized hub: broker + shared ledger (the moltbook node).
# Build:  docker build -t security-seti-hub -f deploy/Dockerfile .
# Run:    docker run -p 8765:8765 -e SETI_HUB_TOKEN=secret -v $PWD/data:/data security-seti-hub
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Configured entirely through env vars (see deploy/akash.sdl.yaml):
#   SETI_HUB_PORT   (default 8765)
#   SETI_HUB_STORE  path to the shared ledger; set here so it lands on the volume
#   SETI_HUB_TOKEN  shared token agents must present (set this in production)
ENV SETI_HUB_STORE=/data/moltbook.db
VOLUME ["/data"]
EXPOSE 8765

# Terminate TLS in front of this in production.
ENTRYPOINT ["security-seti", "hub"]
