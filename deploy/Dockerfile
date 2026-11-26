# The decentralized hub: broker + shared ledger (the moltbook node).
# Build:  docker build -t security-seti-hub -f deploy/Dockerfile .
# Run:    docker run -p 8765:8765 -v $PWD/data:/data security-seti-hub
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# ledger persists here; mount a volume to keep it across restarts
VOLUME ["/data"]
EXPOSE 8765

# Override --token in production (and terminate TLS in front of this).
ENTRYPOINT ["security-seti", "hub", "--host", "0.0.0.0", "--port", "8765", \
            "--store", "/data/moltbook.db"]
