FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping ca-certificates procps iptables \
    && rm -rf /var/lib/apt/lists/*
