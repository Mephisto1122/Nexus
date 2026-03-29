FROM python:3.12-slim

LABEL maintainer="Nexus Gate" \
      description="Nexus Gate — Dashboard Server" \
      org.opencontainers.image.source="https://github.com/Mephisto1122/Nexus"

RUN groupadd -r nexus && useradd -r -g nexus -d /home/nexus -s /bin/bash nexus

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY nexus_server.py nexus_dashboard.html ./

RUN mkdir -p /data && chown nexus:nexus /data
VOLUME /data

ENV NEXUS_DATA_DIR=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER nexus

EXPOSE 7070

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sfk https://localhost:7070/health || exit 1

ENTRYPOINT ["python3", "/app/nexus_server.py"]
CMD ["--no-browser", "--bind", "0.0.0.0", "--tls"]
