FROM hermes-agent:js-dashboard-hardened

RUN apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

COPY deployment/direct-secrets/entrypoint.py /usr/local/bin/hermes-direct-secrets
RUN chmod 0555 /usr/local/bin/hermes-direct-secrets

ENTRYPOINT ["/usr/local/bin/hermes-direct-secrets"]
