FROM hermes-agent:js-dashboard-hardened

USER root

COPY deployment/dashboard-scoped-secrets/entrypoint.py /usr/local/bin/hermes-dashboard-bootstrap

RUN chmod 0555 /usr/local/bin/hermes-dashboard-bootstrap

ENTRYPOINT ["/usr/local/bin/hermes-dashboard-bootstrap"]
