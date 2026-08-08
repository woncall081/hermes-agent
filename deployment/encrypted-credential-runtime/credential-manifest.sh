#!/bin/sh
# name|persistent-path|runtime-relative-path
hermes_credentials() {
    cat <<'EOF'
op-connect-credentials|/run/hermes-connect-provision/1password-credentials.json|bootstrap/op-connect-credentials
op-connect-token|/run/hermes-connect-provision/connect-token|bootstrap/op-connect-token
default-env|/home/hermes/.hermes/.env|.env
agency-env|/home/hermes/.hermes/profiles/agency/.env|profiles/agency/.env
default-auth|/home/hermes/.hermes/auth.json|auth.json
be-auth|/home/hermes/.hermes/profiles/be/auth.json|profiles/be/auth.json
fe-auth|/home/hermes/.hermes/profiles/fe/auth.json|profiles/fe/auth.json
codex-auth|/home/hermes/.hermes/home/.codex/auth.json|codex/auth.json
codex-config|/home/hermes/.hermes/home/.codex/config.toml|codex/config.toml
agency-google-client-secret|/home/hermes/.hermes/profiles/agency/google_client_secret.json|profiles/agency/google_client_secret.json
agency-google-token|/home/hermes/.hermes/profiles/agency/google_token.json|profiles/agency/google_token.json
EOF
}

# tree-name|persistent-directory|runtime-relative-directory
hermes_credential_trees() {
    cat <<'EOF'
mcp-tokens|/home/hermes/.hermes/mcp-tokens|mcp-tokens
EOF
}
