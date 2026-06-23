#!/usr/bin/env bash
# End-to-end deploy script for the b2b-saml-sp demo.
#
# Phase 1: build Lambda zip + SAM deploy (Lambda + IAM + DynamoDB + ACM cert)
# Phase 2: post-deploy CLI steps (Function URL + CloudFront + Route 53)
#
# Required env (export before running, or source from a .env.deploy file):
#   STACK_NAME             - CFN stack name (default: b2b-saml-sp)
#   APP_REGION             - AWS region for Lambda + ACM + everything (default: us-east-1)
#   DOMAIN                 - Public domain (default: totalcontrol.demo-connect.us)
#   HOSTED_ZONE_ID         - Route 53 hosted zone ID for the parent zone
#   SESSION_SECRET         - Random string for express-session signing
#   TOKEN_EXCHANGE_CLIENT_SECRET
#   PROFILE_MGMT_CLIENT_SECRET
#   OIDC_CLIENT_SECRET

set -euo pipefail

cd "$(dirname "$0")/.."

# Auto-load .env (and an optional .env.deploy) so secrets and the zone ID
# stored there flow through to sam + post-deploy. Any var already set in
# the parent shell wins because we set -a *after* shell init.
for f in .env .env.deploy; do
  if [ -f "$f" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$f"
    set +a
    echo "==> loaded $f"
  fi
done

STACK_NAME="${STACK_NAME:-b2b-saml-sp}"
APP_REGION="${APP_REGION:-us-east-1}"
DOMAIN="${DOMAIN:-totalcontrol.demo-connect.us}"
: "${HOSTED_ZONE_ID:?must set HOSTED_ZONE_ID (Route 53 zone for the parent of $DOMAIN)}"
: "${SESSION_SECRET:?must set SESSION_SECRET}"
: "${TOKEN_EXCHANGE_CLIENT_SECRET:?must set TOKEN_EXCHANGE_CLIENT_SECRET}"
: "${PROFILE_MGMT_CLIENT_SECRET:?must set PROFILE_MGMT_CLIENT_SECRET}"
: "${OIDC_CLIENT_SECRET:?must set OIDC_CLIENT_SECRET}"

echo "==> Phase 1: build Lambda zip"
npm run package

# OIDC_TENANT_BASE_URL changes (e.g., flipping to a custom Auth0 domain) MUST
# be passed explicitly each deploy, otherwise SAM keeps the existing stack's
# old parameter value rather than picking up the template default.
OIDC_TENANT_BASE_URL_ARG="${OIDC_TENANT_BASE_URL:-https://adp-auth.demo-connect.us}"

echo "==> Phase 1: sam deploy ($STACK_NAME in $APP_REGION)"
sam deploy \
  --template-file deploy/template.yaml \
  --stack-name "$STACK_NAME" \
  --region "$APP_REGION" \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset \
  --resolve-s3 \
  --parameter-overrides \
    "Domain=$DOMAIN" \
    "HostedZoneId=$HOSTED_ZONE_ID" \
    "SessionSecret=$SESSION_SECRET" \
    "TokenExchangeClientSecret=$TOKEN_EXCHANGE_CLIENT_SECRET" \
    "ProfileMgmtClientSecret=$PROFILE_MGMT_CLIENT_SECRET" \
    "OidcClientSecret=$OIDC_CLIENT_SECRET" \
    "OidcTenantBaseUrl=$OIDC_TENANT_BASE_URL_ARG"

echo "==> Phase 2: post-deploy (Function URL + CloudFront + Route 53)"
STACK_NAME="$STACK_NAME" APP_REGION="$APP_REGION" DOMAIN="$DOMAIN" \
  HOSTED_ZONE_ID="$HOSTED_ZONE_ID" \
  bash deploy/post-deploy.sh

echo "==> Done. Browse to https://$DOMAIN/"
