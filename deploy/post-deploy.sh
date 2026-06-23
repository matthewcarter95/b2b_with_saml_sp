#!/usr/bin/env bash
# Post-CFN steps that the CFN hook prevents:
#   1. aws lambda create-function-url-config (AuthType=NONE)
#   2. aws lambda add-permission (allow public InvokeFunctionUrl)
#   3. aws cloudfront create-distribution (custom domain alias to Function URL)
#   4. aws route53 change-resource-record-sets (ALIAS for $DOMAIN to CloudFront)
#
# All steps are idempotent: re-running won't duplicate resources.
#
# Required env: STACK_NAME, APP_REGION, DOMAIN, HOSTED_ZONE_ID

set -euo pipefail

# Auto-load .env when invoked directly (deploy.sh already exports these).
if [ -z "${HOSTED_ZONE_ID:-}" ] && [ -f "$(dirname "$0")/../.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$(dirname "$0")/../.env"
  set +a
fi

: "${STACK_NAME:?}"
: "${APP_REGION:?}"
: "${DOMAIN:?}"
: "${HOSTED_ZONE_ID:?}"

cfn_output() {
  aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" --region "$APP_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

LAMBDA_NAME="$(cfn_output LambdaFunctionName)"
LAMBDA_ARN="$(cfn_output LambdaFunctionArn)"
CERT_ARN="$(cfn_output CertificateArn)"

echo "  Lambda:    $LAMBDA_NAME"
echo "  Cert ARN:  $CERT_ARN"

#-----------------------------------------------------------------------
# 1. Function URL (AuthType=NONE)
#-----------------------------------------------------------------------
echo "==> Function URL"
FN_URL_JSON="$(aws lambda get-function-url-config \
  --function-name "$LAMBDA_NAME" --region "$APP_REGION" 2>/dev/null || true)"
if [ -z "$FN_URL_JSON" ]; then
  FN_URL_JSON="$(aws lambda create-function-url-config \
    --function-name "$LAMBDA_NAME" \
    --region "$APP_REGION" \
    --auth-type NONE \
    --invoke-mode BUFFERED)"
  echo "  created"
else
  echo "  already exists"
fi
FN_URL="$(echo "$FN_URL_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['FunctionUrl'])")"
FN_URL_HOST="$(echo "$FN_URL" | sed -E 's#https?://([^/]+)/?#\1#')"
echo "  $FN_URL"

aws lambda add-permission \
  --function-name "$LAMBDA_NAME" \
  --region "$APP_REGION" \
  --statement-id FunctionUrlAllowPublicAccess \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type NONE \
  >/dev/null 2>&1 || echo "  permission already attached"

#-----------------------------------------------------------------------
# 2. CloudFront distribution
#-----------------------------------------------------------------------
echo "==> CloudFront distribution"
DIST_ID="$(aws cloudfront list-distributions --query \
  "DistributionList.Items[?Aliases.Items && contains(Aliases.Items, \`$DOMAIN\`)].Id | [0]" \
  --output text)"
if [ "$DIST_ID" = "None" ] || [ -z "$DIST_ID" ]; then
  CALLER_REF="b2b-saml-sp-$(date +%s)"
  CONFIG_FILE="$(mktemp)"
  # NOTE: OriginRequestPolicyId below is AllViewerExceptHostHeader. Lambda
  # Function URLs reject any Host header that isn't their own *.lambda-url.*
  # hostname, so we must NOT forward the viewer's Host. AllViewer
  # (216adef6-...) is wrong here; b689b0a8-... is correct.
  python3 - <<PY > "$CONFIG_FILE"
import json, os
config = {
  "CallerReference": "$CALLER_REF",
  "Comment": "b2b-saml-sp $DOMAIN",
  "Aliases": {"Quantity": 1, "Items": ["$DOMAIN"]},
  "DefaultRootObject": "",
  "Origins": {
    "Quantity": 1,
    "Items": [{
      "Id": "lambda-fn-url",
      "DomainName": "$FN_URL_HOST",
      "OriginPath": "",
      "CustomHeaders": {"Quantity": 0},
      "CustomOriginConfig": {
        "HTTPPort": 80, "HTTPSPort": 443,
        "OriginProtocolPolicy": "https-only",
        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
        "OriginReadTimeout": 30,
        "OriginKeepaliveTimeout": 5
      },
      "ConnectionAttempts": 3,
      "ConnectionTimeout": 10,
      "OriginShield": {"Enabled": False}
    }]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "lambda-fn-url",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Quantity": 7,
      "Items": ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"],
      "CachedMethods": {"Quantity": 2, "Items": ["GET","HEAD"]}
    },
    "Compress": True,
    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
    "OriginRequestPolicyId": "b689b0a8-53d0-40ab-baf2-68738e2966ac",
    "ResponseHeadersPolicyId": "67f7725c-6f97-4210-82d7-5512b31e9d03",
    "FunctionAssociations": {"Quantity": 0},
    "LambdaFunctionAssociations": {"Quantity": 0},
    "FieldLevelEncryptionId": "",
    "SmoothStreaming": False
  },
  "PriceClass": "PriceClass_100",
  "Enabled": True,
  "ViewerCertificate": {
    "ACMCertificateArn": "$CERT_ARN",
    "SSLSupportMethod": "sni-only",
    "MinimumProtocolVersion": "TLSv1.2_2021",
    "Certificate": "$CERT_ARN",
    "CertificateSource": "acm"
  },
  "HttpVersion": "http2and3",
  "IsIPV6Enabled": True,
  "WebACLId": "",
  "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}}
}
print(json.dumps(config))
PY
  CREATE_RESP="$(aws cloudfront create-distribution \
    --distribution-config "file://$CONFIG_FILE")"
  DIST_ID="$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['Distribution']['Id'])")"
  DIST_DOMAIN="$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['Distribution']['DomainName'])")"
  rm -f "$CONFIG_FILE"
  echo "  created $DIST_ID ($DIST_DOMAIN)"
else
  DIST_DOMAIN="$(aws cloudfront get-distribution --id "$DIST_ID" \
    --query 'Distribution.DomainName' --output text)"
  echo "  exists $DIST_ID ($DIST_DOMAIN)"
fi

#-----------------------------------------------------------------------
# 3. Route 53 ALIAS records (A + AAAA) -> CloudFront
#-----------------------------------------------------------------------
echo "==> Route 53"
CHANGE_FILE="$(mktemp)"
cat > "$CHANGE_FILE" <<JSON
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN.",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "Z2FDTNDATAQYW2",
          "DNSName": "$DIST_DOMAIN",
          "EvaluateTargetHealth": false
        }
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN.",
        "Type": "AAAA",
        "AliasTarget": {
          "HostedZoneId": "Z2FDTNDATAQYW2",
          "DNSName": "$DIST_DOMAIN",
          "EvaluateTargetHealth": false
        }
      }
    }
  ]
}
JSON
aws route53 change-resource-record-sets \
  --hosted-zone-id "$HOSTED_ZONE_ID" \
  --change-batch "file://$CHANGE_FILE" >/dev/null
rm -f "$CHANGE_FILE"
echo "  upserted A + AAAA for $DOMAIN -> $DIST_DOMAIN"
echo
echo "CloudFront takes ~5-15 min to deploy globally. Then https://$DOMAIN/ should respond."
