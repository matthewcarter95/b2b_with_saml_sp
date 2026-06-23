# Deploying to AWS

Target: `https://totalcontrol.demo-connect.us` → CloudFront → Lambda Function URL → Express via `serverless-http`. DynamoDB-backed sessions.

## One-time prerequisites

1. **AWS CLI** v2 installed and configured for the target account.
2. **AWS SAM CLI** installed (`brew install aws-sam-cli` or equivalent).
3. **Route 53 hosted zone** for `demo-connect.us`. Zone ID: `Z0779465JLQ9Q597U3NC`.
4. **Region**: us-east-1 for everything (CloudFront only reads ACM from us-east-1; keeping Lambda there too removes a cross-region hop).

## Stack-aware constraints

The org's `AWS::EarlyValidation::PropertyValidation` CloudFormation hook blocks `AWS::Lambda::Url`. The split below works around it:

- **CFN (`template.yaml`)** creates: Lambda function, IAM role, DynamoDB sessions table, ACM cert (DNS-validated against your zone).
- **Post-deploy CLI (`post-deploy.sh`)** creates: Lambda Function URL, public-invoke permission, CloudFront distribution, Route 53 ALIAS records.

`deploy.sh` orchestrates both.

## One-shot deploy

Set the secrets and zone ID in your shell (or write a sourced `.env.deploy` that's gitignored):

```bash
export STACK_NAME=b2b-saml-sp
export APP_REGION=us-east-1
export DOMAIN=totalcontrol.demo-connect.us
export HOSTED_ZONE_ID=Z0779465JLQ9Q597U3NC    # Route 53 zone for demo-connect.us

export SESSION_SECRET=$(openssl rand -hex 32)
export TOKEN_EXCHANGE_CLIENT_SECRET=...      # M2M client secret (mErGed14...)
export PROFILE_MGMT_CLIENT_SECRET=...        # Dedicated profile-mgmt M2M secret
export OIDC_CLIENT_SECRET=...                # SAML app's OIDC client secret (8Zro0UN0...)

bash deploy/deploy.sh
```

What it does:

1. `npm run package` — builds `lambda.zip` from `server.js`, `lambda.js`, `views/`, `public/`, `node_modules` (prod only), and the IdP cert/metadata.
2. `sam deploy` — creates Lambda (arm64, 512 MB, 15s timeout, env vars set), IAM role with DynamoDB CRUD on the sessions table, the sessions table itself (PAY_PER_REQUEST + TTL on `expires`), and an ACM cert for the domain (DNS-auto-validated by the SAM stack via the zone you supplied — takes ~3-5 minutes the first time).
3. `post-deploy.sh` — creates the Function URL with `AuthType=NONE`, attaches the public InvokeFunctionUrl permission, creates a CloudFront distribution that fronts the Function URL with the ACM cert + custom alias, and upserts A/AAAA ALIAS records pointing the domain at CloudFront.

CloudFront takes ~5–15 min to deploy globally after the script finishes. Browse to `https://totalcontrol.demo-connect.us/` once it's live.

## Auth0 callback updates

The deploy script doesn't touch Auth0 — do these once after the first deploy (or update `add-permissions.sh` to do it via the Management API):

In the Auth0 dashboard, on application **`b2b_with_saml_sp` (`8Zro0UN0hnnUXggyDXGm6qxfHmO4ic4V`)**:

- **Allowed Callback URLs** — add:
  - `https://totalcontrol.demo-connect.us/saml/callback` (SAML ACS)
  - `https://totalcontrol.demo-connect.us/oidc/callback` (native-to-web bridge)
- **Allowed Logout URLs** — add:
  - `https://totalcontrol.demo-connect.us/`

In the SAML2 Web App add-on **Settings JSON**, update for the public origin:

```json
{
  "audience": "urn:fiscal-psft:saml-sp-demo",
  "recipient": "https://totalcontrol.demo-connect.us/saml/callback",
  "destination": "https://totalcontrol.demo-connect.us/saml/callback",
  "nameIdentifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "signResponse": false
}
```

## Native-to-Web SSO (early access)

The `/context/set` route is built but won't actually exchange a session_token unless the tenant has the **Native-to-Web SSO** EA feature enabled and the relevant clients have `session_transfer` configured. Steps to verify:

1. In Auth0 dashboard → Settings → Advanced → Early Access (or your tenant's EA panel), enable **Native to Web SSO**.
2. On the **mobile** OIDC client, set `session_transfer.can_create_session_transfer_token: true`.
3. On **this** SAML/OIDC client (`8Zro0UN0hnnUXggyDXGm6qxfHmO4ic4V`), set `session_transfer.can_consume_session_transfer_token: true` (or whatever the flag is named in the tenant — the field is gated behind a higher-privilege scope so it isn't readable from our M2M token).
4. Mobile flow:
   ```
   POST /oauth/token
       grant_type=refresh_token
       refresh_token=<rt>
       audience=urn:fiscal-psft.cic-demo-platform.auth0app.com:session_transfer
   → returns access_token (the session_transfer_token JWT)

   open browser → https://totalcontrol.demo-connect.us/context/set?session_token=<jwt>
   ```

If the tenant flag isn't on, Auth0 returns an error from `/authorize?session_token=…` and the `/oidc/callback` page surfaces it verbatim.

## Tearing it down

```bash
# Delete the Function URL first (it has the public permission attached)
aws lambda delete-function-url-config --function-name b2b-saml-sp-app --region us-east-1

# Delete the CloudFront distribution: disable, wait for deploy, then delete
DIST_ID=$(aws cloudfront list-distributions \
  --query "DistributionList.Items[?Aliases.Items && contains(Aliases.Items, \`totalcontrol.demo-connect.us\`)].Id | [0]" \
  --output text)
ETAG=$(aws cloudfront get-distribution-config --id "$DIST_ID" --query 'ETag' --output text)
aws cloudfront get-distribution-config --id "$DIST_ID" --query 'DistributionConfig' \
  | jq '.Enabled = false' \
  | xargs -I{} aws cloudfront update-distribution --id "$DIST_ID" --if-match "$ETAG" --distribution-config '{}'
# wait ~15 min for status=Deployed, then:
aws cloudfront delete-distribution --id "$DIST_ID" --if-match "$(aws cloudfront get-distribution-config --id $DIST_ID --query ETag --output text)"

# Delete Route 53 records and finally the CFN stack
aws cloudformation delete-stack --stack-name b2b-saml-sp --region us-east-1
```
