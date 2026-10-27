# BRICK IAM - REST API Documentation

**Version:** 1.0.0  
**Base URL:** `http://localhost:8080`  
**Authentication:** X-User-Identity header (required for most endpoints)  
**Content-Type:** `application/json`

## Overview

BRICK IAM provides REST APIs for blockchain-backed identity management. All endpoints integrate with Hyperledger Fabric chaincode for immutable operations.

## Authentication

### Headers Required

```
X-User-Identity: <base64-encoded-user-context>
X-Org-ID: <organization-mspid>
Content-Type: application/json
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/brick/enroll \
  -H "Content-Type: application/json" \
  -H "X-User-Identity: user123@org1.example.com" \
  -H "X-Org-ID: Org1MSP" \
  -d '{"userId":"user123","orgId":"Org1MSP","role":"admin"}'
```

## Endpoints

## App End-User Authentication

Requests to `/api/v1/client/*` authenticate the application with the `X-Brick-Publishable-Key` header. Email/password sign-up and sign-in are isolated by application and environment. The provider must be enabled in that application's auth configuration. Sign-up requires a valid email and an eight-character minimum password; wallet addresses cannot be claimed through the email endpoint.

Wallet clients request a fresh challenge and then sign the exact message with EIP-191 `personal_sign`:

1. `POST /api/v1/client/siwe/nonce` with `{ "wallet_address": "0x…", "chain_id": 1 }` and the app's `Origin` header.
2. Sign the returned `message` with the selected wallet.
3. `POST /api/v1/client/siwe` with `{ "wallet_address": "0x…", "message": "…", "signature": "0x…" }`.

Challenges are app-, environment-, wallet-, and origin-bound, expire after five minutes, and can be consumed once. Wallet sign-in must be enabled for the application. Successful signup or sign-in requires an active identity on the configured ledger and returns an `identity_hash` in `ledger_proof`; it is not a transaction hash. The default cloud ledger is a local JSON simulator, so deployments requiring distributed consensus must configure a real Fabric network.

### Passkeys (WebAuthn)

Passkeys require the app setting `passkeysEnabled: true`, plus `passkeyRPID` and an explicit `passkeyOrigins` array in `SettingsJSON`; configure these in Configure → Web3 & Passkeys. Configure only trusted HTTPS origins (HTTP is accepted only for localhost development); each origin host must equal the RP ID or be its subdomain. Do not derive this allowlist from request headers. Credential records are encrypted at rest using a key derived from `JWT_SECRET`; use a stable secret of at least 32 bytes and back it up before deploying. Passkey user verification satisfies enrolled TOTP MFA only when `passkeySatisfiesMfa: true` is explicitly configured; the default is false.

- `POST /api/v1/client/passkeys/register/begin` (bearer app-user token): starts registration and returns `{ ceremony_id, options }`.
- `POST /api/v1/client/passkeys/register/finish` (bearer app-user token): accepts `{ ceremony_id, name?, credential }` and stores a verified credential.
- `POST /api/v1/client/passkeys/login/begin`: accepts `{ email }` and returns `{ ceremony_id, options }` for that account's registered credentials.
- `POST /api/v1/client/passkeys/login/finish`: accepts `{ ceremony_id, credential }` and returns an app-user token or an MFA challenge.
- `GET /api/v1/client/passkeys` (bearer app-user token): lists the current user's passkeys without exposing credential public keys.
- `DELETE /api/v1/client/passkeys/:credentialId` (bearer app-user token): removes an app-scoped credential; Brick refuses to remove the last sign-in method unless another password, wallet, or social identity exists.

Ceremonies are server-side, expire after five minutes, and are consumed once. Registration requires a discoverable credential and user verification; assertion verification checks the configured RP ID/origin. Passkey login still honors the account's existing MFA requirement. The ceremony endpoints are backend APIs; clients need WebAuthn browser APIs (`navigator.credentials`) to serialize options and credential responses.

### AI Login Anomaly Detection

`POST /api/v1/apps/:id/ai/detect-login-anomalies` scans up to 1,000 app-scoped login events from the last 30 days. The request accepts `{ "environment": "all" | "development" | "production" }`. It sends only event type/status/environment/time and app-scoped HMAC pseudonyms for actor and network address to Meta Model API; raw IPs and account identifiers are not sent. Configure a persistent `MODEL_PSEUDONYM_KEY` (32+ random bytes; distinct from the Meta API key) for stable pseudonyms; if absent, Brick uses `JWT_SECRET`, then a process-ephemeral random key. Local rules also flag repeated failures and possible password spraying. Results are advisory, may be false positives, and never block or change authentication policy automatically. Without `MODEL_API_KEY` (or `META_AI_API_KEY`), the endpoint uses the clearly reported local-rules fallback.

`GET /api/v1/apps/:id/users/:userId/activity?environment=development|production` returns the latest 100 audit events for a user, scoped to the authenticated app owner, application, and environment. The timeline omits raw IP addresses, actor identifiers, and free-form event details.

`PUT /api/v1/apps/:id/users/:userId/metadata?environment=development|production` replaces the app-user custom metadata object with `{ "metadata": { ... } }`. The body is limited to 16 KiB and must be a JSON object. This shared object is not a secret store and does not yet distinguish public from private metadata.

`GET /api/v1/apps/:id/logs/export?environment=development|production|all&since=<RFC3339>&until=<RFC3339>` streams app-owned audit events as CSV. Export is capped at 10,000 rows (with `X-Export-Truncated` and `X-Export-Total` response headers) and omits raw IP, user-agent, and free-form details. Spreadsheet formula prefixes are escaped.

`POST /api/v1/apps/:id/rotate-jwt-signing-key?env=development|production` rotates the app/environment RS256 key after owner authorization. New tokens use the returned `kid`; old public keys remain in JWKS for 24 hours. Keep `JWT_SECRET` persistent across restarts or signing keys cannot be decrypted.

### Health Check

Check API and Fabric Gateway status.

**Request:**
```
GET /health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "BRICK Identity Gateway",
  "version": "1.0.0",
  "gateway": true,
  "timestamp": 1705331400
}
```

**Response (503 Service Unavailable):**
```json
{
  "status": "unhealthy",
  "service": "BRICK Identity Gateway",
  "version": "1.0.0",
  "gateway": false,
  "error": "Fabric Gateway disconnected",
  "timestamp": 1705331400
}
```

---

### Register Identity

Enroll a new user identity on the blockchain.

**Request:**
```
POST /api/v1/brick/enroll
```

**Headers:**
- `X-User-Identity`: Required - Caller's identity context
- `X-Org-ID`: Required - Caller's organization MSPID

**Request Body:**
```json
{
  "userId": "string (required)",
  "orgId": "string (required)",
  "role": "admin | user | auditor (required)",
  "attributes": {
    "brick-admin": "true",
    "department": "engineering",
    "clearance-level": "level3"
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "identity": {
    "userId": "user123",
    "orgId": "Org1MSP",
    "role": "admin",
    "status": "active",
    "identityHash": "abc123def456...",
    "mspId": "Org1MSP",
    "attributes": {
      "brick-admin": "true",
      "department": "engineering"
    },
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z"
  },
  "message": "Identity registered successfully"
}
```

**Error Responses:**

| Status | Code | Reason |
|--------|------|--------|
| 400 | INVALID_REQUEST | Missing required fields or invalid format |
| 401 | UNAUTHORIZED | X-User-Identity header missing |
| 403 | ENROLLMENT_FAILED | Caller lacks brick-admin ABAC attribute |
| 409 | IDENTITY_EXISTS | User already enrolled in org |
| 500 | GATEWAY_ERROR | Fabric Gateway not initialized |

**Example Error (403 Forbidden):**
```json
{
  "error": "ENROLLMENT_FAILED",
  "message": "Failed to register identity: caller lacks brick-admin attribute for identity registration",
  "code": 403
}
```

**ABAC Validation:**
- Caller must have `brick-admin` attribute in certificate
- Organization must match caller's MSPID
- Identity hash prevents re-enrollment with same parameters

---

### Get Session

Retrieve and validate current identity session.

**Request:**
```
GET /api/v1/brick/session/{userId}
```

**Path Parameters:**
- `userId`: The user ID to retrieve (string, required)

**Headers:**
- `X-User-Identity`: Required - Must match userId for access
- `X-Org-ID`: Required - Caller's organization

**Response (200 OK):**
```json
{
  "success": true,
  "identity": {
    "userId": "user123",
    "orgId": "Org1MSP",
    "role": "admin",
    "status": "active",
    "identityHash": "abc123def456...",
    "mspId": "Org1MSP",
    "attributes": {
      "brick-admin": "true"
    },
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z"
  },
  "message": "Session retrieved successfully"
}
```

**Error Responses:**

| Status | Code | Reason |
|--------|------|--------|
| 400 | INVALID_REQUEST | Missing userId or X-Org-ID header |
| 401 | UNAUTHORIZED | X-User-Identity header missing |
| 403 | FORBIDDEN | Caller cannot access other user's session |
| 404 | SESSION_NOT_FOUND | Identity not found on blockchain |
| 500 | GATEWAY_ERROR | Fabric Gateway not initialized |

**Example Error (403 Forbidden):**
```json
{
  "error": "FORBIDDEN",
  "message": "Cannot access other user's session",
  "code": 403
}
```

**Cross-Organization Access:**
- Users can only query their own identities
- Admin endpoints required for cross-org queries
- All access logged on blockchain

---

## Error Handling

### Standard Error Response Format

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable error description",
  "code": 400
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid request format or parameters |
| 401 | Unauthorized - Missing or invalid authentication |
| 403 | Forbidden - Authenticated but lacks permissions (ABAC) |
| 404 | Not Found - Resource does not exist |
| 409 | Conflict - Resource already exists or state conflict |
| 500 | Internal Server Error - Server error or chaincode failure |
| 503 | Service Unavailable - Fabric Gateway unreachable |

### Common Error Codes

| Code | Cause | Solution |
|------|-------|----------|
| INVALID_REQUEST | Malformed JSON or missing required fields | Check request format against spec |
| UNAUTHORIZED | Missing X-User-Identity header | Add identity header to request |
| ENROLLMENT_FAILED | No brick-admin attribute or org mismatch | Verify user certificate attributes |
| SESSION_NOT_FOUND | User not enrolled | Call /enroll endpoint first |
| FORBIDDEN | User accessing other's data | Verify X-User-Identity matches userId |
| GATEWAY_ERROR | Fabric Gateway offline | Check peer connectivity and health |
| PARSE_ERROR | Chaincode response malformed | Restart gateway and retry |

---

## Request Examples

### Example 1: Enroll Admin User

```bash
#!/bin/bash

USER_ID="alice"
ORG_ID="Org1MSP"
ROLE="admin"

curl -X POST http://localhost:8080/api/v1/brick/enroll \
  -H "Content-Type: application/json" \
  -H "X-User-Identity: admin@org1.example.com" \
  -H "X-Org-ID: Org1MSP" \
  -d "{
    \"userId\": \"$USER_ID\",
    \"orgId\": \"$ORG_ID\",
    \"role\": \"$ROLE\",
    \"attributes\": {
      \"brick-admin\": \"true\",
      \"department\": \"engineering\"
    }
  }"
```

### Example 2: Retrieve User Session

```bash
#!/bin/bash

curl -X GET http://localhost:8080/api/v1/brick/session/alice \
  -H "X-User-Identity: alice" \
  -H "X-Org-ID: Org1MSP"
```

### Example 3: TypeScript Fetch API

```typescript
import axios from 'axios';

interface EnrollRequest {
  userId: string;
  orgId: string;
  role: 'admin' | 'user' | 'auditor';
  attributes?: Record<string, string>;
}

async function enrollIdentity(payload: EnrollRequest) {
  try {
    const response = await axios.post(
      'http://localhost:8080/api/v1/brick/enroll',
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-User-Identity': getUserContext(),
          'X-Org-ID': getOrgId(),
        },
        timeout: 30000,
      }
    );

    return response.data.identity;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      console.error(`Error: ${error.response?.data?.error}`);
      console.error(`Message: ${error.response?.data?.message}`);
    }
    throw error;
  }
}
```

### Example 4: cURL with Environment Variables

```bash
#!/bin/bash

# Load configuration
export BRICK_API_URL="http://localhost:8080"
export BRICK_ORG_ID="Org1MSP"
export BRICK_USER_ID="alice"

# Function to enroll user
brick_enroll() {
  local user_id=$1
  local org_id=$2
  local role=$3

  curl -s -X POST "${BRICK_API_URL}/api/v1/brick/enroll" \
    -H "Content-Type: application/json" \
    -H "X-User-Identity: ${BRICK_USER_ID}" \
    -H "X-Org-ID: ${BRICK_ORG_ID}" \
    -d "{
      \"userId\": \"${user_id}\",
      \"orgId\": \"${org_id}\",
      \"role\": \"${role}\"
    }" | jq .
}

# Enroll new user
brick_enroll "bob" "Org1MSP" "user"
```

---

## Rate Limiting

**Current Limits:**
- 100 requests per second per IP address
- Burst capacity: 150 requests

**Response Headers (when limit approaching):**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1705331460
```

**When limit exceeded (429 Too Many Requests):**
```json
{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded. Max 100 requests/sec",
  "code": 429
}
```

---

## Timeouts

**Default Timeouts:**
- Enroll: 30 seconds
- Session retrieval: 10 seconds
- Blockchain consensus: 1 minute

**Configure in connection.json:**
```json
{
  "evaluateTimeout": 5000,
  "endorseTimeout": 30000,
  "submitTimeout": 30000,
  "commitStatusTimeout": 60000
}
```

---

## Audit & Compliance

### Audit Log Format

Every API call generates an immutable blockchain record:

```json
{
  "txId": "abc123def456...",
  "timestamp": "2024-01-15T10:30:00Z",
  "operation": "identity_registration",
  "userId": "alice",
  "orgId": "Org1MSP",
  "status": "success",
  "callerMSP": "Org1MSP",
  "hash": "def456abc123..."
}
```

### Compliance Notes

- All operations immutably recorded on blockchain
- Audit trail cannot be modified or deleted
- 12-month retention policy enforced
- Access logs queryable via GetIdentityHistory()

---

## Migration from v0.x

**Breaking Changes:**
- Endpoint format changed from `/api/blockchain/*` to `/api/v1/brick/*`
- Response format now wrapped in `{success, identity, message}`
- IdentityHash field added (anti-spoofing)

**Migration Steps:**
1. Update API URLs to new v1 paths
2. Update header names (X-User-Identity required)
3. Parse new response format
4. Test against staging environment first

---

## SDKs & Tools

### Official SDKs

- **Go**: See `backend/gateway.go`
- **TypeScript**: See `frontend/lib/BrickAuthProvider.tsx`
- **Python**: Coming soon
- **Java**: Coming soon

### Testing Tools

**Postman Collection:**
```json
{
  "info": {
    "name": "BRICK IAM API",
    "version": "1.0.0"
  },
  "item": [
    {
      "name": "Health Check",
      "request": {
        "method": "GET",
        "url": "http://localhost:8080/health"
      }
    },
    {
      "name": "Enroll Identity",
      "request": {
        "method": "POST",
        "url": "http://localhost:8080/api/v1/brick/enroll",
        "header": [
          {"key": "Content-Type", "value": "application/json"},
          {"key": "X-User-Identity", "value": "admin@org1"},
          {"key": "X-Org-ID", "value": "Org1MSP"}
        ],
        "body": {
          "userId": "alice",
          "orgId": "Org1MSP",
          "role": "admin"
        }
      }
    }
  ]
}
```

---

## End-User TOTP MFA

MFA endpoints require the application's publishable key in `X-Brick-Publishable-Key`. Authenticated enrollment endpoints also require a user access token in `Authorization: Bearer <token>`. Configure a stable, high-entropy `BRICK_MFA_ENCRYPTION_KEY` (32+ bytes) on the backend before enabling enrollment.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/client/mfa/setup` | Create a pending TOTP secret; returns a one-time secret and `otpauth_uri` |
| `POST` | `/api/v1/client/mfa/confirm` | Confirm enrollment using `{ "code": "123456" }`; returns one-time recovery codes |
| `POST` | `/api/v1/client/mfa/disable` | Disable MFA using the current TOTP code |
| `POST` | `/api/v1/client/mfa/verify` | Complete the five-minute sign-in challenge using `{ "mfa_token": "…", "code": "123456" }` or a `recovery_code` |

When an enrolled user signs in with a password or SIWE, `/sign-in` or `/siwe` returns HTTP `202` with `mfa_required`, `mfa_token`, and `expires_in` instead of a session token. Call `/mfa/verify` to receive the normal session token. Recovery codes are single-use. Authenticator secrets are encrypted at rest; changing or losing the encryption key prevents existing users from verifying TOTP.

## Application JWT Signing and JWKS

End-user access tokens use per-application, per-environment RSA-256 key pairs and include a `kid`. `GET /api/v1/client/jwks.json?publishable_key=<pk_test_or_pk_live>` returns a standard public JWKS for that app/environment. The private signing key is AES-GCM encrypted in the database with a key derived from `JWT_SECRET`; configure and persist a random `JWT_SECRET` of at least 32 bytes before issuing end-user tokens. Do not rotate `JWT_SECRET` casually: it protects stored signing keys as well as developer sessions.

Rotate an app's end-user token signing key using the developer-authenticated `POST /api/v1/apps/:id/rotate-jwt-signing-key?env=test|live` route. Previous public keys remain published and accepted for 24 hours so previously issued 24-hour tokens can expire. This is separate from `POST /api/v1/apps/:id/rotate-keys`, which rotates API credentials.

**Meta Model API:** The backend reads the server-only `MODEL_API_KEY` (or legacy `META_AI_API_KEY`) and defaults to `muse-spark-1.3`. Configure it only in the backend runtime; never in frontend environment variables. Without it, the API explicitly identifies its deterministic local-rule fallback.

`POST /api/v1/apps/:id/ai/recommend-auth-policy` returns advisory authentication-policy recommendations based on allowlisted app settings and grouped event counts from the last 30 days. It does not apply configuration changes. AI endpoints are limited to 10 requests/minute/source IP per process; use a shared gateway quota for multi-replica deployments.

## End-User Organizations

Organization routes require `X-Brick-Publishable-Key`, a valid end-user `Authorization: Bearer <token>`, and `org_enabled: true` on the application. Organization and membership rows are isolated by application and test/live environment. The creator receives the `owner` role; organization sessions issued by `/organizations/select` include `org_id` and `org_role`, and Brick rechecks the membership on each authenticated organization request.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/client/organizations` | Create an organization using `{ "name": "Acme", "slug": "acme" }` |
| `GET` | `/api/v1/client/organizations` | List organizations the current user belongs to |
| `POST` | `/api/v1/client/organizations/select` | Select a membership and return an organization-scoped 24-hour access token |
| `GET` | `/api/v1/client/organizations/:orgId/members` | List members for an organization the caller belongs to |
| `DELETE` | `/api/v1/client/organizations/:orgId/members/:userId` | Remove a member (owner/admin; only owners can remove admins; owners cannot be removed) |
| `POST` | `/api/v1/client/organizations/:orgId/invitations` | Create a seven-day, one-use invite for a member/admin; response includes a secret token to deliver through the app's trusted email provider |
| `POST` | `/api/v1/client/organization-invitations/accept` | Accept `{ "token": "..." }` while authenticated as the invited email |

Invitation tokens are returned once and only their SHA-256 hashes are stored. Brick does not send invitation email itself yet; the relying app must deliver the secret securely. Organization APIs are backend-complete only; first-party dashboard and SDK integration remain separate work.

## Social Sign-In (Google, GitHub, and Apple)

Configure Brick's provider OAuth clients only in backend secrets: `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `APPLE_OAUTH_CLIENT_ID`, and `APPLE_OAUTH_CLIENT_SECRET`. The Apple client secret must be a valid developer-generated Sign in with Apple JWT and be rotated before its expiry. Register `BRICK_OAUTH_CALLBACK_URL` exactly with each provider; it must be an HTTPS URL such as `https://api.example.com/api/v1/client/oauth/callback`. Enable the `google`, `github`, or `apple` provider for the app and include exact application callback URLs in `settings_json.socialRedirectUris`. End-user redirect URIs must be HTTPS (HTTP localhost is allowed for local development).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/client/oauth/:provider/start?redirect_uri=<registered-uri>&publishable_key=<pk>` | Starts Google or GitHub authorization and redirects to that provider |
| `GET` / `POST` | `/api/v1/client/oauth/callback` | Validates one-time server-stored state, exchanges the code server-side, verifies provider identity/email, then redirects to the registered app URI with a Brick token or MFA challenge in the URL fragment; Apple uses `POST` form data |

Brick stores only a hash of random single-use state and binds it to app, environment, provider, exact redirect URI, and a ten-minute expiry. Apple additionally uses a one-time nonce verified against Apple's JWKS-signed ID token. It never accepts a redirect URI from the OAuth callback. Provider access tokens and client secrets are never returned to the browser. Account linking requires a verified provider email, and session issuance still requires an active ledger identity. Apple sends its callback using `form_post`, which is supported by the callback endpoint.

## Support

- **Documentation:** [ARCHITECTURE-ENTERPRISE.md](ARCHITECTURE-ENTERPRISE.md)
- **Security Guide:** [SECURITY.md](SECURITY.md)
- **Issues:** GitHub Issues
- **Email:** support@brick-iam.io

