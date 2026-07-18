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

## Support

- **Documentation:** [ARCHITECTURE-ENTERPRISE.md](ARCHITECTURE-ENTERPRISE.md)
- **Security Guide:** [SECURITY.md](SECURITY.md)
- **Issues:** GitHub Issues
- **Email:** support@brick-iam.io

