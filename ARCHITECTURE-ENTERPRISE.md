# BRICK IAM - Enterprise Architecture Guide

## Overview

**BRICK** is a production-ready, decentralized Identity and Access Management (IAM) engine powered by Hyperledger Fabric. It provides sovereign, blockchain-backed authentication and authorization that serves as a decentralized alternative to centralized IAM solutions.

## System Components

### 1. Blockchain Layer (Hyperledger Fabric)

**Smart Contract: `brick-identity` Chaincode (Go)**

Located in: `blockchain/chaincode/identity.go`

#### Core Data Structure: BrickIdentity

```go
type BrickIdentity struct {
    UserID       string                 // User identifier
    OrgID        string                 // Organization/MSPID
    Role         string                 // admin, user, auditor
    Status       string                 // active, suspended, revoked
    IdentityHash string                 // SHA256(userID:OrgID:timestamp) - anti-spoofing
    MSPID        string                 // Caller's dynamically extracted MSP ID
    CreatedAt    string                 // ISO timestamp
    UpdatedAt    string                 // ISO timestamp
    Attributes   map[string]string      // X.509 certificate attributes
}
```

#### Key Functions

**RegisterIdentity()**
- Enrolls new identity on blockchain
- Dynamically extracts caller's MSPID using `cid` package
- Validates ABAC attribute `brick-admin` for sensitive operations
- Generates cryptographic identity hash to prevent spoofing
- Validates organization matching (caller MSPID must equal requested orgID)
- Emits `IdentityRegistered` event

**GetIdentity()**
- Retrieves identity with authorization check
- Validates caller's MSPID matches requested org
- Returns 401 Unauthorized for invalid access

**UpdateIdentityStatus()**
- Modifies identity status (activate/suspend/revoke)
- Requires `brick-admin` ABAC attribute
- Validates status transitions
- Emits `IdentityStatusChanged` event

**QueryIdentitiesByOrg()**
- Lists all identities in organization
- Enforces org-level access control
- Uses CouchDB rich query for filtering

**GetIdentityHistory()**
- Retrieves complete audit trail for identity
- Shows all state transitions with timestamps
- Immutable transaction history

#### Private Data Collections (PDC)

**Architecture Stub for Data Minimization:**

```
Global Ledger (Public):
├─ Identity hash
├─ Role and status
├─ MSP ID
└─ ABAC attributes

Private Data Collection (Org-only):
├─ Full profile data
├─ Email and contact info
├─ Encrypted attribute claims
└─ Sensitive audit logs
```

**Implementation Pattern:**
```go
// Store non-sensitive identity on public ledger
ctx.GetStub().PutState(identityKey, publicData)

// Store PII in private collection (org-only access)
ctx.GetStub().PutPrivateData("userProfilesPDC", profileKey, encryptedProfile)

// Verification anchors on public ledger (identity hash)
// enables privacy while maintaining provenance
```

### 2. Backend API Gateway (Go + Gin Framework)

**Location:** `backend/gateway.go`

#### Singleton Connection Pool Pattern

```go
type GatewayPool struct {
    gateway *client.Gateway
    mu      sync.RWMutex
}
```

**Benefits:**
- Reuses gRPC connections
- Reduces latency for chaincode invocations
- Manages connection lifecycle
- Thread-safe concurrent access

#### Configuration Loading

**connection.json** structure:
```json
{
  "peerHost": "localhost",
  "peerPort": 7051,
  "tlsCertPath": "./certs/peer0.org1.example.com-cert.pem",
  "certPath": "./certs/Admin@org1.example.com-cert.pem",
  "keyPath": "./certs/priv_sk",
  "orgName": "Org1",
  "orgMspId": "Org1MSP",
  "channelName": "mychannel",
  "chaincodeName": "brick-identity"
}
```

#### API Endpoints

**POST /api/v1/brick/enroll**

Register new identity on blockchain

Request Headers:
- `Content-Type: application/json`
- `X-User-Identity`: Base64-encoded caller identity
- `X-Org-ID`: Organization identifier

Request Body:
```json
{
  "userId": "user123",
  "orgId": "Org1MSP",
  "role": "admin",
  "attributes": {
    "brick-admin": "true",
    "department": "engineering"
  }
}
```

Response (201 Created):
```json
{
  "success": true,
  "identity": {
    "userId": "user123",
    "orgId": "Org1MSP",
    "role": "admin",
    "status": "active",
    "identityHash": "abc123...",
    "mspId": "Org1MSP",
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z",
    "attributes": { "brick-admin": "true" }
  },
  "message": "Identity registered successfully"
}
```

Errors:
- `400 Bad Request`: Invalid payload
- `401 Unauthorized`: Missing X-User-Identity header
- `403 Forbidden`: Caller lacks brick-admin attribute
- `500 Internal Server Error`: Blockchain invocation failed

**GET /api/v1/brick/session/:userId**

Retrieve and validate current identity session

Request Headers:
- `X-User-Identity`: Base64-encoded caller identity
- `X-Org-ID`: Organization identifier

Response (200 OK):
```json
{
  "success": true,
  "identity": { /* same as enroll response */ },
  "message": "Session retrieved successfully"
}
```

Errors:
- `400 Bad Request`: Missing required headers
- `403 Forbidden`: Cross-org access violation
- `404 Not Found`: Identity not found
- `401 Unauthorized`: Identity not active

#### Error Response Format

```go
type ErrorResponse struct {
    Error   string `json:"error"`        // Machine-readable code (e.g., "UNAUTHORIZED")
    Message string `json:"message"`      // Human-readable description
    Code    int    `json:"code"`         // HTTP status code
}
```

#### gRPC Dial Options

```go
client.WithClientConnection(conn),
client.WithEvaluateTimeout(5*time.Second),
client.WithEndorseTimeout(30*time.Second),
client.WithSubmitTimeout(30*time.Second),
client.WithCommitStatusTimeout(1*time.Minute),
```

### 3. Frontend (Next.js + TypeScript)

**Location:** `frontend/`

#### BrickAuthProvider Context

**File:** `frontend/lib/BrickAuthProvider.tsx`

Exposes custom hook `useBrickAuth()` with:

```typescript
interface BrickAuthContextType {
  // State
  user: BrickIdentity | null;
  isLoading: boolean;
  status: 'unauthenticated' | 'authenticating' | 'authenticated' | 'error';
  error: string | null;

  // Actions
  connectIdentity: (userID: string, orgID: string, role: string) => Promise<BrickIdentity>;
  getSession: (userID: string, orgID: string) => Promise<BrickIdentity>;
  disconnect: () => void;
  clearError: () => void;
}
```

#### TypeScript Interfaces

```typescript
interface BrickIdentity {
  userId: string;
  orgId: string;
  role: 'admin' | 'user' | 'auditor';
  status: 'active' | 'suspended' | 'revoked';
  identityHash: string;
  mspId: string;
  attributes: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}
```

#### Dashboard Component

**File:** `frontend/app/dashboard/page.tsx`

Features:
- Real-time identity state display
- MSP ID badge showing organization
- Role badge with color coding
- Status indicator (active/suspended/revoked)
- Cryptographic identity hash display
- ABAC attributes visualization
- Private Data Collections architecture stub
- Refresh identity session from blockchain

Styling:
- Tailwind CSS utility classes
- Responsive grid layout (mobile-first)
- Color-coded badges for roles and status
- Gradient headers
- Smooth animations and transitions

#### Session Management

- Stores identity in `localStorage` as `brick-identity`
- Persists MSP ID as `brick-msp-id`
- Stores user context as `user-identity`
- Auto-loads session on component mount
- Validates identity status before allowing access

## Security Architecture

### 1. Identity Verification

**Dynamic MSP Extraction:**
- Uses Hyperledger Fabric `cid` package
- Extracts caller's MSPID from client context
- Validates organization matching
- Prevents identity spoofing

**Cryptographic Identity Hash:**
- SHA256(userID:OrgID:timestamp)
- Provides cryptographic proof of unique identity
- Enables audit trail verification
- Prevents replay attacks

### 2. Attribute-Based Access Control (ABAC)

**X.509 Certificate Attributes:**
- `brick-admin`: Required for sensitive operations
- `department`, `clearance-level`: Custom org attributes
- Embedded in user's certificate
- Validated by gateway middleware

**Enforcement Pattern:**
```go
hasAdminAttr, err := clientIdentity.HasAttribute("brick-admin")
if !hasAdminAttr {
    return fmt.Errorf("unauthorized: caller lacks brick-admin attribute")
}
```

### 3. Certificate Validation

**TLS Configuration:**
- Peer TLS cert loaded from `tlsCertPath`
- User cert and key loaded from connection profile
- gRPC connections use TLS credentials
- Certificate chain validation enabled

### 4. Data Minimization

**Global Ledger (Public):**
- Identity hash only (no PII)
- Role and status
- MSPID and organization
- Immutable audit trail

**Private Data Collections (PDC):**
- Full profile details
- Email, phone, contact info
- Sensitive attributes
- Org-only access enforcement
- Encrypted at rest

### 5. HTTP Security

**Proper Status Codes:**
- `401 Unauthorized`: Invalid identity
- `403 Forbidden`: Insufficient ABAC permissions
- `400 Bad Request`: Malformed request
- `500 Internal Server Error`: Server failures

**Header Validation:**
- `X-User-Identity`: Required for auth
- `X-Org-ID`: Org context validation
- `Content-Type`: JSON enforcement

## Production Deployment

### Prerequisites

- Go 1.21+
- Node.js 18+
- Hyperledger Fabric 2.5+
- PostgreSQL 13+ (optional, for audit logs)
- Docker (for Fabric network deployment)

### Configuration

**Backend:**
1. Create `connection.json` with peer addresses
2. Set environment variables in `.env.production`
3. Place certificates in `certs/` directory
4. Configure MSP paths

**Frontend:**
1. Build with `npm run build`
2. Set `NEXT_PUBLIC_API_URL` to backend URL
3. Configure API timeout values
4. Enable TypeScript strict mode

### Scaling

**Connection Pool:**
- Reuses gRPC connections
- Max connections configurable
- Connection recycling on timeout
- Load balancing across multiple peers

**Chaincode:**
- Support for multiple channels
- Partition identities by org for parallel processing
- Rich query support via CouchDB
- Batch operations for high throughput

## Monitoring

**Health Check:**
```
GET /health
```

Response:
```json
{
  "status": "healthy",
  "service": "BRICK Identity Gateway",
  "version": "1.0.0",
  "gateway": true,
  "timestamp": 1705331400
}
```

**Metrics:**
- Identity registration rate
- Session retrieval latency
- Chaincode invocation success rate
- Connection pool utilization

## Future Enhancements

1. **Multi-Channel Support**: Different identity namespaces per channel
2. **Certificate Revocation**: Implement CRL/OCSP
3. **Audit Logging**: Syslog/ELK integration
4. **Rate Limiting**: Prevent enumeration attacks
5. **OAuth2 Bridge**: Interoperability with traditional systems
6. **SSO Integration**: Enterprise SSO compatibility
7. **Biometric Binding**: Hardware security key support
8. **Zero-Knowledge Proofs**: Privacy-preserving identity assertions

## References

- [Hyperledger Fabric Gateway Client Go](https://github.com/hyperledger/fabric-gateway)
- [Hyperledger Fabric CID Package](https://github.com/hyperledger/fabric/tree/main/common/cauthdsl)
- [Fabric Smart Contracts](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode.html)
- [Private Data Collections](https://hyperledger-fabric.readthedocs.io/en/latest/private-data-arch.html)
