# BRICK IAM - Security Best Practices & Implementation Guide

## Executive Summary

BRICK is built on cryptographic identity verification and immutable audit trails. This guide details security practices and operational hardening for production deployments.

## 1. Identity Spoofing Prevention

### Cryptographic Identity Hash

Every identity is bound to an immutable hash calculated as:

```
IdentityHash = SHA256(userID : orgID : enrollmentTimestamp)
```

**Why this prevents spoofing:**
- Hash is unique to user, org, and enrollment time
- Stored on immutable ledger
- Cannot be replayed or forged
- Changes require re-enrollment (auditable)

**Implementation:**
```go
identityHashInput := fmt.Sprintf("%s:%s:%d", userID, orgID, ctx.GetTxTimestamp().Seconds)
identityHash := sha256.Sum256([]byte(identityHashInput))
identityHashStr := hex.EncodeToString(identityHash[:])
```

### Organization Validation

Caller's MSPID is dynamically extracted and matched:

```go
callerMSPID, err := clientIdentity.GetMSPID()
if orgID != callerMSPID {
    return nil, fmt.Errorf("organization mismatch: requested %s, caller MSP %s", orgID, callerMSPID)
}
```

**Guarantees:**
- Users cannot enroll into other organizations
- Identity cannot be transferred between orgs
- MSP signature required for all operations

## 2. Attribute-Based Access Control (ABAC)

### X.509 Certificate Attributes

Permissions are embedded in user certificates as attributes:

```
Certificate Subject:
└── CN=user123@org1.example.com
└── O=Org1
└── Attributes:
    └── brick-admin: true
    └── department: engineering
    └── clearance-level: level3
```

### ABAC Enforcement

**Admin Operations** (e.g., RegisterIdentity):

```go
hasAdminAttr, err := clientIdentity.HasAttribute("brick-admin")
if !hasAdminAttr {
    return fmt.Errorf("caller lacks brick-admin attribute for identity registration")
}
```

**Custom Attributes:**

```go
dept, err := clientIdentity.GetAttributeValue("department")
if dept != "engineering" && dept != "security" {
    return fmt.Errorf("unauthorized department")
}
```

### Attribute Provisioning

**Certificate Authority Flow:**

1. CA issues user certificate with attributes
2. Attributes embedded in X.509 v3 extension
3. Hyperledger Fabric extracts attributes via `cid` package
4. Gateway validates attributes before chaincode execution
5. Immutable record of all attribute changes

## 3. Data Minimization & Private Data

### Two-Tier Architecture

| Layer | Visibility | Contents |
|-------|------------|----------|
| **Global Ledger** | All participants | Identity hash, role, status, MSPID |
| **Private Data Collection** | Organization only | Full profile, email, PII, audit logs |

### Private Data Collection Pattern

**Storing Non-Sensitive Identity:**
```go
// Public state - visible to all orgs
identity := BrickIdentity{
    UserID:       userID,
    IdentityHash: hashValue,
    Role:         role,
    MSPID:        callerMSPID,
    Status:       "active",
}
ctx.GetStub().PutState(identityKey, identityBytes)
```

**Storing Sensitive Profile (PDC):**
```go
// Private state - org-only access
privateProfile := map[string]interface{}{
    "email":   "user@org.com",
    "phone":   "+1-555-0123",
    "address": "123 Main St",
}
encryptedProfile := encrypt(privateProfile, orgKey)
ctx.GetStub().PutPrivateData("userProfilesPDC", profileKey, encryptedProfile)
```

**Verification Without Exposure:**
```go
// Verify identity without exposing PII
identityFromLedger := getIdentity(userID) // Only hash + role
profileHash := hash(getPrivateProfile(userID)) // Org-only access
verify(identityFromLedger.IdentityHash == profileHash) // Confirms consistency
```

## 4. Certificate Validation

### TLS Configuration

**Peer TLS Validation:**
```go
tlsConfig := credentials.NewClientTLSFromCert(
    certPool,
    "peer0.org1.example.com", // SNI hostname
)
```

**Requirements:**
- Valid certificate chain
- Correct hostname (SANs)
- Valid expiration
- Trusted CA

### Certificate Rotation

**Lifecycle:**
1. New certificate issued by CA (30 days before expiry)
2. Update `certPath` and `keyPath` in connection.json
3. Restart gateway process
4. Validate new certificate with health check
5. Old certificate remains in trust store for 1 day

**Zero-Downtime Rotation:**
```go
// Update connection profile path
func (gp *GatewayPool) RotateCertificate(newCertPath string) error {
    gp.mu.Lock()
    defer gp.mu.Unlock()
    
    // Load new certificate
    newCert, _, err := loadUserCredentials(newCertPath, newKeyPath)
    if err != nil {
        return fmt.Errorf("failed to load new cert: %w", err)
    }
    
    // Validate certificate
    if err := validateCertificate(newCert); err != nil {
        return fmt.Errorf("invalid certificate: %w", err)
    }
    
    // Reconnect with new credentials
    // Old connections drain gracefully
    return gp.reconnect(newCert, newKey)
}
```

## 5. HTTP Security Hardening

### Proper Error Responses

**DO:**
```go
// ✓ Clear error codes
c.JSON(http.StatusUnauthorized, ErrorResponse{
    Error:   "UNAUTHORIZED",
    Message: "X-User-Identity header required",
    Code:    http.StatusUnauthorized,
})

// ✓ Generic error for security operations
c.JSON(http.StatusForbidden, ErrorResponse{
    Error:   "FORBIDDEN",
    Message: "Identity enrollment denied",  // Don't reveal reason
    Code:    http.StatusForbidden,
})
```

**DON'T:**
```go
// ✗ Don't expose internals
c.JSON(500, gin.H{"error": "chaincode cid.GetMSPID() failed: ...stack trace..."})

// ✗ Don't reveal existence of identities
c.JSON(404, gin.H{"error": "User 'user@org.com' not found in ledger"})
```

### CORS Policy

**Production Configuration:**
```go
func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Whitelist specific origins
        origin := c.Request.Header.Get("Origin")
        allowedOrigins := map[string]bool{
            "https://app.brick-iam.io": true,
            "https://admin.brick-iam.io": true,
        }
        
        if allowedOrigins[origin] {
            c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
        }
        
        // Restrict methods
        c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST")
        
        // Restrict headers
        c.Writer.Header().Set(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-User-Identity, X-Org-ID",
        )
        
        // Disable credentials for public APIs
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "false")
        
        c.Next()
    }
}
```

### Rate Limiting

**Implementation (Recommended):**
```go
import "github.com/gin-contrib/ratelimit"

router.Use(ratelimit.RateLimit(
    ratelimit.NewStore(100), // 100 requests per second per IP
))
```

### Request Signing (Non-Repudiation)

**Sign critical operations:**
```typescript
// Frontend
const signature = signWithUserKey(JSON.stringify(enrollPayload));
api.post('/api/v1/brick/enroll', enrollPayload, {
    headers: {
        'X-Signature': signature,
        'X-Timestamp': Date.now(),
    }
});

// Backend
func VerifyRequestSignature(c *gin.Context) {
    signature := c.GetHeader("X-Signature")
    timestamp := c.GetHeader("X-Timestamp")
    
    // Verify timestamp within acceptable window (e.g., ±5 minutes)
    // Verify signature against user's public key
    // Prevent replay attacks
}
```

## 6. Audit & Monitoring

### Immutable Audit Trail

**Blockchain provides:**
- Complete history of all identity operations
- Timestamps from consensus layer (not user-controlled)
- Digital signatures from endorsing peers
- Cannot be modified retroactively

**Retrieve history:**
```go
func (bic *BrickIdentityContract) GetIdentityHistory(
    ctx contractapi.TransactionContextInterface,
    orgID string,
    userID string,
) []*map[string]interface{} {
    iterator, _ := ctx.GetStub().GetHistoryForKey(identityKey)
    // Returns: [Register, Suspend, Reactivate, ...] with timestamps
}
```

### Structured Logging

**Backend logging format:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "service": "brick-iam-gateway",
  "operation": "identity_registration",
  "userId": "user123",
  "orgId": "Org1MSP",
  "result": "success",
  "latency_ms": 245,
  "requestId": "req_abc123",
  "callerIP": "203.0.113.42"
}
```

**Log levels:**
- `ERROR`: Security incidents, chaincode failures
- `WARN`: Unauthorized attempts, certificate expiry
- `INFO`: Successful enrollments, status changes
- `DEBUG`: Detailed chaincode execution (dev only)

### Monitoring Alerts

**Alert on:**
1. Failed ABAC checks (brick-admin missing)
2. Organization mismatch attempts
3. Certificate expiration (<30 days)
4. Identity status changes (suspend/revoke)
5. Peer unreachable
6. High latency (>2s per request)

## 7. Cryptographic Key Management

### Private Key Protection

**DO:**
- Store private keys in environment variables or secrets manager
- Use file permissions (chmod 600 on certificates)
- Rotate keys every 90 days
- Use HSM for production deployments

**DON'T:**
- Commit keys to Git
- Pass keys as command-line arguments
- Store in plaintext configuration
- Log key material

### Key Derivation

```
User CA Certificate
  └── Private Key (256-bit, ECDSA)
  └── X.509 Attributes
      └── CN: user@org
      └── O: Organization
      └── brick-admin: true
      └── department: engineering
```

## 8. Incident Response

### Compromised User Certificate

**Steps:**
1. Revoke certificate immediately via CA
2. Update identity status to "revoked" in chaincode
3. Audit all transactions by user (Get history)
4. Notify organization of compromise
5. Reissue certificate after verification

**Chaincode action:**
```go
err := UpdateIdentityStatus(ctx, orgID, userID, "revoked")
// Emits event: IdentityStatusChanged
// Blocks all future requests
```

### Peer Compromise

**Steps:**
1. Remove peer from channel
2. Restart peer with fresh MSP credentials
3. Rejoin peer to channel
4. Verify peer sync and endorsement

### Private Key Compromise

**Steps:**
1. Rotate gateway certificate immediately
2. Re-establish all connections
3. Audit connection logs for suspicious activity
4. Consider re-enrollment of all users

## 9. TypeScript Security

### Strict Type Checking

**tsconfig.json:**
```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true
  }
}
```

### Runtime Validation

```typescript
// Always validate API responses
const validateIdentityResponse = (data: unknown): BrickIdentity => {
  if (!isObject(data)) throw new Error('Invalid response');
  if (typeof data.userId !== 'string') throw new Error('Invalid userId');
  if (!['active', 'suspended', 'revoked'].includes(data.status)) {
    throw new Error('Invalid status');
  }
  return data as BrickIdentity;
};
```

## 10. Compliance & Standards

### Standards Followed

- **NIST SP 800-63B**: Authentication & Lifecycle Management
- **OWASP Top 10**: Web application security
- **ISO 27001**: Information security management
- **SOC 2**: Security and availability controls

### Audit Requirements

- Maintain 12-month audit logs
- Quarterly security reviews
- Annual penetration testing
- Certificate expiration monitoring
- Access control reviews

## Production Checklist

- [ ] All certificates rotated to production CAs
- [ ] CORS policy configured for production domain
- [ ] Rate limiting enabled (100 req/s per IP)
- [ ] Structured logging configured
- [ ] Audit log retention enabled (12 months)
- [ ] TLS 1.3 minimum for connections
- [ ] HTTPS enforced for frontend
- [ ] Environment variables in secrets manager
- [ ] Private key permissions: 600
- [ ] HSM key management enabled
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented
- [ ] Security training completed for operators

