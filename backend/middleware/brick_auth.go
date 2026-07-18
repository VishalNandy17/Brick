package middleware

import (
	"brick/services"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// ledgerReadState is a minimal struct to read the cloud-ledger.json
// without importing the ledger package (avoids circular deps).
type ledgerReadState struct {
	Identities map[string]struct {
		Status string `json:"status"`
	} `json:"identities"`
}

// BrickAuthMiddleware is the production-grade successor to AuthMiddleware.
// It performs a two-step validation:
//  1. Cryptographically verify the Bearer JWT via services.ParseAccessToken
//  2. Cross-check the user's identity status in the CloudLedger JSON —
//     if status is "revoked" or "suspended", the request is dropped with 401.
//
// On success, it injects user_id, org_id, role, and email into the Gin context.
func BrickAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// ── Step 1: Extract Bearer token ───────────────────────────────────
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "UNAUTHORIZED",
				"message": "Missing Authorization header",
			})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "UNAUTHORIZED",
				"message": "Authorization header must be: Bearer <token>",
			})
			c.Abort()
			return
		}

		// ── Step 2: Cryptographic JWT verification ─────────────────────────
		claims, err := services.ParseAccessToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "TOKEN_INVALID",
				"message": "Token is invalid, expired, or tampered",
			})
			c.Abort()
			return
		}

		// ── Step 3: Ledger revocation check ────────────────────────────────
		ledgerStatus, ledgerErr := readLedgerIdentityStatus(claims.UserID, claims.OrgID)
		if ledgerErr == nil {
			switch ledgerStatus {
			case "revoked":
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "IDENTITY_REVOKED",
					"message": "This identity has been permanently revoked on the blockchain ledger",
				})
				c.Abort()
				return
			case "suspended":
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "IDENTITY_SUSPENDED",
					"message": "This identity is temporarily suspended on the blockchain ledger",
				})
				c.Abort()
				return
			}
		}
		// If ledger is unreadable (e.g., file locked), allow through — fail open
		// to prevent the ledger simulator from becoming a hard dependency.

		// ── Inject verified claims into Gin context ────────────────────────
		c.Set("user_id", claims.UserID)
		c.Set("org_id", claims.OrgID)
		c.Set("role", claims.Role)
		c.Set("email", claims.Email)
		c.Next()
	}
}

// AdminGuard is a follow-up middleware (used after BrickAuthMiddleware) that
// restricts access to admin-only routes.
func AdminGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "FORBIDDEN",
				"message": "This endpoint requires admin role",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// readLedgerIdentityStatus opens the CloudLedger JSON and returns the identity
// status string for the given userID + orgID combination.
// Returns ("active", nil) if the identity is not found (new user not yet enrolled).
func readLedgerIdentityStatus(userID, orgID string) (string, error) {
	ledgerPath := os.Getenv("BRICK_LEDGER_DATA")
	if ledgerPath == "" {
		ledgerPath = "../data/cloud-ledger.json"
	}

	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		return "", fmt.Errorf("ledger file unreadable: %w", err)
	}

	var state ledgerReadState
	if err := json.Unmarshal(data, &state); err != nil {
		return "", fmt.Errorf("ledger JSON malformed: %w", err)
	}

	// Try both key formats used by CloudLedger.identityKey()
	candidateKeys := []string{
		fmt.Sprintf("identity_%s_%s", orgID, userID),
		fmt.Sprintf("identity_%sMSP_%s", orgID, userID),
	}
	for _, key := range candidateKeys {
		if identity, ok := state.Identities[key]; ok {
			return strings.ToLower(identity.Status), nil
		}
	}

	// Identity not on ledger yet — treat as active
	return "active", nil
}
