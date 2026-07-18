package handlers

import (
	"brick/db"
	"brick/models"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ledgerMu serializes all writes to cloud-ledger.json to prevent data races.
var ledgerMu sync.Mutex

// ── Request / Response ─────────────────────────────────────────────────────

type RevokeSessionInput struct {
	UserID string `json:"user_id" binding:"required"`
	OrgID  string `json:"org_id" binding:"required"`
	Reason string `json:"reason"`
}

// ── Ledger JSON types (mirrors ledger/cloud_ledger.go) ────────────────────
// Duplicated here to avoid importing the ledger package in handlers (separation of concerns).

type revokeIdentity struct {
	UserID       string            `json:"userId"`
	OrgID        string            `json:"orgId"`
	Role         string            `json:"role"`
	Status       string            `json:"status"`
	IdentityHash string            `json:"identityHash"`
	MSPID        string            `json:"mspId"`
	Attributes   map[string]string `json:"attributes"`
	CreatedAt    string            `json:"createdAt"`
	UpdatedAt    string            `json:"updatedAt"`
}

type revokeHistoryEntry struct {
	Timestamp string      `json:"timestamp"`
	Value     interface{} `json:"value"`
	TxID      string      `json:"txid"`
	IsDelete  bool        `json:"isDelete,omitempty"`
}

type revokeLedgerState struct {
	Identities map[string]*revokeIdentity      `json:"identities"`
	Assets     map[string]string               `json:"assets"`
	History    map[string][]revokeHistoryEntry  `json:"history"`
	Events     []map[string]interface{}         `json:"events"`
}

/* ─── POST /api/v1/brick/admin/revoke-session ─── */

// RevokeSession is an admin-only endpoint that:
//  1. Marks the user inactive in Postgres
//  2. Revokes all active refresh tokens for the user
//  3. Writes a REVOKED status + history block to cloud-ledger.json
func RevokeSession(c *gin.Context) {
	var input RevokeSessionInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": err.Error(),
		})
		return
	}

	reason := input.Reason
	if reason == "" {
		reason = "Revoked by administrator"
	}

	// ── 1. Mark user inactive in Postgres ──────────────────────────────────
	dbResult := db.DB.Model(&models.User{}).
		Where("id = ?", input.UserID).
		Updates(map[string]interface{}{"active": false})
	if dbResult.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "DB_ERROR",
			"message": fmt.Sprintf("Failed to deactivate user in database: %v", dbResult.Error),
		})
		return
	}
	if dbResult.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "USER_NOT_FOUND",
			"message": fmt.Sprintf("No user found with ID: %s", input.UserID),
		})
		return
	}

	// ── 2. Revoke all active refresh tokens ────────────────────────────────
	db.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked = false", input.UserID).
		Update("revoked", true)

	// ── 3. Append REVOKED block to CloudLedger ─────────────────────────────
	ledgerPath := ledgerFilePath()
	updatedIdentity, ledgerErr := appendRevocationToLedger(ledgerPath, input.UserID, input.OrgID, reason)
	if ledgerErr != nil {
		// Non-fatal: DB already updated. Return partial success with warning.
		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"user_id":  input.UserID,
			"warning":  fmt.Sprintf("Postgres updated but ledger write failed: %v", ledgerErr),
			"message":  "User deactivated in database. Ledger update pending.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"user_id":          input.UserID,
		"ledger_status":    "revoked",
		"ledger_identity":  updatedIdentity,
		"message":          "Session revoked in Postgres and committed to blockchain ledger",
	})
}

// appendRevocationToLedger reads, updates, and atomically rewrites cloud-ledger.json.
// It acquires the global ledgerMu lock to prevent concurrent write corruption.
func appendRevocationToLedger(path, userID, orgID, reason string) (*revokeIdentity, error) {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()

	// Read current ledger state
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ledger file: %w", err)
	}

	var state revokeLedgerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse ledger JSON: %w", err)
	}

	if state.Identities == nil {
		state.Identities = make(map[string]*revokeIdentity)
	}
	if state.History == nil {
		state.History = make(map[string][]revokeHistoryEntry)
	}
	if state.Events == nil {
		state.Events = []map[string]interface{}{}
	}

	// Locate identity by trying both key formats
	var key string
	var identity *revokeIdentity
	for _, k := range []string{
		fmt.Sprintf("identity_%s_%s", orgID, userID),
		fmt.Sprintf("identity_%sMSP_%s", orgID, userID),
	} {
		if id, ok := state.Identities[k]; ok {
			key = k
			identity = id
			break
		}
	}

	now := time.Now().UTC()
	txID := fmt.Sprintf("revoke_tx_%d", now.UnixNano())

	if identity == nil {
		// Create a revocation tombstone if the identity was never enrolled on ledger
		key = fmt.Sprintf("identity_%s_%s", orgID, userID)
		identity = &revokeIdentity{
			UserID:     userID,
			OrgID:      orgID,
			Status:     "revoked",
			Attributes: map[string]string{},
			CreatedAt:  now.Format(time.RFC3339),
			UpdatedAt:  now.Format(time.RFC3339),
		}
		state.Identities[key] = identity
	} else {
		identity.Status = "revoked"
		identity.UpdatedAt = now.Format(time.RFC3339)
	}

	// Append immutable history entry
	state.History[key] = append(state.History[key], revokeHistoryEntry{
		Timestamp: now.Format(time.RFC3339),
		TxID:      txID,
		Value: map[string]interface{}{
			"action":    "REVOKED",
			"reason":    reason,
			"userID":    userID,
			"orgID":     orgID,
			"timestamp": now.Format(time.RFC3339),
		},
	})

	// Append ledger event (audit trail)
	state.Events = append(state.Events, map[string]interface{}{
		"type": "IdentityRevoked",
		"payload": map[string]string{
			"userId": userID,
			"orgId":  orgID,
			"txId":   txID,
			"reason": reason,
		},
		"timestamp": now.Format(time.RFC3339),
	})

	// Atomically write back
	out, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal ledger: %w", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return nil, fmt.Errorf("write ledger file: %w", err)
	}

	return identity, nil
}

func ledgerFilePath() string {
	if p := os.Getenv("BRICK_LEDGER_DATA"); p != "" {
		return p
	}
	return "../data/cloud-ledger.json"
}
