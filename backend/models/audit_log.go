package models

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditLog records security, authentication, and access events across Brick.
// It powers the Developer Dashboard audit trail and provides the real event stream
// for the Meta AI Security Engine (muse-spark-1.1).
type AuditLog struct {
	ID           string         `gorm:"primaryKey;type:varchar(64)" json:"id"`
	AppID        string         `gorm:"index;type:varchar(64);not null" json:"app_id"`
	UserID       string         `gorm:"index;type:varchar(255)" json:"user_id"`
	Actor        string         `gorm:"index;type:varchar(255);not null" json:"actor"`      // user email, wallet, or "system"
	EventType    string         `gorm:"index;type:varchar(64);not null" json:"type"`        // USER_SIGNUP, USER_SIGNIN, etc.
	Details      string         `gorm:"type:text;not null" json:"details"`
	Status       string         `gorm:"type:varchar(32);default:'confirmed'" json:"status"` // confirmed, verified, failed, quarantined
	IPAddress    string         `gorm:"type:varchar(64)" json:"ip_address"`
	UserAgent    string         `gorm:"type:text" json:"user_agent"`
	Environment  string         `gorm:"index;type:varchar(20);default:'development'" json:"environment"` // development | production | live
	RiskScore    string         `gorm:"type:varchar(20);default:'LOW'" json:"risk_score"`                // LOW, MEDIUM, HIGH, CRITICAL
	TxHash       string         `gorm:"type:varchar(66)" json:"tx_hash"`                                 // 0x... cryptographic hash
	AssetKey     string         `gorm:"type:varchar(255)" json:"asset_key"`
	MetadataJSON string         `gorm:"type:text" json:"metadata_json"`
	CreatedAt    time.Time      `gorm:"index" json:"timestamp"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate populates default ID, timestamps, and cryptographic transaction hash.
func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = "log_" + uuid.New().String()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.TxHash == "" {
		hashInput := fmt.Sprintf("%s:%s:%s:%d", a.AppID, a.Actor, a.EventType, a.CreatedAt.UnixNano())
		h := sha256.Sum256([]byte(hashInput))
		a.TxHash = fmt.Sprintf("0x%x", h)
	}
	if a.AssetKey == "" && a.AppID != "" {
		a.AssetKey = "log_asset_" + a.ID
	}
	return nil
}
