package models

import (
	"time"

	"gorm.io/gorm"
)

// RefreshToken stores a hashed long-lived token used to silently renew access tokens.
// The raw token is NEVER stored — only its SHA-256 hex digest.
type RefreshToken struct {
	ID        string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID    string         `gorm:"index;not null;type:varchar(255)" json:"user_id"`
	OrgID     string         `gorm:"type:varchar(255)" json:"org_id"`
	TokenHash string         `gorm:"not null;uniqueIndex" json:"-"` // SHA-256 of raw token
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	Revoked   bool           `gorm:"default:false;index" json:"revoked"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}
