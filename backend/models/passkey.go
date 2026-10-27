package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PasskeyCredential struct {
	ID             string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
	AppID          string    `gorm:"uniqueIndex:idx_passkey;type:varchar(36);not null" json:"app_id"`
	Environment    string    `gorm:"uniqueIndex:idx_passkey;type:varchar(20);not null" json:"environment"`
	CredentialID   string    `gorm:"uniqueIndex:idx_passkey;type:text;not null" json:"-"`
	UserID         string    `gorm:"index;type:varchar(255);not null" json:"user_id"`
	CredentialData string    `gorm:"type:text;not null" json:"-"`
	Name           string    `gorm:"type:varchar(100)" json:"name"`
	CreatedAt      time.Time `json:"created_at"`
	LastUsedAt     time.Time `json:"last_used_at"`
}

func (credential *PasskeyCredential) BeforeCreate(tx *gorm.DB) error {
	if credential.ID == "" {
		credential.ID = uuid.NewString()
	}
	return nil
}

type WebAuthnChallenge struct {
	ID          string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
	AppID       string    `gorm:"index;type:varchar(36);not null" json:"app_id"`
	Environment string    `gorm:"index;type:varchar(20);not null" json:"environment"`
	UserID      string    `gorm:"index;type:varchar(255);not null" json:"user_id"`
	Type        string    `gorm:"type:varchar(20);not null" json:"type"`
	SessionData string    `gorm:"type:text;not null" json:"-"`
	ExpiresAt   time.Time `gorm:"index;not null" json:"expires_at"`
	Used        bool      `gorm:"index;default:false" json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}

func (challenge *WebAuthnChallenge) BeforeCreate(tx *gorm.DB) error {
	if challenge.ID == "" {
		challenge.ID = uuid.NewString()
	}
	return nil
}
