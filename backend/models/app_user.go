package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AppUser represents an end-user of a developer's Brick application.
// Authenticated via password, OTP, passkey, or Web3 wallet and recorded on the blockchain ledger.
type AppUser struct {
	ID             string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	AppID          string         `gorm:"index;type:varchar(36);not null" json:"app_id"`
	Email          string         `gorm:"index;type:varchar(255)" json:"email"`
	WalletAddress  string         `gorm:"index;type:varchar(255)" json:"wallet_address"`
	Name           string         `json:"name"`
	Role           string         `gorm:"default:'member'" json:"role"`
	Active         bool           `gorm:"default:true" json:"active"`
	Environment    string         `gorm:"type:varchar(20);default:'development';index" json:"environment"`
	PasswordHash   string         `gorm:"type:varchar(255)" json:"-"`
	MFASecret      string         `gorm:"type:varchar(255)" json:"-"`
	MFAEnabled     bool           `gorm:"default:false" json:"mfa_enabled"`
	LedgerAssetKey string         `gorm:"type:varchar(255)" json:"ledger_asset_key"`
	MetadataJSON   string         `gorm:"type:text" json:"metadata_json"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate assigns a unique ID and ledger asset key.
func (u *AppUser) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = "usr_" + uuid.New().String()
	}
	if u.LedgerAssetKey == "" {
		u.LedgerAssetKey = "appuser_" + u.ID
	}
	return nil
}
