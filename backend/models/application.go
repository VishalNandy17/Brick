package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuthOption mirrors a sign-in method that can be toggled on/off per app.
type AuthOption struct {
	Provider string `json:"provider"` // "email","google","github","phone","username","apple"
	Enabled  bool   `json:"enabled"`
}

// Application represents a developer's registered Brick application.
// Each app gets its own set of auth providers, org settings, and publishable key.
type Application struct {
	ID              string         `gorm:"primaryKey;type:varchar(36)" json:"id"`
	OwnerID         string         `gorm:"index;type:varchar(255);not null" json:"owner_id"`
	Name            string         `gorm:"type:varchar(255);not null" json:"name"`
	AuthOptions     string         `gorm:"type:text" json:"auth_options"`     // JSON: []AuthOption
	OrgEnabled      bool           `gorm:"default:false" json:"org_enabled"`
	BillingEnabled  bool           `gorm:"default:false" json:"billing_enabled"`
	PublishableKey  string         `gorm:"type:varchar(255);uniqueIndex" json:"publishable_key"`
	SecretKey       string         `gorm:"type:varchar(255)" json:"-"` // never exposed in JSON
	LedgerAssetKey  string         `gorm:"type:varchar(255)" json:"ledger_asset_key"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate sets a UUID primary key and generates API keys before insert.
func (a *Application) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	if a.PublishableKey == "" {
		a.PublishableKey = "pk_" + uuid.New().String()
	}
	if a.SecretKey == "" {
		a.SecretKey = "sk_" + uuid.New().String()
	}
	if a.LedgerAssetKey == "" {
		a.LedgerAssetKey = "app_" + a.ID
	}
	return nil
}
