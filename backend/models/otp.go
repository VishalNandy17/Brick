package models

import (
	"time"

	"gorm.io/gorm"
)

// OTPRecord stores a one-time password for email verification
type OTPRecord struct {
	ID        uint           `gorm:"primaryKey;autoIncrement" json:"-"`
	Email     string         `gorm:"index;not null" json:"email"`
	Code      string         `gorm:"not null" json:"-"`  // SHA-256 hashed OTP, never stored in raw plaintext
	Attempts  int            `gorm:"default:0" json:"-"` // Tracks verification attempts; locked after 5 failed attempts
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	Used      bool           `gorm:"default:false" json:"used"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type SIWENonce struct {
	Nonce         string    `gorm:"primaryKey;type:varchar(64)" json:"-"`
	AppID         string    `gorm:"index;not null;type:varchar(36)" json:"-"`
	Environment   string    `gorm:"type:varchar(20);not null" json:"-"`
	WalletAddress string    `gorm:"index;type:varchar(42);not null" json:"-"`
	Message       string    `gorm:"type:text;not null" json:"-"`
	ExpiresAt     time.Time `gorm:"index;not null" json:"-"`
	Used          bool      `gorm:"default:false;index" json:"-"`
	CreatedAt     time.Time `json:"-"`
}

type MFAChallenge struct {
	ID          string    `gorm:"primaryKey;type:varchar(36)" json:"-"`
	AppID       string    `gorm:"index;not null;type:varchar(36)" json:"-"`
	Environment string    `gorm:"type:varchar(20);not null" json:"-"`
	UserID      string    `gorm:"index;not null;type:varchar(255)" json:"-"`
	ExpiresAt   time.Time `gorm:"index;not null" json:"-"`
	Used        bool      `gorm:"default:false;index" json:"-"`
	CreatedAt   time.Time `json:"-"`
}

type OAuthTransaction struct {
	StateHash   string    `gorm:"primaryKey;type:varchar(64)" json:"-"`
	NonceHash   string    `gorm:"type:varchar(64)" json:"-"`
	AppID       string    `gorm:"index;not null;type:varchar(36)" json:"-"`
	Environment string    `gorm:"type:varchar(20);not null" json:"-"`
	Provider    string    `gorm:"type:varchar(20);not null" json:"-"`
	RedirectURI string    `gorm:"type:text;not null" json:"-"`
	ExpiresAt   time.Time `gorm:"index;not null" json:"-"`
	Used        bool      `gorm:"default:false;index" json:"-"`
	CreatedAt   time.Time `json:"-"`
}
