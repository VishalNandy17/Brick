package models

import (
	"time"

	"gorm.io/gorm"
)

// OTPRecord stores a one-time password for email verification
type OTPRecord struct {
	ID        uint           `gorm:"primaryKey;autoIncrement" json:"-"`
	Email     string         `gorm:"index;not null" json:"email"`
	Code      string         `gorm:"not null" json:"-"` // Never expose the raw OTP in JSON
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	Used      bool           `gorm:"default:false" json:"used"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}
