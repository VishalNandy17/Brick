package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the Brick database
type User struct {
	ID           string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Email        string         `gorm:"uniqueIndex;not null" json:"email"`
	Name         string         `json:"name"`
	Role         string         `gorm:"default:'user'" json:"role"` // admin, user, auditor
	Active       bool           `gorm:"default:true" json:"active"`
	PasswordHash string         `gorm:"type:varchar(255)" json:"-"` // bcrypt hash, never exposed
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// UserRequest is the request body for creating/updating users (used mostly internally or by admins)
type UserRequest struct {
	Email string `json:"email" binding:"required,email"`
	Name  string `json:"name" binding:"required"`
	Role  string `json:"role" binding:"required,oneof=admin user auditor"`
}
