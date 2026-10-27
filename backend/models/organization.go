package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Organization struct {
	ID          string         `gorm:"primaryKey;type:varchar(36)" json:"id"`
	AppID       string         `gorm:"uniqueIndex:idx_org_app_slug;type:varchar(36);not null" json:"app_id"`
	Environment string         `gorm:"uniqueIndex:idx_org_app_slug;type:varchar(20);not null" json:"environment"`
	Name        string         `gorm:"type:varchar(120);not null" json:"name"`
	Slug        string         `gorm:"uniqueIndex:idx_org_app_slug;type:varchar(80);not null" json:"slug"`
	CreatedBy   string         `gorm:"type:varchar(255);not null" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

func (organization *Organization) BeforeCreate(tx *gorm.DB) error {
	if organization.ID == "" {
		organization.ID = uuid.NewString()
	}
	return nil
}

type OrganizationMembership struct {
	ID             string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
	AppID          string    `gorm:"uniqueIndex:idx_org_membership;type:varchar(36);not null" json:"app_id"`
	Environment    string    `gorm:"uniqueIndex:idx_org_membership;type:varchar(20);not null" json:"environment"`
	OrganizationID string    `gorm:"uniqueIndex:idx_org_membership;type:varchar(36);not null;index" json:"organization_id"`
	UserID         string    `gorm:"uniqueIndex:idx_org_membership;type:varchar(255);not null;index" json:"user_id"`
	Role           string    `gorm:"type:varchar(24);not null;default:member" json:"role"`
	CreatedAt      time.Time `json:"created_at"`
}

func (membership *OrganizationMembership) BeforeCreate(tx *gorm.DB) error {
	if membership.ID == "" {
		membership.ID = uuid.NewString()
	}
	return nil
}

type OrganizationInvitation struct {
	ID             string     `gorm:"primaryKey;type:varchar(36)" json:"id"`
	AppID          string     `gorm:"index;type:varchar(36);not null" json:"app_id"`
	Environment    string     `gorm:"index;type:varchar(20);not null" json:"environment"`
	OrganizationID string     `gorm:"index;type:varchar(36);not null" json:"organization_id"`
	Email          string     `gorm:"type:varchar(255);not null" json:"email"`
	Role           string     `gorm:"type:varchar(24);not null" json:"role"`
	TokenHash      string     `gorm:"uniqueIndex;type:varchar(64);not null" json:"-"`
	ExpiresAt      time.Time  `gorm:"index;not null" json:"expires_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
	CreatedBy      string     `gorm:"type:varchar(255);not null" json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (invitation *OrganizationInvitation) BeforeCreate(tx *gorm.DB) error {
	if invitation.ID == "" {
		invitation.ID = uuid.NewString()
	}
	return nil
}
