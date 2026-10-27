package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"

	"brick/db"
	"brick/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var organizationSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$`)

type organizationInput struct {
	Name string `json:"name" binding:"required"`
	Slug string `json:"slug" binding:"required"`
}

type organizationInviteInput struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role"`
}

type organizationAcceptInput struct {
	Token string `json:"token" binding:"required"`
}

type organizationSwitchInput struct {
	OrganizationID string `json:"organization_id" binding:"required"`
}

func clientOrganizationContext(c *gin.Context) (*models.Application, *models.AppUser, string, bool) {
	app, user, environment, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return nil, nil, "", false
	}
	if !app.OrgEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "ORGANIZATIONS_DISABLED", "message": "Organizations are not enabled for this application"})
		return nil, nil, "", false
	}
	return app, user, environment, true
}

func CreateClientOrganization(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	var input organizationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Name and slug are required"})
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	if input.Name == "" || len(input.Name) > 120 || !organizationSlugPattern.MatchString(input.Slug) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ORGANIZATION", "message": "Provide a name (max 120 characters) and a valid lowercase slug"})
		return
	}
	organization := models.Organization{AppID: app.ID, Environment: environment, Name: input.Name, Slug: input.Slug, CreatedBy: user.ID}
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&organization).Error; err != nil {
			return err
		}
		return tx.Create(&models.OrganizationMembership{AppID: app.ID, Environment: environment, OrganizationID: organization.ID, UserID: user.ID, Role: "owner"}).Error
	})
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "ORGANIZATION_CREATE_FAILED", "message": "Organization slug is already in use or could not be created"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"organization": organization, "role": "owner"})
}

func ListClientOrganizations(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	var organizations []struct {
		models.Organization
		Role string `json:"role"`
	}
	err := db.DB.Table("organizations").Select("organizations.*, organization_memberships.role AS role").Joins("JOIN organization_memberships ON organization_memberships.organization_id = organizations.id AND organization_memberships.app_id = organizations.app_id AND organization_memberships.environment = organizations.environment").Where("organization_memberships.app_id = ? AND organization_memberships.environment = ? AND organization_memberships.user_id = ?", app.ID, environment, user.ID).Order("organizations.created_at asc").Find(&organizations).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not load organizations"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"organizations": organizations})
}

func SelectClientOrganization(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	var input organizationSwitchInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Organization ID is required"})
		return
	}
	var membership models.OrganizationMembership
	if err := db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, environment, input.OrganizationID, user.ID).First(&membership).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "ORGANIZATION_ACCESS_DENIED", "message": "You are not a member of this organization"})
		return
	}
	privateKey, signingKey, err := getAppTokenSigningKey(app.ID, environment)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "TOKEN_SIGNING_UNAVAILABLE", "message": "Application token signing is not configured"})
		return
	}
	now := time.Now().UTC()
	claims := gin.H{"sub": user.ID, "app_id": app.ID, "email": user.Email, "name": user.Name, "role": user.Role, "wallet_address": user.WalletAddress, "environment": environment, "org_id": membership.OrganizationID, "org_role": membership.Role, "iat": now.Unix(), "exp": now.Add(24 * time.Hour).Unix(), "iss": "https://api.brick.id", "aud": app.ID, "ledger_key": user.LedgerAssetKey}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = signingKey.ID
	accessToken, err := token.SignedString(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_ERROR", "message": "Could not issue organization session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": accessToken, "organization_id": membership.OrganizationID, "organization_role": membership.Role, "expires_in": 86400})
}

func ListClientOrganizationMembers(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	organizationID := c.Param("orgId")
	var callerMembership models.OrganizationMembership
	if err := db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, environment, organizationID, user.ID).First(&callerMembership).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ORGANIZATION_NOT_FOUND", "message": "Organization not found"})
		return
	}
	var members []struct {
		ID        string    `json:"id"`
		UserID    string    `json:"user_id"`
		Email     string    `json:"email"`
		Name      string    `json:"name"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
	}
	err := db.DB.Table("organization_memberships").Select("organization_memberships.id, organization_memberships.user_id, app_users.email, app_users.name, organization_memberships.role, organization_memberships.created_at").Joins("JOIN app_users ON app_users.id = organization_memberships.user_id AND app_users.app_id = organization_memberships.app_id AND app_users.environment = organization_memberships.environment").Where("organization_memberships.app_id = ? AND organization_memberships.environment = ? AND organization_memberships.organization_id = ?", app.ID, environment, organizationID).Order("organization_memberships.created_at asc").Find(&members).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not load organization members"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": members})
}

func CreateClientOrganizationInvitation(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	organizationID := c.Param("orgId")
	var organization models.Organization
	if err := db.DB.Where("id = ? AND app_id = ? AND environment = ?", organizationID, app.ID, environment).First(&organization).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ORGANIZATION_NOT_FOUND", "message": "Organization not found"})
		return
	}
	var callerMembership models.OrganizationMembership
	if err := db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, environment, organizationID, user.ID).First(&callerMembership).Error; err != nil || (callerMembership.Role != "owner" && callerMembership.Role != "admin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "FORBIDDEN", "message": "Organization owner or admin role required"})
		return
	}
	var input organizationInviteInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "A valid email address is required"})
		return
	}
	role := strings.ToLower(strings.TrimSpace(input.Role))
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ROLE", "message": "Invited users can be assigned member or admin role"})
		return
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	var existing models.AppUser
	if err := db.DB.Where("app_id = ? AND environment = ? AND lower(email) = ?", app.ID, environment, input.Email).First(&existing).Error; err == nil {
		var membership models.OrganizationMembership
		if db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, environment, organizationID, existing.ID).First(&membership).Error == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "ALREADY_MEMBER", "message": "This user is already a member"})
			return
		}
	}
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "INVITATION_FAILED", "message": "Could not create invitation"})
		return
	}
	secret := base64.RawURLEncoding.EncodeToString(rawToken)
	digest := sha256.Sum256([]byte(secret))
	invitation := models.OrganizationInvitation{AppID: app.ID, Environment: environment, OrganizationID: organizationID, Email: input.Email, Role: role, TokenHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour), CreatedBy: user.ID}
	if err := db.DB.Create(&invitation).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "INVITATION_FAILED", "message": "Could not create invitation"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"invitation": invitation, "acceptance_token": secret, "delivery": "Send this one-time token to the invited user using your trusted email provider"})
}

func RemoveClientOrganizationMember(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	organizationID := c.Param("orgId")
	var callerMembership models.OrganizationMembership
	if err := db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, environment, organizationID, user.ID).First(&callerMembership).Error; err != nil || (callerMembership.Role != "owner" && callerMembership.Role != "admin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "FORBIDDEN", "message": "Organization owner or admin role required"})
		return
	}
	var target models.OrganizationMembership
	if err := db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, environment, organizationID, c.Param("userId")).First(&target).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "MEMBER_NOT_FOUND", "message": "Organization member not found"})
		return
	}
	if target.Role == "owner" || (target.Role == "admin" && callerMembership.Role != "owner") {
		c.JSON(http.StatusForbidden, gin.H{"error": "ROLE_PROTECTED", "message": "Only an owner can remove admins; owners cannot be removed"})
		return
	}
	if err := db.DB.Delete(&target).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not remove organization member"})
		return
	}
	c.Status(http.StatusNoContent)
}

func AcceptClientOrganizationInvitation(c *gin.Context) {
	app, user, environment, ok := clientOrganizationContext(c)
	if !ok {
		return
	}
	var input organizationAcceptInput
	if err := c.ShouldBindJSON(&input); err != nil || len(input.Token) < 40 || len(input.Token) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "A valid invitation token is required"})
		return
	}
	digest := sha256.Sum256([]byte(input.Token))
	tokenHash := hex.EncodeToString(digest[:])
	var membership models.OrganizationMembership
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		var invitation models.OrganizationInvitation
		if err := tx.Where("token_hash = ? AND app_id = ? AND environment = ? AND accepted_at IS NULL AND expires_at > ?", tokenHash, app.ID, environment, time.Now().UTC()).First(&invitation).Error; err != nil {
			return err
		}
		if !strings.EqualFold(invitation.Email, user.Email) {
			return gorm.ErrRecordNotFound
		}
		now := time.Now().UTC()
		updated := tx.Model(&models.OrganizationInvitation{}).Where("id = ? AND accepted_at IS NULL AND expires_at > ?", invitation.ID, now).Update("accepted_at", now)
		if updated.Error != nil {
			return updated.Error
		}
		if updated.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		membership = models.OrganizationMembership{AppID: app.ID, Environment: environment, OrganizationID: invitation.OrganizationID, UserID: user.ID, Role: invitation.Role}
		return tx.Create(&membership).Error
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVITATION_INVALID", "message": "Invitation is invalid, expired, already used, or belongs to another email"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"membership": membership})
}
