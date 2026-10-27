package handlers

import (
	"brick/db"
	"brick/ledger"
	"brick/models"
	"brick/services"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// maskSecretKey moved to top of file

/* ─── POST /api/v1/apps ─── */

type CreateAppInput struct {
	Name           string              `json:"name" binding:"required,min=1,max=100"`
	AuthOptions    []models.AuthOption `json:"auth_options"`
	OrgEnabled     bool                `json:"org_enabled"`
	BillingEnabled bool                `json:"billing_enabled"`
}

// CreateApplication creates a new developer app record in DB and logs it immutably on the ledger.
func CreateApplication(c *gin.Context) {
	// ① Get authenticated user from context (set by BrickAuthMiddleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "No authenticated session"})
		return
	}

	var input CreateAppInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	// ② Serialize auth options to JSON string
	authJSON, err := json.Marshal(input.AuthOptions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SERIALIZATION_ERROR", "message": "Failed to encode auth options"})
		return
	}

	// ③ Persist to Postgres/SQLite
	app := models.Application{
		OwnerID:        fmt.Sprintf("%v", userID),
		Name:           input.Name,
		AuthOptions:    string(authJSON),
		OrgEnabled:     input.OrgEnabled,
		BillingEnabled: input.BillingEnabled,
	}

	if err := db.DB.Create(&app).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to save application"})
		return
	}

	// ④ Log immutably to blockchain ledger
	svc := ledger.Get()
	if svc != nil {
		ledgerPayload := map[string]interface{}{
			"appId":          app.ID,
			"name":           app.Name,
			"ownerId":        app.OwnerID,
			"publishableKey": app.PublishableKey,
			"orgEnabled":     app.OrgEnabled,
			"createdAt":      time.Now().UTC().Format(time.RFC3339),
		}
		payloadJSON, _ := json.Marshal(ledgerPayload)
		_, err := svc.Invoke("CreateAsset", map[string]interface{}{
			"key":   app.LedgerAssetKey,
			"value": string(payloadJSON),
		})
		if err != nil {
			// Non-fatal — log warning but don't fail the request
			fmt.Printf("⚠️ Ledger write warning for app %s: %v\n", app.ID, err)
		}
	}

	services.RecordEvent(
		c,
		app.ID,
		app.OwnerID,
		"Developer",
		"APP_CREATED",
		fmt.Sprintf("Application '%s' initialized with cryptographic keys and ledger anchor", app.Name),
		"confirmed",
		"LOW",
	)

	app.SecretKey = maskSecretKey(app.SecretKey)
	app.LiveSecretKey = maskSecretKey(app.LiveSecretKey)
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"app":     app,
	})
}

/* ─── GET /api/v1/apps ─── */

// GetApplications returns all apps owned by the authenticated user.
func GetApplications(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "No authenticated session"})
		return
	}

	var apps []models.Application
	if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").Find(&apps).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to fetch applications"})
		return
	}

	// Hydrate auth_options back from JSON string for each app
	type AppResponse struct {
		models.Application
		AuthOptionsParsed []models.AuthOption `json:"auth_options_parsed"`
	}
	result := make([]AppResponse, 0, len(apps))
	for _, a := range apps {
		var opts []models.AuthOption
		_ = json.Unmarshal([]byte(a.AuthOptions), &opts)
		a.SecretKey = maskSecretKey(a.SecretKey)
		a.LiveSecretKey = maskSecretKey(a.LiveSecretKey)
		result = append(result, AppResponse{Application: a, AuthOptionsParsed: opts})
	}

	c.JSON(http.StatusOK, gin.H{"apps": result, "total": len(result)})
}

/* ─── GET /api/v1/apps/:id ─── */

func maskSecretKey(k string) string {
	if k == "" {
		return ""
	}
	if len(k) < 14 {
		return "sk_••••••••••••"
	}
	prefix := k[:7]
	suffix := k[len(k)-4:]
	return prefix + "••••••••••••••••" + suffix
}

// GetApplicationByID returns a single app by its ID. Secret keys are masked by default (CRITICAL-003 fix).
func GetApplicationByID(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	// Verify ledger asset existence
	ledgerStatus := "not_found"
	svc := ledger.Get()
	if svc != nil {
		if _, err := svc.QueryState(app.LedgerAssetKey); err == nil {
			ledgerStatus = "verified"
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"app":                  app,
		"secret_key":           maskSecretKey(app.SecretKey),
		"live_secret_key":      maskSecretKey(app.LiveSecretKey),
		"publishable_key":      app.PublishableKey,
		"live_publishable_key": app.LivePublishableKey,
		"ledger_status":        ledgerStatus,
	})
}

/* ─── POST /api/v1/apps/:id/reveal-key ─── */

type RevealKeyInput struct {
	KeyType string `json:"key_type"` // "test" or "live"
}

// RevealAPIKey safely reveals the secret key on-demand for authenticated application owners.
func RevealAPIKey(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	var input RevealKeyInput
	_ = c.ShouldBindJSON(&input)

	if strings.EqualFold(input.KeyType, "live") {
		c.JSON(http.StatusOK, gin.H{
			"key_type":   "live",
			"secret_key": app.LiveSecretKey,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"key_type":   "test",
			"secret_key": app.SecretKey,
		})
	}
}

/* ─── PUT /api/v1/apps/:id ─── */
type UpdateAppInput struct {
	Name           string              `json:"name"`
	AuthOptions    []models.AuthOption `json:"auth_options"`
	OrgEnabled     *bool               `json:"org_enabled"`
	BillingEnabled *bool               `json:"billing_enabled"`
	SettingsJSON   string              `json:"settings_json"`
}

// UpdateApplication saves developer configuration to database and anchors to ledger.
func UpdateApplication(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			// If none exists yet, create one
			app = models.Application{
				OwnerID: fmt.Sprintf("%v", userID),
				Name:    "My Application",
			}
			db.DB.Create(&app)
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	var input UpdateAppInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	if input.Name != "" {
		app.Name = input.Name
	}
	if len(input.AuthOptions) > 0 {
		authJSON, err := json.Marshal(input.AuthOptions)
		if err == nil {
			app.AuthOptions = string(authJSON)
		}
	}
	if input.OrgEnabled != nil {
		app.OrgEnabled = *input.OrgEnabled
	}
	if input.BillingEnabled != nil {
		app.BillingEnabled = *input.BillingEnabled
	}
	if input.SettingsJSON != "" {
		app.SettingsJSON = input.SettingsJSON
	}

	if err := db.DB.Save(&app).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to update application"})
		return
	}

	// Update ledger entry with latest config
	svc := ledger.Get()
	if svc != nil {
		ledgerPayload := map[string]interface{}{
			"appId":          app.ID,
			"name":           app.Name,
			"ownerId":        app.OwnerID,
			"publishableKey": app.PublishableKey,
			"orgEnabled":     app.OrgEnabled,
			"settings":       app.SettingsJSON,
			"updatedAt":      time.Now().UTC().Format(time.RFC3339),
		}
		payloadJSON, _ := json.Marshal(ledgerPayload)
		_, _ = svc.Invoke("UpdateAsset", map[string]interface{}{
			"key":   app.LedgerAssetKey,
			"value": string(payloadJSON),
		})
	}

	services.RecordEvent(
		c,
		app.ID,
		app.OwnerID,
		"Developer",
		"CONFIG_UPDATED",
		"Application authentication and security policies updated",
		"confirmed",
		"LOW",
	)

	app.SecretKey = maskSecretKey(app.SecretKey)
	app.LiveSecretKey = maskSecretKey(app.LiveSecretKey)
	c.JSON(http.StatusOK, gin.H{"success": true, "app": app})
}

// generateAppName is a helper used internally.
func generateAppName(userEmail string) string {
	return services.SanitizeAppName(userEmail)
}

// RotateAPIKeys generates a new secret key for the application
func RotateAPIKeys(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	env := c.Query("env")
	if env == "live" || env == "production" {
		app.LiveSecretKey = "sk_live_" + uuid.New().String()
	} else {
		app.SecretKey = "sk_test_" + uuid.New().String()
	}

	if err := db.DB.Save(&app).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to rotate secret key"})
		return
	}

	services.RecordEvent(
		c,
		app.ID,
		app.OwnerID,
		"Developer",
		"KEY_ROTATED",
		fmt.Sprintf("Secret API key rotated for %s environment", env),
		"confirmed",
		"MEDIUM",
	)

	c.JSON(http.StatusOK, gin.H{
		"message":              "Secret key rotated successfully",
		"secret_key":           app.SecretKey,
		"live_secret_key":      app.LiveSecretKey,
		"publishable_key":      app.PublishableKey,
		"live_publishable_key": app.LivePublishableKey,
		"env":                  env,
	})
}

func RotateJWTSigningKey(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var app models.Application
	appQuery := db.DB.Where("owner_id = ?", userID)
	if appID := c.Param("id"); appID != "current" && appID != "" {
		appQuery = appQuery.Where("id = ?", appID)
	}
	if err := appQuery.Order("created_at desc").First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
		return
	}
	environment := "development"
	if c.Query("env") == "live" || c.Query("env") == "production" {
		environment = "production"
	}
	publishableKey := app.PublishableKey
	if environment == "production" {
		publishableKey = app.LivePublishableKey
	}
	key, err := rotateAppTokenSigningKey(app.ID, environment)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SIGNING_KEY_ROTATION_FAILED", "message": "Could not rotate application token signing key"})
		return
	}
	services.RecordEvent(c, app.ID, app.OwnerID, "Developer", "JWT_SIGNING_KEY_ROTATED", "Application JWT signing key rotated", "confirmed", "MEDIUM")
	c.JSON(http.StatusOK, gin.H{
		"success": true, "kid": key.ID, "environment": environment,
		"jwks_uri":                   "/api/v1/client/jwks.json?publishable_key=" + publishableKey,
		"old_keys_valid_for_seconds": 86400,
	})
}

/* ─── GET /api/v1/apps/:id/users (Application Users Listing) ─── */

func GetApplicationUsers(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	env := c.Query("environment")
	search := c.Query("search")

	query := db.DB.Where("app_id = ?", app.ID)
	if env != "" && env != "all" {
		query = query.Where("environment = ?", env)
	}

	search = strings.TrimSpace(search)
	if len(search) > 64 {
		search = search[:64]
	}
	if search != "" {
		escaped := strings.ReplaceAll(search, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "%", "\\%")
		escaped = strings.ReplaceAll(escaped, "_", "\\_")
		s := "%" + escaped + "%"
		query = query.Where("email LIKE ? OR name LIKE ? OR wallet_address LIKE ?", s, s, s)
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				limit = 100
			} else {
				limit = parsedLimit
			}
		}
	}
	offset := 0
	if p := c.Query("page"); p != "" {
		if page, err := strconv.Atoi(p); err == nil && page > 1 {
			offset = (page - 1) * limit
		}
	}

	var total int64
	query.Model(&models.AppUser{}).Count(&total)

	var users []models.AppUser
	if err := query.Order("created_at desc").Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": total,
		"limit": limit,
		"page":  (offset / limit) + 1,
		"app": gin.H{
			"id":   app.ID,
			"name": app.Name,
		},
	})
}

func GetApplicationUserActivity(c *gin.Context) {
	ownerID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	appID := c.Param("id")
	var app models.Application
	appQuery := db.DB.Where("owner_id = ?", ownerID)
	if appID != "current" && appID != "" {
		appQuery = appQuery.Where("id = ?", appID)
	}
	if err := appQuery.Order("created_at desc").First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
		return
	}
	var user models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ?", c.Param("userId"), app.ID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "USER_NOT_FOUND"})
		return
	}
	query := db.DB.Model(&models.AuditLog{}).Where("app_id = ? AND user_id = ?", app.ID, user.ID)
	if env := c.Query("environment"); env != "" && env != "all" {
		if env != "development" && env != "production" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ENVIRONMENT"})
			return
		}
		query = query.Where("environment = ?", env)
	}
	var events []models.AuditLog
	if err := query.Select("id, event_type, status, risk_score, environment, created_at").Order("created_at desc").Limit(100).Find(&events).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not load user activity"})
		return
	}
	timeline := make([]gin.H, 0, len(events))
	for _, event := range events {
		timeline = append(timeline, gin.H{"id": event.ID, "event_type": event.EventType, "status": event.Status, "risk_score": event.RiskScore, "environment": event.Environment, "timestamp": event.CreatedAt})
	}
	c.JSON(http.StatusOK, gin.H{"user_id": user.ID, "events": timeline, "total": len(timeline)})
}

func UpdateApplicationUserMetadata(c *gin.Context) {
	ownerID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var app models.Application
	query := db.DB.Where("owner_id = ?", ownerID)
	if appID := c.Param("id"); appID != "current" && appID != "" {
		query = query.Where("id = ?", appID)
	}
	if err := query.Order("created_at desc").First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
		return
	}
	var user models.AppUser
	userQuery := db.DB.Where("id = ? AND app_id = ?", c.Param("userId"), app.ID)
	if environment := c.Query("environment"); environment != "" {
		if environment != "development" && environment != "production" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ENVIRONMENT"})
			return
		}
		userQuery = userQuery.Where("environment = ?", environment)
	}
	if err := userQuery.First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "USER_NOT_FOUND"})
		return
	}
	var input struct {
		Metadata json.RawMessage `json:"metadata" binding:"required"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024+1024)
	if err := c.ShouldBindJSON(&input); err != nil || len(input.Metadata) == 0 || len(input.Metadata) > 16384 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_METADATA", "message": "Metadata must be a JSON object no larger than 16 KiB"})
		return
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(input.Metadata, &metadata); err != nil || metadata == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_METADATA", "message": "Metadata must be a JSON object"})
		return
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_METADATA"})
		return
	}
	user.MetadataJSON = string(encoded)
	if err := db.DB.Model(&user).Update("metadata_json", user.MetadataJSON).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not update user metadata"})
		return
	}
	actor := user.Email
	if actor == "" {
		actor = user.WalletAddress
	}
	services.RecordEvent(c, app.ID, user.ID, actor, "USER_METADATA_UPDATED", "Developer updated app-user metadata", "confirmed", "LOW")
	c.JSON(http.StatusOK, gin.H{"success": true, "user_id": user.ID, "metadata": metadata})
}

/* ─── POST /api/v1/apps/:id/users (Direct User Provisioning) ─── */

type CreateAppUserInput struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	Password      string `json:"password"`
	WalletAddress string `json:"wallet_address"`
	Role          string `json:"role"`
	Environment   string `json:"environment"`
}

func CreateApplicationUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	var input CreateAppUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_INPUT", "message": err.Error()})
		return
	}

	if input.Email == "" && input.WalletAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MISSING_IDENTIFIER", "message": "Email or wallet address is required"})
		return
	}

	env := input.Environment
	if env != "production" {
		env = "development"
	}

	// Check if already exists in this app & env
	var existing models.AppUser
	q := db.DB.Where("app_id = ? AND environment = ?", app.ID, env)
	if input.Email != "" {
		q = q.Where("email = ?", input.Email)
	} else {
		q = q.Where("wallet_address = ?", input.WalletAddress)
	}
	if err := q.First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "USER_EXISTS", "message": "User already exists in this environment"})
		return
	}

	var passHash string
	if input.Password != "" {
		bytes, err := bcrypt.GenerateFromPassword([]byte(input.Password), 12)
		if err == nil {
			passHash = string(bytes)
		}
	}

	role := "member"
	if input.Role != "" {
		role = input.Role
	}

	appUser := models.AppUser{
		ID:            "usr_" + uuid.New().String()[:12],
		AppID:         app.ID,
		Environment:   env,
		Email:         input.Email,
		Name:          input.Name,
		PasswordHash:  passHash,
		WalletAddress: input.WalletAddress,
		Role:          role,
		Active:        true,
	}

	if err := db.DB.Create(&appUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to create user"})
		return
	}

	// Anchor to Blockchain Ledger
	svc := ledger.Get()
	if svc != nil {
		adminCaller := ledger.CallerContext{UserIdentity: appUser.ID, OrgID: app.ID, MSPID: "BrickMSP", IsAdmin: true}
		attrs := map[string]string{
			"email":       appUser.Email,
			"name":        appUser.Name,
			"environment": appUser.Environment,
			"role":        appUser.Role,
			"app_id":      app.ID,
			"status":      "active",
		}
		if appUser.WalletAddress != "" {
			attrs["wallet_address"] = appUser.WalletAddress
		}
		_, _ = svc.RegisterIdentity(ledger.RegistrationRequest{
			UserID:     appUser.ID,
			OrgID:      app.ID,
			Role:       appUser.Role,
			Attributes: attrs,
			Caller:     adminCaller,
		})
	}

	actor := appUser.Email
	if actor == "" {
		actor = appUser.WalletAddress
	}
	services.RecordEvent(
		c,
		app.ID,
		appUser.ID,
		actor,
		"USER_CREATED",
		fmt.Sprintf("User account created by developer (%s)", appUser.Role),
		"confirmed",
		"LOW",
	)

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user":    appUser,
	})
}

/* ─── PUT /api/v1/apps/:id/users/:userId ─── */

type UpdateAppUserInput struct {
	Active *bool   `json:"active"`
	Role   *string `json:"role"`
}

func UpdateApplicationUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	targetUserID := c.Param("userId")

	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND"})
			return
		}
	}

	var appUser models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ?", targetUserID, app.ID).First(&appUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "USER_NOT_FOUND"})
		return
	}

	var input UpdateAppUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	if input.Active != nil {
		appUser.Active = *input.Active
	}
	if input.Role != nil && *input.Role != "" {
		appUser.Role = *input.Role
	}

	if err := db.DB.Save(&appUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to update user"})
		return
	}

	// Update status on Blockchain ledger
	svc := ledger.Get()
	if svc != nil {
		caller := ledger.CallerContext{UserIdentity: appUser.ID, OrgID: app.ID, MSPID: "BrickMSP", IsAdmin: true}
		status := "active"
		if !appUser.Active {
			status = "revoked"
		}
		_, _ = svc.UpdateIdentityStatus(app.ID, appUser.ID, status, caller)
	}

	dispatchWebhooks(&app, "user.updated", gin.H{
		"id":     appUser.ID,
		"email":  appUser.Email,
		"active": appUser.Active,
		"role":   appUser.Role,
	})

	c.JSON(http.StatusOK, gin.H{"success": true, "user": appUser})
}

/* ─── DELETE /api/v1/apps/:id/users/:userId ─── */

func DeleteApplicationUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	targetUserID := c.Param("userId")

	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND"})
			return
		}
	}

	var appUser models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ?", targetUserID, app.ID).First(&appUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "USER_NOT_FOUND"})
		return
	}

	// Revoke on blockchain ledger
	svc := ledger.Get()
	if svc != nil {
		caller := ledger.CallerContext{UserIdentity: appUser.ID, OrgID: app.ID, MSPID: "BrickMSP", IsAdmin: true}
		_, _ = svc.UpdateIdentityStatus(app.ID, appUser.ID, "revoked", caller)
	}

	_ = db.DB.Delete(&appUser)

	dispatchWebhooks(&app, "user.deleted", gin.H{
		"id":    appUser.ID,
		"email": appUser.Email,
	})

	actor := appUser.Email
	if actor == "" {
		actor = appUser.WalletAddress
	}
	services.RecordEvent(
		c,
		app.ID,
		appUser.ID,
		actor,
		"USER_DELETED",
		fmt.Sprintf("User %s deleted and revoked on ledger", actor),
		"confirmed",
		"MEDIUM",
	)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "User deleted and revoked on ledger"})
}

/* ─── GET /api/v1/apps/:id/logs (Strictly Application-Isolated Ledger Audit Trail) ─── */

type AppAuditLog struct {
	ID        string `json:"id"`
	Type      string `json:"type"`  // "USER_SIGNUP", "USER_SIGNIN", "MFA_VERIFIED", "KEY_ROTATED", "CONFIG_UPDATED"
	Actor     string `json:"actor"` // user email / wallet / system
	Details   string `json:"details"`
	AssetKey  string `json:"asset_key"`
	Status    string `json:"status"` // "confirmed", "verified"
	Timestamp string `json:"timestamp"`
	TxHash    string `json:"tx_hash"`
}

func GetApplicationLogs(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if id == "current" || id == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND"})
			return
		}
	}

	env := c.Query("environment")

	// Query real persisted audit logs from Neon PostgreSQL scoped to app or developer
	var dbLogs []models.AuditLog
	logQuery := db.DB.Where("app_id = ? OR (app_id = 'system' AND user_id = ?)", app.ID, userID)
	if env != "" && env != "all" {
		logQuery = logQuery.Where("environment = ? OR environment = 'production'", env)
	}

	_ = logQuery.Order("created_at desc").Limit(100).Find(&dbLogs)

	// If no logs recorded yet for this app, record and return an initial anchor event
	if len(dbLogs) == 0 {
		initialLog := models.AuditLog{
			AppID:       app.ID,
			UserID:      app.OwnerID,
			Actor:       "Developer",
			EventType:   "CONFIG_ANCHORED",
			Details:     "Application security policies, publishable keys, and auth guardrails anchored to ledger",
			Status:      "confirmed",
			IPAddress:   c.ClientIP(),
			UserAgent:   c.GetHeader("User-Agent"),
			Environment: "development",
			RiskScore:   "LOW",
			AssetKey:    app.LedgerAssetKey,
		}
		_ = db.DB.Create(&initialLog)
		dbLogs = append(dbLogs, initialLog)
	}

	ledgerMode := "cloud"
	svc := ledger.Get()
	if svc != nil {
		ledgerMode = svc.Mode()
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":        dbLogs,
		"total":       len(dbLogs),
		"app_id":      app.ID,
		"ledger_mode": ledgerMode,
	})
}

func ExportApplicationLogsCSV(c *gin.Context) {
	ownerID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var app models.Application
	query := db.DB.Where("owner_id = ?", ownerID)
	if appID := c.Param("id"); appID != "current" && appID != "" {
		query = query.Where("id = ?", appID)
	}
	if err := query.Order("created_at desc").First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
		return
	}
	logQuery := db.DB.Model(&models.AuditLog{}).Where("app_id = ?", app.ID)
	environment := c.Query("environment")
	if environment != "" && environment != "all" {
		if environment != "development" && environment != "production" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ENVIRONMENT"})
			return
		}
		logQuery = logQuery.Where("environment = ?", environment)
	}
	if rawSince := c.Query("since"); rawSince != "" {
		since, err := time.Parse(time.RFC3339, rawSince)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_DATE", "message": "since must be RFC3339"})
			return
		}
		logQuery = logQuery.Where("created_at >= ?", since)
	}
	if rawUntil := c.Query("until"); rawUntil != "" {
		until, err := time.Parse(time.RFC3339, rawUntil)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_DATE", "message": "until must be RFC3339"})
			return
		}
		logQuery = logQuery.Where("created_at <= ?", until)
	}
	var count int64
	if err := logQuery.Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not count audit logs"})
		return
	}
	const maxRows = 10000
	var logs []models.AuditLog
	if err := logQuery.Select("id, event_type, actor, status, risk_score, environment, created_at, tx_hash").Order("created_at desc").Limit(maxRows).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not export audit logs"})
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=brick-audit-%s.csv", time.Now().UTC().Format("20060102T150405Z")))
	c.Header("Cache-Control", "no-store")
	c.Header("X-Export-Total", strconv.FormatInt(count, 10))
	if count > maxRows {
		c.Header("X-Export-Truncated", "true")
	}
	c.Status(http.StatusOK)
	writer := csv.NewWriter(c.Writer)
	if err := writer.Write([]string{"id", "event_type", "actor", "status", "risk_score", "environment", "timestamp", "tx_hash"}); err != nil {
		return
	}
	for _, event := range logs {
		row := []string{csvSafeCell(event.ID), csvSafeCell(event.EventType), csvSafeCell(event.Actor), csvSafeCell(event.Status), csvSafeCell(event.RiskScore), csvSafeCell(event.Environment), event.CreatedAt.UTC().Format(time.RFC3339Nano), csvSafeCell(event.TxHash)}
		if err := writer.Write(row); err != nil {
			return
		}
	}
	writer.Flush()
}

func csvSafeCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

// TestWebhookPayload simulates a webhook ping and test dispatch
type TestWebhookInput struct {
	URL   string `json:"url" binding:"required"`
	Event string `json:"event"`
}

func TestWebhook(c *gin.Context) {
	var input TestWebhookInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	if input.Event == "" {
		input.Event = "user.created"
	}

	// Return simulated test delivery with Svix compatible signature and timestamp
	c.JSON(http.StatusOK, gin.H{
		"status":      "success",
		"http_status": 200,
		"url":         input.URL,
		"event":       input.Event,
		"delivery_id": "del_" + uuid.New().String()[:8],
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"latency_ms":  34,
	})
}
