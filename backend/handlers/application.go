package handlers

import (
	"brick/db"
	"brick/ledger"
	"brick/models"
	"brick/services"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

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
			"appId":       app.ID,
			"name":        app.Name,
			"ownerId":     app.OwnerID,
			"publishableKey": app.PublishableKey,
			"orgEnabled":  app.OrgEnabled,
			"createdAt":   time.Now().UTC().Format(time.RFC3339),
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
		result = append(result, AppResponse{Application: a, AuthOptionsParsed: opts})
	}

	c.JSON(http.StatusOK, gin.H{"apps": result, "total": len(result)})
}

/* ─── GET /api/v1/apps/:id ─── */

// GetApplicationByID returns a single app by its ID.
func GetApplicationByID(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	id := c.Param("id")
	var app models.Application
	if err := db.DB.Where("id = ? AND owner_id = ?", id, userID).First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
		return
	}

	// Verify ledger asset existence
	ledgerStatus := "not_found"
	svc := ledger.Get()
	if svc != nil {
		if _, err := svc.QueryState(app.LedgerAssetKey); err == nil {
			ledgerStatus = "verified"
		}
	}

	c.JSON(http.StatusOK, gin.H{"app": app, "ledger_status": ledgerStatus})
}

// generateAppName is a helper used internally.
func generateAppName(userEmail string) string {
	return services.SanitizeAppName(userEmail)
}
