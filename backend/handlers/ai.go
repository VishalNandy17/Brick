package handlers

import (
	"brick/db"
	"brick/models"
	"brick/services"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Global MetaAIService instance
var metaAIService = services.NewMetaAIService()

/* ─────────────────────────────────────────────────────────────
   POST /api/v1/apps/:id/ai/analyze-logs
───────────────────────────────────────────────────────────── */

type AnalyzeLogsRequest struct {
	Limit       int    `json:"limit"`       // Default 50, max 100
	Environment string `json:"environment"` // "development" | "production" | "all"
}

// AnalyzeLogs fetches recent real audit logs for the application and feeds them to Meta AI muse-spark-1.1
func AnalyzeLogs(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "Authentication required"})
		return
	}

	appID := c.Param("id")
	var app models.Application
	if appID == "current" || appID == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", appID, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	var req AnalyzeLogsRequest
	_ = c.ShouldBindJSON(&req)

	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	// Fetch real audit logs from Neon PostgreSQL scoped strictly to this app
	var logs []models.AuditLog
	q := db.DB.Where("app_id = ? OR (app_id = 'system' AND user_id = ?)", app.ID, userID)
	if req.Environment != "" && req.Environment != "all" {
		q = q.Where("environment = ? OR environment = 'production'", req.Environment)
	}
	if err := q.Order("created_at desc").Limit(limit).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to fetch audit logs"})
		return
	}

	// If no logs exist yet, anchor an initial baseline event
	if len(logs) == 0 {
		initialLog := models.AuditLog{
			AppID:       app.ID,
			UserID:      app.OwnerID,
			Actor:       "Developer",
			EventType:   "CONFIG_ANCHORED",
			Details:     "Application security policies, publishable keys, and auth guardrails initialized",
			Status:      "confirmed",
			IPAddress:   c.ClientIP(),
			UserAgent:   c.GetHeader("User-Agent"),
			Environment: "development",
			RiskScore:   "LOW",
			AssetKey:    app.LedgerAssetKey,
		}
		_ = db.DB.Create(&initialLog)
		logs = append(logs, initialLog)
	}

	logsJSONBytes, err := json.Marshal(logs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MARSHAL_ERROR", "message": "Failed to format logs for AI"})
		return
	}

	// Query Meta AI muse-spark-1.1
	analysis, err := metaAIService.AnalyzeSecurityEvents(c.Request.Context(), app.ID, string(logsJSONBytes), len(logs))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI_ANALYSIS_FAILED", "message": err.Error()})
		return
	}

	// Record AI analysis audit event
	services.RecordEvent(
		c,
		app.ID,
		app.OwnerID,
		"Meta AI Sentinel",
		"AI_SECURITY_ANALYZED",
		fmt.Sprintf("Scanned %d audit logs with Meta AI (%s). Overall risk: %s", len(logs), analysis.Model, analysis.RiskLevel),
		"confirmed",
		analysis.RiskLevel,
	)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"analysis": analysis,
		"meta": gin.H{
			"model":          analysis.Model,
			"events_scanned": len(logs),
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		},
	})
}

/* ─────────────────────────────────────────────────────────────
   POST /api/v1/apps/:id/ai/explain-access
───────────────────────────────────────────────────────────── */

type ExplainAccessRequest struct {
	Event models.AuditLog `json:"event"`
}

// ExplainAccess explains an audit log event in plain, human-understandable English
func ExplainAccess(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "Authentication required"})
		return
	}

	appID := c.Param("id")
	var app models.Application
	if appID == "current" || appID == "" {
		if err := db.DB.Where("owner_id = ?", userID).Order("created_at desc").First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	} else {
		if err := db.DB.Where("id = ? AND owner_id = ?", appID, userID).First(&app).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
			return
		}
	}

	var req ExplainAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Event payload is required"})
		return
	}

	eventJSONBytes, err := json.Marshal(req.Event)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MARSHAL_ERROR", "message": "Failed to serialize event"})
		return
	}

	// Query Meta AI muse-spark-1.1
	explanation, err := metaAIService.ExplainAccessEvent(c.Request.Context(), string(eventJSONBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI_EXPLANATION_FAILED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"explanation": explanation,
		"model":       "muse-spark-1.1",
	})
}
