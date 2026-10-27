package handlers

import (
	"brick/db"
	"brick/models"
	"brick/services"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Global MetaAIService instance
var metaAIService *services.MetaAIService
var metaAIServiceOnce sync.Once

func getMetaAIService() *services.MetaAIService {
	metaAIServiceOnce.Do(func() {
		metaAIService = services.NewMetaAIService()
	})
	return metaAIService
}

/* ─────────────────────────────────────────────────────────────
   POST /api/v1/apps/:id/ai/analyze-logs
───────────────────────────────────────────────────────────── */

type AnalyzeLogsRequest struct {
	Limit       int    `json:"limit"`       // Default 50, max 100
	Environment string `json:"environment"` // "development" | "production" | "all"
}

type aiAuditEvent struct {
	ID          string    `json:"id"`
	Actor       string    `json:"actor"`
	EventType   string    `json:"type"`
	Status      string    `json:"status"`
	RiskScore   string    `json:"risk_score"`
	Environment string    `json:"environment"`
	Timestamp   time.Time `json:"timestamp"`
}

type loginSignal struct {
	Actor         string    `json:"actor"`
	IPFingerprint string    `json:"ip_fingerprint"`
	EventType     string    `json:"type"`
	Status        string    `json:"status"`
	Environment   string    `json:"environment"`
	Timestamp     time.Time `json:"timestamp"`
}

type loginIPBucket struct {
	Fingerprint string
	Events      []models.AuditLog
}

func DetectLoginAnomalies(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "Authentication required"})
		return
	}
	var app models.Application
	query := db.DB.Where("owner_id = ?", userID)
	if appID := c.Param("id"); appID != "current" && appID != "" {
		query = query.Where("id = ?", appID)
	}
	if err := query.Order("created_at desc").First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Application not found"})
		return
	}
	var input struct {
		Environment string `json:"environment"`
	}
	if c.Request.ContentLength > 0 && c.ShouldBindJSON(&input) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}
	if input.Environment == "" {
		input.Environment = "all"
	}
	if input.Environment != "all" && input.Environment != "development" && input.Environment != "production" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ENVIRONMENT"})
		return
	}
	var logs []models.AuditLog
	logsQuery := db.DB.Where("app_id = ? AND created_at >= ? AND event_type IN ? AND ip_address <> '' AND ip_address <> ?", app.ID, time.Now().UTC().Add(-30*24*time.Hour), []string{"USER_LOGIN_FAILED", "SESSION_CREATED", "SOCIAL_LOGIN", "SIWE_AUTH_FAILED"}, "unknown")
	if input.Environment != "all" {
		logsQuery = logsQuery.Where("environment = ?", input.Environment)
	}
	if err := logsQuery.Order("created_at desc").Limit(1000).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not load login events"})
		return
	}
	if len(logs) == 0 {
		analysis := services.SecurityAnalysisResult{AppID: app.ID, Model: "brick-login-anomaly-rules-v1", Provider: "local_rules", RiskLevel: "low", Summary: "No login audit events with IP context were available in the selected period.", Findings: []services.SecurityFinding{}, AnalyzedAt: time.Now().UTC().Format(time.RFC3339)}
		c.JSON(http.StatusOK, gin.H{"success": true, "analysis": analysis, "events_scanned": 0, "ip_fingerprints_sent": 0})
		return
	}
	buckets := map[string]*loginIPBucket{}
	signals := make([]loginSignal, 0, len(logs))
	for _, event := range logs {
		actor := services.PseudonymizeActor(app.ID, event.Actor)
		fingerprint := services.PseudonymizeActor(app.ID+":ip", event.IPAddress)
		if buckets[fingerprint] == nil {
			buckets[fingerprint] = &loginIPBucket{Fingerprint: fingerprint}
		}
		buckets[fingerprint].Events = append(buckets[fingerprint].Events, event)
		signals = append(signals, loginSignal{Actor: actor, IPFingerprint: fingerprint, EventType: event.EventType, Status: event.Status, Environment: event.Environment, Timestamp: event.CreatedAt})
	}
	analysisInput, err := json.Marshal(signals)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MARSHAL_ERROR"})
		return
	}
	analysis, err := getMetaAIService().AnalyzeSecurityEvents(c.Request.Context(), app.ID, string(analysisInput), len(signals))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI_ANALYSIS_FAILED", "message": "Could not analyze login signals"})
		return
	}
	for _, bucket := range buckets {
		recentFailed := 0
		recentActors := map[string]struct{}{}
		for _, event := range bucket.Events {
			if event.Status == "failed" || event.EventType == "USER_LOGIN_FAILED" || event.EventType == "SIWE_AUTH_FAILED" {
				if event.CreatedAt.After(time.Now().UTC().Add(-15 * time.Minute)) {
					recentFailed++
					recentActors[services.PseudonymizeActor(app.ID, event.Actor)] = struct{}{}
				}
			}
		}
		if recentFailed >= 5 {
			analysis.Findings = append(analysis.Findings, services.SecurityFinding{ID: "ip_" + bucket.Fingerprint, Severity: "high", Title: "Repeated authentication failures from one network", Description: fmt.Sprintf("An app-scoped network fingerprint had %d failed attempts in 15 minutes. This may indicate credential guessing; shared networks and proxies can produce false positives.", recentFailed), Actor: "multiple", EventType: "USER_LOGIN_FAILED", Suggestion: "Review the correlated login events and rate-limit configuration. This finding does not automatically block users."})
		}
		if len(recentActors) >= 10 && recentFailed >= 10 {
			analysis.Findings = append(analysis.Findings, services.SecurityFinding{ID: "spray_" + bucket.Fingerprint, Severity: "critical", Title: "Possible distributed credential attack", Description: fmt.Sprintf("An app-scoped network fingerprint affected %d distinct pseudonymized actors with %d failed attempts in 15 minutes.", len(recentActors), recentFailed), Actor: "multiple", EventType: "USER_LOGIN_FAILED", Suggestion: "Investigate source distribution and configure progressive rate limits or MFA; review before taking action."})
		}
	}
	analysis.AnomaliesDetected = len(analysis.Findings)
	for _, finding := range analysis.Findings {
		if finding.Severity == "critical" {
			analysis.RiskLevel = "critical"
			break
		}
		if finding.Severity == "high" && analysis.RiskLevel != "critical" {
			analysis.RiskLevel = "high"
		}
	}
	services.RecordEvent(c, app.ID, app.OwnerID, "Brick AI Login Sentinel", "AI_LOGIN_ANOMALIES_SCANNED", fmt.Sprintf("Analyzed %d authentication events using %s", len(signals), analysis.Provider), "confirmed", analysis.RiskLevel)
	c.JSON(http.StatusOK, gin.H{"success": true, "analysis": analysis, "events_scanned": len(signals), "ip_fingerprints_sent": len(buckets), "period_days": 30, "human_review_required": true})
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

	modelEvents := make([]aiAuditEvent, 0, len(logs))
	for _, entry := range logs {
		actor := "anonymous"
		if entry.Actor != "" {
			actor = services.PseudonymizeActor(app.ID, entry.Actor)
		}
		modelEvents = append(modelEvents, aiAuditEvent{
			ID:          entry.ID,
			Actor:       actor,
			EventType:   entry.EventType,
			Status:      entry.Status,
			RiskScore:   entry.RiskScore,
			Environment: entry.Environment,
			Timestamp:   entry.CreatedAt,
		})
	}
	logsJSONBytes, err := json.Marshal(modelEvents)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MARSHAL_ERROR", "message": "Failed to format logs for AI"})
		return
	}

	// Send only the minimum event fields required for security analysis.
	analysis, err := getMetaAIService().AnalyzeSecurityEvents(c.Request.Context(), app.ID, string(logsJSONBytes), len(logs))
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
			"provider":       analysis.Provider,
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

	if req.Event.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Event ID is required"})
		return
	}
	var event models.AuditLog
	if err := db.DB.Where("id = ? AND app_id = ?", req.Event.ID, app.ID).First(&event).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "NOT_FOUND", "message": "Audit event not found"})
		return
	}
	actor := "anonymous"
	if event.Actor != "" {
		actor = services.PseudonymizeActor(app.ID, event.Actor)
	}
	modelEvent := aiAuditEvent{
		ID: event.ID, Actor: actor, EventType: event.EventType, Status: event.Status,
		RiskScore: event.RiskScore, Environment: event.Environment, Timestamp: event.CreatedAt,
	}
	eventJSONBytes, err := json.Marshal(modelEvent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MARSHAL_ERROR", "message": "Failed to serialize event"})
		return
	}

	// The model receives minimized, app-scoped event fields, not raw audit details.
	explanation, err := getMetaAIService().ExplainAccessEvent(c.Request.Context(), string(eventJSONBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI_EXPLANATION_FAILED", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"explanation": explanation,
		"model":       explanation.Model,
		"provider":    explanation.Provider,
	})
}

type policyAdvisorRequest struct {
	Environment string `json:"environment"`
}

type policyEventCount struct {
	EventType string `json:"event_type"`
	Status    string `json:"status"`
	RiskScore string `json:"risk_score"`
	Count     int64  `json:"count"`
}

type policyAdvisorContext struct {
	Application struct {
		EnabledMethods       []string `json:"enabled_methods"`
		OrganizationsEnabled bool     `json:"organizations_enabled"`
		PasswordEnabled      bool     `json:"password_enabled"`
		TOTPAvailable        bool     `json:"totp_available"`
	} `json:"configuration"`
	EventCounts []policyEventCount `json:"event_counts"`
}

func RecommendAuthPolicy(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "Authentication required"})
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
	var input policyAdvisorRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Invalid policy review options"})
			return
		}
	}
	if input.Environment == "" {
		input.Environment = "all"
	}
	if input.Environment != "all" && input.Environment != "development" && input.Environment != "production" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ENVIRONMENT", "message": "Environment must be development, production, or all"})
		return
	}
	context := policyAdvisorContext{}
	context.Application.OrganizationsEnabled = app.OrgEnabled
	context.Application.TOTPAvailable = len([]byte(os.Getenv("BRICK_MFA_ENCRYPTION_KEY"))) >= 32
	context.Application.PasswordEnabled = appSettingEnabled(&app, "passwordEnabled", true)
	for _, provider := range []string{"email", "google", "github", "apple", "wallet"} {
		if appProviderEnabled(&app, provider) {
			context.Application.EnabledMethods = append(context.Application.EnabledMethods, provider)
		}
	}
	type aggregateRow struct {
		EventType string
		Status    string
		RiskScore string
		Count     int64
	}
	var aggregates []aggregateRow
	query := db.DB.Model(&models.AuditLog{}).Select("event_type, status, risk_score, COUNT(*) AS count").Where("app_id = ? AND created_at >= ?", app.ID, time.Now().UTC().Add(-30*24*time.Hour))
	if input.Environment != "all" {
		query = query.Where("environment = ?", input.Environment)
	}
	if err := query.Group("event_type, status, risk_score").Order("count desc").Limit(100).Scan(&aggregates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Could not load aggregate security events"})
		return
	}
	context.EventCounts = make([]policyEventCount, 0, len(aggregates))
	for _, item := range aggregates {
		context.EventCounts = append(context.EventCounts, policyEventCount{EventType: item.EventType, Status: item.Status, RiskScore: item.RiskScore, Count: item.Count})
	}
	contextBytes, err := json.Marshal(context)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MARSHAL_ERROR", "message": "Could not prepare policy review context"})
		return
	}
	recommendation, err := getMetaAIService().RecommendAuthPolicy(c.Request.Context(), app.ID, string(contextBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI_POLICY_REVIEW_FAILED", "message": "Could not generate a policy recommendation"})
		return
	}
	services.RecordEvent(c, app.ID, app.OwnerID, "Brick AI Policy Advisor", "AI_AUTH_POLICY_REVIEWED", "Generated an advisory authentication-policy review", "confirmed", recommendation.RiskLevel)
	c.JSON(http.StatusOK, gin.H{"success": true, "recommendation": recommendation, "events_aggregated": len(context.EventCounts)})
}
