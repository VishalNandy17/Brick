package services

import (
	"brick/db"
	"brick/models"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// auditQueue is a buffered channel for asynchronous, non-blocking audit logging.
var auditQueue = make(chan models.AuditLog, 2000)

func init() {
	// Start background worker to process audit events without slowing down HTTP request cycles
	go func() {
		for event := range auditQueue {
			if db.DB != nil {
				if err := db.DB.Create(&event).Error; err != nil {
					log.Printf("⚠️ AuditLog write error: %v", err)
				}
			}
		}
	}()
}

// LogEvent queues an audit event asynchronously. Non-blocking and ultra-fast.
func LogEvent(event models.AuditLog) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Status == "" {
		event.Status = "confirmed"
	}
	if event.RiskScore == "" {
		event.RiskScore = "LOW"
	}

	select {
	case auditQueue <- event:
	default:
		// Channel buffer full — write in separate goroutine to avoid dropping critical audit data
		go func(e models.AuditLog) {
			if db.DB != nil {
				_ = db.DB.Create(&e)
			}
		}(event)
	}
}

// RecordEvent is a convenience helper that extracts context (IP, User-Agent, Env) from gin.Context.
func RecordEvent(
	c *gin.Context,
	appID string,
	userID string,
	actor string,
	eventType string,
	details string,
	status string,
	riskScore ...string,
) {
	ip := "unknown"
	ua := "unknown"
	env := "development"

	if os.Getenv("GIN_MODE") == "release" || os.Getenv("IS_PRODUCTION") == "true" {
		env = "production"
	}

	if c != nil {
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				ip = strings.TrimSpace(parts[0])
			}
		} else if xrip := c.GetHeader("X-Real-IP"); xrip != "" {
			ip = strings.TrimSpace(xrip)
		} else {
			ip = c.ClientIP()
		}

		if clientUA := c.GetHeader("User-Agent"); clientUA != "" {
			ua = clientUA
		}

		if reqEnv := c.Query("environment"); reqEnv != "" {
			env = reqEnv
		}
	}

	risk := "LOW"
	if len(riskScore) > 0 && riskScore[0] != "" {
		risk = strings.ToUpper(riskScore[0])
	} else if status == "failed" || status == "warning" || strings.Contains(eventType, "FAILED") {
		risk = "MEDIUM"
	} else if status == "quarantined" || strings.Contains(eventType, "ATTACK") {
		risk = "HIGH"
	}

	if actor == "" {
		actor = "Anonymous"
	}

	LogEvent(models.AuditLog{
		AppID:       appID,
		UserID:      userID,
		Actor:       actor,
		EventType:   eventType,
		Details:     details,
		Status:      status,
		IPAddress:   ip,
		UserAgent:   ua,
		Environment: env,
		RiskScore:   risk,
	})
}
