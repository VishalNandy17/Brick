package main

import (
	"brick/ledger"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// IdentityRegistrationPayload represents enrollment request
type IdentityRegistrationPayload struct {
	UserID     string            `json:"userId" binding:"required"`
	OrgID      string            `json:"orgId" binding:"required"`
	Role       string            `json:"role" binding:"required"`
	Attributes map[string]string `json:"attributes"`
}

// IdentityResponse represents identity data returned to client
type IdentityResponse struct {
	UserID       string            `json:"userId"`
	OrgID        string            `json:"orgId"`
	Role         string            `json:"role"`
	Status       string            `json:"status"`
	IdentityHash string            `json:"identityHash"`
	MSPID        string            `json:"mspId"`
	Attributes   map[string]string `json:"attributes"`
	CreatedAt    string            `json:"createdAt"`
	UpdatedAt    string            `json:"updatedAt"`
}

// ErrorResponse standardized error format
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func toIdentityResponse(id *ledger.Identity) IdentityResponse {
	return IdentityResponse{
		UserID:       id.UserID,
		OrgID:        id.OrgID,
		Role:         id.Role,
		Status:       id.Status,
		IdentityHash: id.IdentityHash,
		MSPID:        id.MSPID,
		Attributes:   id.Attributes,
		CreatedAt:    id.CreatedAt,
		UpdatedAt:    id.UpdatedAt,
	}
}

func parseCaller(c *gin.Context) ledger.CallerContext {
	orgID := c.GetHeader("X-Org-ID")
	isAdmin := strings.EqualFold(c.GetHeader("X-Brick-Admin"), "true")
	attrs := c.GetHeader("X-Brick-Attributes")
	if attrs != "" {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(attrs), &parsed); err == nil {
			if val, ok := parsed["brick-admin"]; ok && val == "true" {
				isAdmin = true
			}
		}
	}
	return ledger.CallerContext{
		UserIdentity: c.GetHeader("X-User-Identity"),
		OrgID:        orgID,
		MSPID:        orgID,
		IsAdmin:      isAdmin,
	}
}

// EnrollIdentity handles POST /api/v1/brick/enroll
func EnrollIdentity(c *gin.Context) {
	var payload IdentityRegistrationPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "INVALID_REQUEST",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	validation := ValidateIdentityRequest(payload)
	if !validation.Valid {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   validation.Errors[0].Code,
			Message: validation.Errors[0].Message,
			Code:    http.StatusBadRequest,
		})
		return
	}

	caller := parseCaller(c)
	if caller.UserIdentity == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "UNAUTHORIZED",
			Message: "X-User-Identity header required",
			Code:    http.StatusUnauthorized,
		})
		return
	}

	svc := ledger.Get()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "GATEWAY_ERROR",
			Message: "Ledger service not initialized",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	identity, err := svc.RegisterIdentity(ledger.RegistrationRequest{
		UserID:     payload.UserID,
		OrgID:      payload.OrgID,
		Role:       payload.Role,
		Attributes: payload.Attributes,
		Caller:     caller,
	})
	if err != nil {
		log.Printf("Enrollment error: %v", err)
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "ENROLLMENT_FAILED",
			Message: fmt.Sprintf("Failed to register identity: %v", err),
			Code:    http.StatusForbidden,
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success":  true,
		"identity": toIdentityResponse(identity),
		"message":  "Identity registered successfully",
		"ledger":   svc.Mode(),
	})
}

// GetSession handles GET /api/v1/brick/session/:userId
func GetSession(c *gin.Context) {
	userID := c.Param("userId")
	orgID := c.GetHeader("X-Org-ID")

	if userID == "" || orgID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "INVALID_REQUEST",
			Message: "userId path param and X-Org-ID header required",
			Code:    http.StatusBadRequest,
		})
		return
	}

	callerID := c.GetHeader("X-User-Identity")
	if callerID != userID {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "FORBIDDEN",
			Message: "Cannot access other user's session",
			Code:    http.StatusForbidden,
		})
		return
	}

	svc := ledger.Get()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "GATEWAY_ERROR",
			Message: "Ledger service not initialized",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	caller := parseCaller(c)
	identity, err := svc.GetIdentity(orgID, userID, caller)
	if err != nil {
		log.Printf("Session error: %v", err)
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "SESSION_NOT_FOUND",
			Message: fmt.Sprintf("Failed to retrieve session: %v", err),
			Code:    http.StatusNotFound,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"identity": toIdentityResponse(identity),
		"message":  "Session retrieved successfully",
		"ledger":   svc.Mode(),
	})
}

// ListIdentities handles GET /api/v1/brick/identities
func ListIdentities(c *gin.Context) {
	orgID := c.GetHeader("X-Org-ID")
	if orgID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "INVALID_REQUEST",
			Message: "X-Org-ID header required",
			Code:    http.StatusBadRequest,
		})
		return
	}

	svc := ledger.Get()
	identities, err := svc.QueryIdentitiesByOrg(orgID, parseCaller(c))
	if err != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "QUERY_FAILED",
			Message: err.Error(),
			Code:    http.StatusForbidden,
		})
		return
	}

	results := make([]IdentityResponse, 0, len(identities))
	for _, id := range identities {
		results = append(results, toIdentityResponse(id))
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"identities": results,
		"count":      len(results),
		"ledger":     svc.Mode(),
	})
}

// Health returns API health status
func Health(c *gin.Context) {
	svc := ledger.Get()
	ledgerHealthy := svc != nil && svc.Healthy()
	mode := "uninitialized"
	if svc != nil {
		mode = svc.Mode()
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "BRICK Identity Gateway",
		"version":   "1.0.0",
		"ledger":    ledgerHealthy,
		"ledgerMode": mode,
		"timestamp": time.Now().Unix(),
	})
}

