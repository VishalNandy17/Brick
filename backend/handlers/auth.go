package handlers

import (
	"brick/db"
	"brick/ledger"
	"brick/models"
	"brick/services"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

/* ─── Request / Response Payloads ─── */

type RequestOTPInput struct {
	Email string `json:"email" binding:"required,email"`
	Name  string `json:"name"`
	OrgID string `json:"orgId"`
}

type VerifyOTPInput struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required,len=6"`
}

type AuthResponse struct {
	Token    string      `json:"token"`
	User     models.User `json:"user"`
	Identity interface{} `json:"identity,omitempty"` // Fabric identity payload
}

/* ─── POST /api/v1/auth/request-otp ─── */

func RequestOTP(c *gin.Context) {
	var input RequestOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	// ① Validate email: format + disposable-domain check
	valid, reason := services.ValidateEmail(input.Email)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_EMAIL", "message": reason})
		return
	}

	// ①.5 Prevent duplicate signup if Name is provided (signup flow)
	if input.Name != "" {
		var existingUser models.User
		if err := db.DB.Where("email = ?", input.Email).First(&existingUser).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "ACCOUNT_EXISTS", "message": "An account with this email already exists. Please sign in."})
			return
		}
	}

	// ② Generate 6-digit OTP
	otp, err := services.GenerateOTP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OTP_GENERATION_FAILED", "message": "Could not generate verification code"})
		return
	}

	// ③ Invalidate any previous unused OTPs for this email
	db.DB.Where("email = ? AND used = false", input.Email).
		Updates(map[string]interface{}{"used": true})

	// ④ Store new OTP in DB (expires in 10 minutes)
	record := models.OTPRecord{
		Email:     input.Email,
		Code:      otp,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		Used:      false,
	}
	if err := db.DB.Create(&record).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to save OTP"})
		return
	}

	// ⑤ Send OTP via Twilio SendGrid
	if err := services.SendOTPEmail(input.Email, otp); err != nil {
		log.Printf("Email send error for %s: %v", input.Email, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "EMAIL_SEND_FAILED", "message": "Could not send verification email. Try again."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Verification code sent to %s. Valid for 10 minutes.", maskEmail(input.Email)),
	})
}

/* ─── POST /api/v1/auth/verify-otp ─── */

func VerifyOTP(c *gin.Context) {
	var input VerifyOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	// ① Look up latest valid OTP record
	var record models.OTPRecord
	result := db.DB.Where(
		"email = ? AND used = false AND expires_at > ?",
		input.Email, time.Now().UTC(),
	).Order("created_at desc").First(&record)

	if result.Error == gorm.ErrRecordNotFound {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP_NOT_FOUND", "message": "No valid OTP found. Please request a new code."})
		return
	}
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Database error during OTP lookup"})
		return
	}

	// ② Validate code match
	if record.Code != strings.TrimSpace(input.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP_INVALID", "message": "Incorrect verification code."})
		return
	}

	// ③ Mark OTP as used (single-use)
	db.DB.Model(&record).Update("used", true)

	// ④ Upsert user in Postgres DB
	user := models.User{
		ID:    hashUserID(input.Email),
		Email: input.Email,
		Role:  "user",
	}
	dbResult := db.DB.Where(models.User{Email: input.Email}).FirstOrCreate(&user)
	if dbResult.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "USER_CREATE_FAILED", "message": "Could not create user record"})
		return
	}

	// ⑤ Register/fetch identity on Hyperledger Fabric Ledger
	var fabricIdentity interface{}
	svc := ledger.Get()
	if svc != nil {
		orgID := c.GetHeader("X-Org-ID")
		if orgID == "" {
			orgID = "Org1"
		}
		identity, err := svc.RegisterIdentity(ledger.RegistrationRequest{
			UserID: user.ID,
			OrgID:  orgID,
			Role:   user.Role,
			Attributes: map[string]string{
				"email": user.Email,
			},
			Caller: ledger.CallerContext{
				UserIdentity: user.ID,
				OrgID:        orgID,
				MSPID:        orgID + "MSP",
				IsAdmin:      false,
			},
		})
		if err != nil {
			log.Printf("Fabric enroll warning for %s: %v", user.Email, err)
			// Non-fatal — user is still authenticated via DB
		} else {
			fabricIdentity = identity
		}
	}

	// ⑥ Issue short-lived Access Token (15 min)
	orgID := c.GetHeader("X-Org-ID")
	if orgID == "" {
		orgID = "Org1"
	}
	accessToken, err := services.GenerateAccessToken(user, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_GENERATION_FAILED", "message": "Could not generate access token"})
		return
	}

	// ⑦ Issue long-lived Refresh Token (7 days) — stored hashed in DB
	rawRefresh, refreshRecord, err := services.GenerateRefreshToken(user.ID, orgID)
	if err != nil {
		log.Printf("Refresh token generation warning for %s: %v", user.Email, err)
		// Non-fatal — user still gets access token
	} else {
		if dbErr := db.DB.Create(&refreshRecord).Error; dbErr != nil {
			log.Printf("Refresh token DB save warning: %v", dbErr)
		} else {
			// Set as HttpOnly cookie — JS cannot access this
			c.SetCookie(
				"brick_refresh_token",
				rawRefresh,
				7*24*60*60, // 7 days in seconds
				"/",
				"",
				false, // secure=false for localhost dev; set true in prod
				true,  // httpOnly=true
			)
		}
	}

	c.JSON(http.StatusOK, AuthResponse{
		Token:    accessToken,
		User:     user,
		Identity: fabricIdentity,
	})
}

/* ─── Helpers ─── */

// generateJWT is kept for backward compatibility with any internal callers.
// New code should use services.GenerateAccessToken instead.
func generateJWT(user models.User) (string, error) {
	return services.GenerateAccessToken(user, "Org1")
}

func hashUserID(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(email)))
	return fmt.Sprintf("usr_%x", h[:8])
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) < 2 {
		return email
	}
	masked := string(parts[0][0]) + strings.Repeat("*", len(parts[0])-1)
	return masked + "@" + parts[1]
}
