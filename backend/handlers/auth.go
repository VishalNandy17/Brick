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
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

/* ─── Request / Response Payloads ─── */

type RequestOTPInput struct {
	Email string `json:"email" binding:"required,email"`
	Name  string `json:"name"`
	OrgID string `json:"orgId"`
}

// VerifyOTPInput now includes an optional password for signup.
type VerifyOTPInput struct {
	Email    string `json:"email" binding:"required,email"`
	Code     string `json:"code" binding:"required,len=6"`
	Password string `json:"password"` // required on signup, empty on login OTP (legacy)
	Name     string `json:"name"`     // carried through from signup step 1
}

// LoginInput is the payload for password-based sign-in.
type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
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

/* ─── POST /api/v1/auth/verify-otp  (signup completion only) ─── */

func VerifyOTP(c *gin.Context) {
	var input VerifyOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	// Look up if user already exists
	var existingUser models.User
	userExists := db.DB.Where("email = ?", input.Email).First(&existingUser).Error == nil

	// If new signup, password is required
	if !userExists {
		if strings.TrimSpace(input.Password) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "PASSWORD_REQUIRED", "message": "Password is required to complete sign-up."})
			return
		}
		if len(input.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "PASSWORD_TOO_SHORT", "message": "Password must be at least 8 characters."})
			return
		}
	}

	// ② Look up latest valid OTP record
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

	// ③ Validate code match
	if record.Code != strings.TrimSpace(input.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP_INVALID", "message": "Incorrect verification code."})
		return
	}

	// ④ Mark OTP as used (single-use)
	db.DB.Model(&record).Update("used", true)

	var user models.User
	if userExists {
		user = existingUser
		if input.Password != "" {
			hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
			if err == nil {
				db.DB.Model(&user).Update("password_hash", string(hashed))
			}
		}
		if input.Name != "" && user.Name == "" {
			db.DB.Model(&user).Update("name", input.Name)
			user.Name = input.Name
		}
	} else {
		// ⑤ Hash password with bcrypt
		hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSWORD_HASH_FAILED", "message": "Could not secure password"})
			return
		}

		// ⑥ Create user (email is now verified; password is set)
		user = models.User{
			ID:           hashUserID(input.Email),
			Email:        input.Email,
			Name:         input.Name,
			Role:         "user",
			Active:       true,
			PasswordHash: string(hashed),
		}
		if err := db.DB.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "USER_CREATE_FAILED", "message": "Could not create user record"})
			return
		}
	}

	issueTokensAndRespond(c, user)
}

/* ─── POST /api/v1/auth/login  (password-based sign-in) ─── */

func LoginWithPassword(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	// ① Look up user by email
	var user models.User
	if err := db.DB.Where("email = ?", input.Email).First(&user).Error; err != nil {
		// Generic message — don't reveal whether the email exists
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS", "message": "Invalid email or password."})
		return
	}

	// ② Check account is active
	if !user.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "ACCOUNT_INACTIVE", "message": "Your account has been deactivated."})
		return
	}

	// ③ Verify password
	if user.PasswordHash == "" {
		// Legacy account with no password — prompt them to reset via email OTP
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "NO_PASSWORD_SET",
			"message": "This account was created before passwords were introduced. Please sign up again or contact support.",
		})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS", "message": "Invalid email or password."})
		return
	}

	issueTokensAndRespond(c, user)
}

/* ─── Shared: issue JWT + refresh cookie then respond ─── */

func issueTokensAndRespond(c *gin.Context, user models.User) {
	// ① Register/fetch identity on Hyperledger Fabric Ledger
	var fabricIdentity interface{}
	svc := ledger.Get()
	if svc != nil {
		orgID := c.GetHeader("X-Org-ID")
		if orgID == "" {
			orgID = "Org1"
		}

		adminCaller := ledger.CallerContext{
			UserIdentity: user.ID,
			OrgID:        orgID,
			MSPID:        orgID,
			IsAdmin:      true,
		}

		// Check if already registered on blockchain ledger
		identity, err := svc.GetIdentity(orgID, user.ID, adminCaller)
		if err != nil {
			// Not yet registered — enroll identity on ledger
			identity, err = svc.RegisterIdentity(ledger.RegistrationRequest{
				UserID: user.ID,
				OrgID:  orgID,
				Role:   user.Role,
				Attributes: map[string]string{
					"email": user.Email,
				},
				Caller: adminCaller,
			})
		}

		if err != nil {
			log.Printf("Fabric enroll warning for %s: %v", user.Email, err)
			// Non-fatal — user is still authenticated
		} else {
			fabricIdentity = identity
		}
	}

	// ② Issue short-lived Access Token (15 min)
	orgID := c.GetHeader("X-Org-ID")
	if orgID == "" {
		orgID = "Org1"
	}
	accessToken, err := services.GenerateAccessToken(user, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_GENERATION_FAILED", "message": "Could not generate access token"})
		return
	}

	// ③ Issue long-lived Refresh Token (7 days) — stored hashed in DB
	rawRefresh, refreshRecord, err := services.GenerateRefreshToken(user.ID, orgID)
	if err != nil {
		log.Printf("Refresh token generation warning for %s: %v", user.Email, err)
	} else {
		if dbErr := db.DB.Create(&refreshRecord).Error; dbErr != nil {
			log.Printf("Refresh token DB save warning: %v", dbErr)
		} else {
			c.SetCookie(
				"brick_refresh_token",
				rawRefresh,
				7*24*60*60, // 7 days in seconds
				"/",
				"",
				false, // secure=false for localhost dev
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
