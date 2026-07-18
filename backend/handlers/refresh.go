package handlers

import (
	"brick/db"
	"brick/models"
	"brick/services"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

/* ─── POST /api/v1/auth/refresh ─── */

// RefreshTokenHandler silently renews an access token using the HttpOnly
// refresh token cookie set during VerifyOTP. No credentials required.
func RefreshTokenHandler(c *gin.Context) {
	rawToken, err := c.Cookie("brick_refresh_token")
	if err != nil || rawToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "NO_REFRESH_TOKEN",
			"message": "No refresh token cookie found. Please sign in again.",
		})
		return
	}

	// Lookup hashed token in DB — must be non-revoked and non-expired
	tokenHash := services.HashToken(rawToken)
	var record models.RefreshToken
	result := db.DB.Where(
		"token_hash = ? AND revoked = false AND expires_at > ?",
		tokenHash, time.Now().UTC(),
	).First(&record)
	if result.Error != nil {
		// Clear stale cookie
		c.SetCookie("brick_refresh_token", "", -1, "/", "", false, true)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "REFRESH_TOKEN_INVALID",
			"message": "Refresh token is invalid, expired, or revoked. Please sign in again.",
		})
		return
	}

	// Ensure the linked user is still active
	var user models.User
	if err := db.DB.First(&user, "id = ?", record.UserID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "USER_NOT_FOUND",
			"message": "Associated user no longer exists.",
		})
		return
	}
	if !user.Active {
		c.SetCookie("brick_refresh_token", "", -1, "/", "", false, true)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "IDENTITY_REVOKED",
			"message": "This account has been deactivated.",
		})
		return
	}

	// Issue new access token (refresh token itself is NOT rotated — stateless refresh)
	newAccessToken, err := services.GenerateAccessToken(user, record.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "TOKEN_GENERATION_FAILED",
			"message": "Could not generate new access token.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": newAccessToken,
		"user":  user,
	})
}
