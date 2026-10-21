package handlers

import (
	"brick/db"
	"brick/ledger"
	"brick/models"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetMe retrieves the currently authenticated user's profile along with their blockchain ledger state.
func GetMe(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": "No authenticated session"})
		return
	}

	var user models.User
	if err := db.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "USER_NOT_FOUND", "message": "User record not found"})
		return
	}

	orgID, _ := c.Get("org_id")
	orgStr := fmt.Sprintf("%v", orgID)
	if orgStr == "" || orgStr == "<nil>" {
		orgStr = "Org1"
	}

	var fabricIdentity interface{}
	svc := ledger.Get()
	if svc != nil {
		adminCaller := ledger.CallerContext{
			UserIdentity: user.ID,
			OrgID:        orgStr,
			MSPID:        orgStr,
			IsAdmin:      true,
		}
		if id, err := svc.GetIdentity(orgStr, user.ID, adminCaller); err == nil {
			fabricIdentity = id
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"user":     user,
		"identity": fabricIdentity,
	})
}

// GetUsers retrieves all users from the database.
func GetUsers(c *gin.Context) {
	var users []models.User
	if err := db.DB.Order("created_at desc").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "DB_ERROR",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    users,
		"count":   len(users),
	})
}

// CreateUser creates a new user record in the database.
func CreateUser(c *gin.Context) {
	var req models.UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": err.Error(),
		})
		return
	}

	var existing models.User
	if err := db.DB.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":   "ACCOUNT_EXISTS",
			"message": "User with this email already exists",
		})
		return
	}

	user := models.User{
		ID:     hashUserID(req.Email),
		Email:  req.Email,
		Name:   req.Name,
		Role:   req.Role,
		Active: true,
	}

	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "DB_ERROR",
			"message": err.Error(),
		})
		return
	}

	// Also record on ledger if initialized
	svc := ledger.Get()
	if svc != nil {
		_, _ = svc.RegisterIdentity(ledger.RegistrationRequest{
			UserID: user.ID,
			OrgID:  "Org1",
			Role:   user.Role,
			Attributes: map[string]string{
				"email": user.Email,
			},
			Caller: ledger.CallerContext{
				UserIdentity: user.ID,
				OrgID:        "Org1",
				MSPID:        "Org1",
				IsAdmin:      true,
			},
		})
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    user,
		"message": "User created successfully",
	})
}

// GetUserByID retrieves a user by ID from the database.
func GetUserByID(c *gin.Context) {
	id := c.Param("id")

	var user models.User
	if err := db.DB.First(&user, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "USER_NOT_FOUND",
			"message": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    user,
	})
}

// UpdateUser updates a user's details.
func UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var req models.UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": err.Error(),
		})
		return
	}

	var user models.User
	if err := db.DB.First(&user, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "USER_NOT_FOUND",
			"message": "User not found",
		})
		return
	}

	user.Name = req.Name
	user.Role = req.Role
	if err := db.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "DB_ERROR",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    user,
		"message": "User updated successfully",
	})
}

// DeleteUser deactivates/soft-deletes a user and updates status on ledger.
func DeleteUser(c *gin.Context) {
	id := c.Param("id")

	var user models.User
	if err := db.DB.First(&user, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "USER_NOT_FOUND",
			"message": "User not found",
		})
		return
	}

	user.Active = false
	db.DB.Save(&user)
	db.DB.Delete(&user)

	// Revoke on ledger
	svc := ledger.Get()
	if svc != nil {
		_, _ = svc.UpdateIdentityStatus("Org1", id, "revoked", ledger.CallerContext{
			UserIdentity: "system_admin",
			OrgID:        "Org1",
			MSPID:        "Org1",
			IsAdmin:      true,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User deleted successfully",
		"id":      id,
	})
}
