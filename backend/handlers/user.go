package handlers

import (
	"brick/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// GetUsers retrieves all users
func GetUsers(c *gin.Context) {
	// TODO: Implement database query
	users := []models.User{
		{
			ID:        "user_1",
			Email:     "admin@brick.io",
			Name:      "Admin User",
			Role:      "admin",
			Active:    true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    users,
		"count":   len(users),
	})
}

// CreateUser creates a new user
func CreateUser(c *gin.Context) {
	var req models.UserRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// TODO: Implement user creation in database
	user := models.User{
		ID:        "user_" + time.Now().Format("20060102150405"),
		Email:     req.Email,
		Name:      req.Name,
		Role:      req.Role,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    user,
		"message": "User created successfully",
	})
}

// GetUserByID retrieves a user by ID
func GetUserByID(c *gin.Context) {
	id := c.Param("id")

	// TODO: Implement database query
	user := models.User{
		ID:        id,
		Email:     "user@brick.io",
		Name:      "Brick User",
		Role:      "user",
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    user,
	})
}

// UpdateUser updates a user
func UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var req models.UserRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// TODO: Implement user update in database
	user := models.User{
		ID:        id,
		Email:     req.Email,
		Name:      req.Name,
		Role:      req.Role,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    user,
		"message": "User updated successfully",
	})
}

// DeleteUser deletes a user
func DeleteUser(c *gin.Context) {
	id := c.Param("id")

	// TODO: Implement user deletion
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User deleted successfully",
		"id":      id,
	})
}
