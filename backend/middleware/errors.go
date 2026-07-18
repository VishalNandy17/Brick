package middleware

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorRecoveryMiddleware catches panics and returns structured JSON errors.
func ErrorRecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic recovered: %v", r)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":   "INTERNAL_ERROR",
					"message": "An unexpected error occurred",
					"code":    http.StatusInternalServerError,
				})
			}
		}()
		c.Next()
	}
}
