package middleware

import (
	"log"

	"github.com/gin-gonic/gin"
)

// LoggingMiddleware logs all HTTP requests
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("[%s] %s %s", c.Request.Method, c.Request.RequestURI, c.ClientIP())
		c.Next()
	}
}
