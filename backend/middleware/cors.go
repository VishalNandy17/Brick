package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// defaultAllowedOrigins lists verified production and development origins.
var defaultAllowedOrigins = []string{
	"https://trybrick.dev",
	"https://www.trybrick.dev",
	"https://trybrick-chi.vercel.app",
	"http://localhost:5173",
	"http://localhost:3000",
	"http://localhost:8080",
}

func isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	// 1. Check verified default origins
	for _, o := range defaultAllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}

	// 2. Check custom allowed origins from environment variable
	if custom := os.Getenv("ALLOWED_ORIGINS"); custom != "" {
		for _, o := range strings.Split(custom, ",") {
			if strings.EqualFold(strings.TrimSpace(o), origin) {
				return true
			}
		}
	}

	// 3. Allow Vercel preview deployments for the project
	if strings.HasPrefix(origin, "https://") && strings.HasSuffix(origin, ".vercel.app") {
		lower := strings.ToLower(origin)
		if strings.Contains(lower, "brick") || strings.Contains(lower, "trybrick") {
			return true
		}
	}

	return false
}

// CORSMiddleware restricts cross-origin access strictly to authorized frontend origins.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if origin != "" && isOriginAllowed(origin) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-User-Identity, X-Org-ID, X-Brick-Admin, X-Brick-Attributes")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
			c.Writer.Header().Set("Access-Control-Max-Age", "86400") // 24 hours preflight cache
		}

		if c.Request.Method == "OPTIONS" {
			if origin != "" && isOriginAllowed(origin) {
				c.AbortWithStatus(http.StatusNoContent)
			} else {
				// Reject unauthorized preflight origins
				c.AbortWithStatus(http.StatusForbidden)
			}
			return
		}

		c.Next()
	}
}
