package middleware

import "github.com/gin-gonic/gin"

// SecurityHeadersMiddleware adds comprehensive defense-in-depth HTTP security headers.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME-sniffing
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		c.Writer.Header().Set("X-Frame-Options", "DENY")

		// Control referrer exposure
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// XSS filter protection
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")

		// Disable browser access to sensitive hardware features
		c.Writer.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")

		// Content Security Policy for API server
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Enforce HTTPS with HTTP Strict Transport Security (HSTS)
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		c.Next()
	}
}
