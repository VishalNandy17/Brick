package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// clientBucket tracks request counts for a single IP address.
type clientBucket struct {
	tokens     int
	lastRefill time.Time
}

// MemoryRateLimiter implements a high-performance in-memory token bucket rate limiter.
type MemoryRateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*clientBucket
	limit       int           // Maximum burst tokens
	refillRate  time.Duration // Time interval to add 1 token
	maxWindow   time.Duration // Eviction timeout for stale IPs
	lastCleaned time.Time
}

// NewMemoryRateLimiter creates a new thread-safe rate limiter.
func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
	limiter := &MemoryRateLimiter{
		buckets:     make(map[string]*clientBucket),
		limit:       limit,
		refillRate:  window / time.Duration(limit),
		maxWindow:   window * 2,
		lastCleaned: time.Now(),
	}

	// Background goroutine to evict dead IP entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			limiter.cleanupStale()
		}
	}()

	return limiter
}

func (l *MemoryRateLimiter) cleanupStale() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, b := range l.buckets {
		if now.Sub(b.lastRefill) > l.maxWindow {
			delete(l.buckets, ip)
		}
	}
	l.lastCleaned = now
}

// Allow checks if the given IP is within rate limits.
func (l *MemoryRateLimiter) Allow(ip string) (bool, int, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[ip]
	if !exists {
		l.buckets[ip] = &clientBucket{
			tokens:     l.limit - 1,
			lastRefill: now,
		}
		return true, l.limit - 1, 0
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastRefill)
	refillTokens := int(elapsed / l.refillRate)
	if refillTokens > 0 {
		b.tokens += refillTokens
		if b.tokens > l.limit {
			b.tokens = l.limit
		}
		b.lastRefill = now
	}

	if b.tokens > 0 {
		b.tokens--
		return true, b.tokens, 0
	}

	retryAfter := l.refillRate - (now.Sub(b.lastRefill))
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return false, 0, retryAfter
}

func extractClientIP(c *gin.Context) string {
	// Check standard proxy headers
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xrip := c.GetHeader("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	return c.ClientIP()
}

// GlobalRateLimitMiddleware protects the entire server against volumetric flood / DDoS attacks.
// Default: 120 requests per minute per IP.
func GlobalRateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	limiter := NewMemoryRateLimiter(limit, window)

	return func(c *gin.Context) {
		ip := extractClientIP(c)
		allowed, remaining, retryAfter := limiter.Allow(ip)

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", seconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "RATE_LIMIT_EXCEEDED",
				"message":     "Too many requests. Please slow down and try again later.",
				"retry_after": seconds,
			})
			return
		}

		c.Next()
	}
}

// StrictAuthRateLimitMiddleware enforces tight rate limits on sensitive auth endpoints
// (OTP requests, login, password resets) to prevent credential stuffing and brute force.
// Default: 10 requests per minute per IP.
func StrictAuthRateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	limiter := NewMemoryRateLimiter(limit, window)

	return func(c *gin.Context) {
		ip := extractClientIP(c)
		allowed, remaining, retryAfter := limiter.Allow(ip)

		c.Header("X-RateLimit-Auth-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Auth-Remaining", fmt.Sprintf("%d", remaining))

		if !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", seconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "AUTH_RATE_LIMIT_EXCEEDED",
				"message":     "Too many authentication attempts. Please wait before retrying.",
				"retry_after": seconds,
			})
			return
		}

		c.Next()
	}
}

// MaxBodySizeMiddleware stops memory exhaustion DDoS attacks by limiting maximum request payload.
func MaxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
