package services

import (
	"brick/models"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// BrickTokenClaims holds the structured JWT payload for BRICK access tokens.
// These are injected into Gin context by BrickAuthMiddleware.
type BrickTokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	OrgID  string `json:"org_id"`
	jwt.RegisteredClaims
}

// GenerateAccessToken mints a short-lived (15 min) signed JWT for a user.
func GenerateAccessToken(user models.User, orgID string) (string, error) {
	if orgID == "" {
		orgID = "Org1"
	}
	claims := BrickTokenClaims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		OrgID:  orgID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(15 * time.Minute)),
			Issuer:    "brick-auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret()))
}

// GenerateRefreshToken creates a cryptographically secure 32-byte opaque token.
// Returns: rawToken (sent to client as HttpOnly cookie), DB record (with hashed token).
func GenerateRefreshToken(userID, orgID string) (rawToken string, record models.RefreshToken, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", models.RefreshToken{}, fmt.Errorf("failed to generate random token: %w", err)
	}
	rawToken = hex.EncodeToString(b)

	record = models.RefreshToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		OrgID:     orgID,
		TokenHash: HashToken(rawToken),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		Revoked:   false,
	}
	return rawToken, record, nil
}

// ParseAccessToken validates the JWT signature and returns the typed claims.
// Returns an error if the token is expired, tampered, or malformed.
func ParseAccessToken(tokenStr string) (*BrickTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &BrickTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(jwtSecret()), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*BrickTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// HashToken returns the SHA-256 hex digest of a raw token string.
// Used for safe DB storage — the raw token is never persisted.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func jwtSecret() string {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return s
	}
	return "brick-dev-secret-change-in-prod"
}
