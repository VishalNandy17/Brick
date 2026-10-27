package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"brick/db"
	"brick/ledger"
	"brick/models"
	"brick/services"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/* ─── Client DTOs ─── */

type ClientSignUpInput struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	Name          string `json:"name"`
	WalletAddress string `json:"wallet_address"`
}

type ClientSignInInput struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	WalletAddress string `json:"wallet_address"`
}

type ClientMFACodeInput struct {
	Code string `json:"code"`
}

type ClientMFAVerifyInput struct {
	MFAToken     string `json:"mfa_token" binding:"required"`
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
}

type ClientSIWEInput struct {
	WalletAddress string `json:"wallet_address" binding:"required"`
	Message       string `json:"message"`
	Signature     string `json:"signature"`
}

type ClientSIWENonceInput struct {
	WalletAddress string `json:"wallet_address" binding:"required"`
	ChainID       int64  `json:"chain_id" binding:"required,gt=0"`
}

type ClientVerifyTokenInput struct {
	Token string `json:"token" binding:"required"`
}

// isSafeWebhookURL validates that a webhook destination does not target loopback, private ranges, or cloud metadata
func isSafeWebhookURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "169.254.169.254" {
		return false
	}
	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return false
		}
	}
	return true
}

// verifyEthereumSignature verifies an EIP-191 personal_sign signature against a claimed Ethereum address
func verifyEthereumSignature(addressHex, message, signatureHex string) (bool, error) {
	cleanSig := strings.TrimPrefix(strings.TrimSpace(signatureHex), "0x")
	sigBytes, err := hex.DecodeString(cleanSig)
	if err != nil || len(sigBytes) != 65 {
		return false, fmt.Errorf("invalid signature length: expected 65 bytes")
	}

	// Normalize recovery byte (V)
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}
	if sigBytes[64] != 0 && sigBytes[64] != 1 {
		return false, fmt.Errorf("invalid recovery ID")
	}

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	msgHash := crypto.Keccak256([]byte(prefix))

	pubKey, err := crypto.SigToPub(msgHash, sigBytes)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %w", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	return strings.EqualFold(recoveredAddr.Hex(), addressHex), nil
}

/* ─── Helper: Get App from Publishable Key Header / Query ─── */

func getAppFromPublishableKey(c *gin.Context) (*models.Application, string, error) {
	pk := c.GetHeader("X-Brick-Publishable-Key")
	if pk == "" {
		pk = c.Query("publishable_key")
	}
	if pk == "" {
		return nil, "", fmt.Errorf("MISSING_PUBLISHABLE_KEY: Provide X-Brick-Publishable-Key header")
	}

	var app models.Application
	if err := db.DB.Where("publishable_key = ? OR live_publishable_key = ?", pk, pk).First(&app).Error; err != nil {
		return nil, "", fmt.Errorf("INVALID_PUBLISHABLE_KEY: No application matches key %s", pk)
	}

	env := "development"
	if pk == app.LivePublishableKey || strings.HasPrefix(pk, "pk_live_") {
		env = "production"
	}
	return &app, env, nil
}

/* ─── Helper: Get App from Secret Key Header ─── */

func getAppFromSecretKey(c *gin.Context) (*models.Application, string, error) {
	authHeader := c.GetHeader("Authorization")
	sk := strings.TrimPrefix(authHeader, "Bearer ")
	if sk == "" {
		sk = c.GetHeader("X-Brick-Secret-Key")
	}
	if sk == "" {
		return nil, "", fmt.Errorf("MISSING_SECRET_KEY: Provide Bearer <secret_key> in Authorization header")
	}

	var app models.Application
	if err := db.DB.Where("secret_key = ? OR live_secret_key = ?", sk, sk).First(&app).Error; err != nil {
		return nil, "", fmt.Errorf("INVALID_SECRET_KEY: Unauthorized application")
	}

	env := "development"
	if sk == app.LiveSecretKey || strings.HasPrefix(sk, "sk_live_") {
		env = "production"
	}
	return &app, env, nil
}

/* ─── Helper: Generate App User JWT ─── */

func generateAppUserJWT(user *models.AppUser, app *models.Application) (string, error) {
	key, signingKey, err := getAppTokenSigningKey(app.ID, user.Environment)
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"sub":            user.ID,
		"app_id":         app.ID,
		"email":          user.Email,
		"name":           user.Name,
		"role":           user.Role,
		"wallet_address": user.WalletAddress,
		"environment":    user.Environment,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(24 * time.Hour).Unix(),
		"iss":            "https://api.brick.id",
		"aud":            app.ID,
		"ledger_key":     user.LedgerAssetKey,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = signingKey.ID
	return token.SignedString(key)
}

func getAppTokenSigningKey(appID, environment string) (*rsa.PrivateKey, *models.TokenSigningKey, error) {
	if len([]byte(strings.TrimSpace(os.Getenv("JWT_SECRET")))) < 32 {
		return nil, nil, fmt.Errorf("JWT_SECRET must be configured with at least 32 bytes before issuing application JWTs")
	}
	var privateKey *rsa.PrivateKey
	var signingKey models.TokenSigningKey
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		var app models.Application
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", appID).First(&app).Error; err != nil {
			return err
		}
		lookupErr := tx.Where("app_id = ? AND environment = ? AND active = ?", appID, environment, true).Order("created_at desc").First(&signingKey).Error
		if lookupErr == nil {
			privatePEM, decryptErr := services.DecryptTokenPrivateKey(signingKey.EncryptedPrivateKey)
			if decryptErr != nil {
				return decryptErr
			}
			block, _ := pem.Decode(privatePEM)
			if block == nil {
				return fmt.Errorf("stored token signing key is invalid")
			}
			privateKey, decryptErr = x509.ParsePKCS1PrivateKey(block.Bytes)
			return decryptErr
		} else if !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
			return lookupErr
		}
		generatedKey, generateErr := rsa.GenerateKey(rand.Reader, 2048)
		if generateErr != nil {
			return generateErr
		}
		privateKey = generatedKey
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		encryptedPrivateKey, encryptErr := services.EncryptTokenPrivateKey(privatePEM)
		if encryptErr != nil {
			return encryptErr
		}
		publicDER, marshalErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if marshalErr != nil {
			return marshalErr
		}
		publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
		signingKey = models.TokenSigningKey{
			ID: uuid.NewString(), AppID: appID, Environment: environment,
			PublicKeyPEM: string(publicPEM), EncryptedPrivateKey: encryptedPrivateKey, Active: true,
		}
		return tx.Create(&signingKey).Error
	})
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &signingKey, nil
}

func rotateAppTokenSigningKey(appID, environment string) (*models.TokenSigningKey, error) {
	if len([]byte(strings.TrimSpace(os.Getenv("JWT_SECRET")))) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be configured with at least 32 bytes before rotating application JWT keys")
	}
	var signingKey models.TokenSigningKey
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		var app models.Application
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", appID).First(&app).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := tx.Model(&models.TokenSigningKey{}).Where("app_id = ? AND environment = ? AND active = ?", appID, environment, true).Updates(map[string]interface{}{"active": false, "retired_at": now}).Error; err != nil {
			return err
		}
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		encryptedPrivateKey, err := services.EncryptTokenPrivateKey(privatePEM)
		if err != nil {
			return err
		}
		publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return err
		}
		signingKey = models.TokenSigningKey{
			ID: uuid.NewString(), AppID: appID, Environment: environment,
			PublicKeyPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
			EncryptedPrivateKey: encryptedPrivateKey, Active: true,
		}
		return tx.Create(&signingKey).Error
	})
	if err != nil {
		return nil, err
	}
	return &signingKey, nil
}

func appSecretForEnvironment(app *models.Application, environment string) string {
	if environment == "production" && app.LiveSecretKey != "" {
		return app.LiveSecretKey
	}
	return app.SecretKey
}

func generateMFAChallengeToken(user *models.AppUser, app *models.Application) (string, error) {
	challengeID := uuid.NewString()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub": user.ID, "app_id": app.ID, "environment": user.Environment,
		"typ": "mfa_challenge", "jti": challengeID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"iss": "https://api.brick.id", "aud": app.ID,
	}
	privateKey, signingKey, err := getAppTokenSigningKey(app.ID, user.Environment)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = signingKey.ID
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	_ = db.DB.Where("expires_at < ?", now.Add(-time.Hour)).Delete(&models.MFAChallenge{}).Error
	challenge := models.MFAChallenge{ID: challengeID, AppID: app.ID, Environment: user.Environment, UserID: user.ID, ExpiresAt: now.Add(5 * time.Minute)}
	if err := db.DB.Create(&challenge).Error; err != nil {
		return "", err
	}
	return tokenString, nil
}

func parseClientToken(raw string, app *models.Application, environment string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
		if token.Method == jwt.SigningMethodRS256 {
			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, fmt.Errorf("token key identifier is missing")
			}
			var signingKey models.TokenSigningKey
			if err := db.DB.Where("id = ? AND app_id = ? AND environment = ?", kid, app.ID, environment).First(&signingKey).Error; err != nil {
				return nil, fmt.Errorf("token signing key was not found")
			}
			if !signingKey.Active && (signingKey.RetiredAt == nil || !signingKey.RetiredAt.Add(24*time.Hour).After(time.Now().UTC())) {
				return nil, fmt.Errorf("token signing key has expired")
			}
			block, _ := pem.Decode([]byte(signingKey.PublicKeyPEM))
			if block == nil {
				return nil, fmt.Errorf("stored token public key is invalid")
			}
			publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("stored token public key is not RSA")
			}
			return rsaPublicKey, nil
		}
		if token.Method == jwt.SigningMethodHS256 {
			return []byte(appSecretForEnvironment(app, environment)), nil
		}
		return nil, fmt.Errorf("unexpected signing method")
	})
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	issuer, _ := claims.GetIssuer()
	audience, _ := claims.GetAudience()
	validAudience := false
	for _, value := range audience {
		if value == app.ID {
			validAudience = true
			break
		}
	}
	if claims["app_id"] != app.ID || claims["environment"] != environment || issuer != "https://api.brick.id" || !validAudience {
		return nil, fmt.Errorf("token application or environment mismatch")
	}
	if _, ok := claims["sub"].(string); !ok {
		return nil, fmt.Errorf("token subject missing")
	}
	return claims, nil
}

func authenticatedClientUser(c *gin.Context) (*models.Application, *models.AppUser, string, error) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		return nil, nil, "", err
	}
	parts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, nil, "", fmt.Errorf("authentication token required")
	}
	claims, err := parseClientToken(parts[1], app, env)
	if err != nil || claims["typ"] == "mfa_challenge" {
		return nil, nil, "", fmt.Errorf("valid user access token required")
	}
	var user models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ? AND environment = ? AND active = ?", claims["sub"], app.ID, env, true).First(&user).Error; err != nil {
		return nil, nil, "", fmt.Errorf("active user not found")
	}
	if organizationID, ok := claims["org_id"].(string); ok && organizationID != "" {
		var membership models.OrganizationMembership
		if err := db.DB.Where("app_id = ? AND environment = ? AND organization_id = ? AND user_id = ?", app.ID, env, organizationID, user.ID).First(&membership).Error; err != nil {
			return nil, nil, "", fmt.Errorf("organization membership is no longer active")
		}
	}
	return app, &user, env, nil
}

func appProviderEnabled(app *models.Application, provider string) bool {
	var settings struct {
		SocialProviders []models.AuthOption `json:"socialProviders"`
	}
	if app.SettingsJSON != "" {
		if json.Unmarshal([]byte(app.SettingsJSON), &settings) != nil {
			return false
		}
		for _, option := range settings.SocialProviders {
			if option.Provider == provider {
				return option.Enabled
			}
		}
	}
	var options []models.AuthOption
	if json.Unmarshal([]byte(app.AuthOptions), &options) != nil {
		return false
	}
	for _, option := range options {
		if option.Provider == provider {
			return option.Enabled
		}
	}
	return false
}

func appSettingEnabled(app *models.Application, key string, defaultValue bool) bool {
	settings := make(map[string]interface{})
	if app.SettingsJSON == "" {
		return defaultValue
	}
	if json.Unmarshal([]byte(app.SettingsJSON), &settings) != nil {
		return false
	}
	value, exists := settings[key]
	if !exists {
		return defaultValue
	}
	enabled, ok := value.(bool)
	return ok && enabled
}

/* ─── Helper: Dispatch Real Webhooks ─── */

func dispatchWebhooks(app *models.Application, eventType string, payload interface{}) {
	if app.SettingsJSON == "" {
		return
	}

	var s struct {
		Webhooks []struct {
			ID     string   `json:"id"`
			URL    string   `json:"url"`
			Events []string `json:"events"`
			Status string   `json:"status"`
		} `json:"webhooks"`
		WebhookSigningSecret string `json:"webhookSigningSecret"`
	}

	if err := json.Unmarshal([]byte(app.SettingsJSON), &s); err != nil {
		return
	}

	bodyBytes, err := json.Marshal(gin.H{
		"type":      eventType,
		"app_id":    app.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      payload,
		"object":    "event",
		"id":        "evt_" + uuid.New().String(),
	})
	if err != nil {
		return
	}

	for _, wh := range s.Webhooks {
		if wh.Status != "active" || wh.URL == "" || !isSafeWebhookURL(wh.URL) {
			continue
		}
		// Check event match
		matched := false
		for _, e := range wh.Events {
			if e == eventType || e == "*" {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Asynchronous webhook dispatch
		go func(url, signingSecret string, data []byte) {
			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Brick-Webhooks/1.0")

			if signingSecret != "" {
				h := hmac.New(sha256.New, []byte(signingSecret))
				h.Write(data)
				sig := hex.EncodeToString(h.Sum(nil))
				req.Header.Set("svix-signature", fmt.Sprintf("v1,%s", sig))
				req.Header.Set("svix-timestamp", fmt.Sprintf("%d", time.Now().Unix()))
			}

			resp, err := client.Do(req)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}(wh.URL, s.WebhookSigningSecret, bodyBytes)
	}
}

/* ─── GET /api/v1/client/config ─── */

func GetClientConfig(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}

	var settings map[string]interface{}
	if app.SettingsJSON != "" {
		_ = json.Unmarshal([]byte(app.SettingsJSON), &settings)
	}
	if settings == nil {
		settings = make(map[string]interface{})
	}
	publicSettings := make(map[string]interface{})
	for _, key := range []string{
		"signUpWithEmail", "signInWithEmail", "verifyAtSignUp", "verifyMethod",
		"passwordEnabled", "phoneEnabled", "passkeysEnabled", "socialProviders",
		"legalPrivacyUrl", "legalTermsUrl", "legalConsentRequired",
	} {
		if value, ok := settings[key]; ok {
			publicSettings[key] = value
		}
	}
	var authOptions []models.AuthOption
	_ = json.Unmarshal([]byte(app.AuthOptions), &authOptions)
	if authOptions == nil {
		authOptions = []models.AuthOption{}
	}
	publishableKey := app.PublishableKey
	if env == "production" {
		publishableKey = app.LivePublishableKey
	}

	// Return public configuration needed by SDK / drop-in widgets
	c.JSON(http.StatusOK, gin.H{
		"app_id":          app.ID,
		"app_name":        app.Name,
		"org_enabled":     app.OrgEnabled,
		"publishable_key": publishableKey,
		"settings":        publicSettings,
		"auth_options":    authOptions,
	})
}

/* ─── POST /api/v1/client/sign-up ─── */

func ClientSignUp(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	if !appProviderEnabled(app, "email") || !appSettingEnabled(app, "signUpWithEmail", true) || !appSettingEnabled(app, "passwordEnabled", true) {
		c.JSON(http.StatusForbidden, gin.H{"error": "AUTH_METHOD_DISABLED", "message": "Email and password sign-up is disabled for this application"})
		return
	}

	var input ClientSignUpInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.WalletAddress != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "WALLET_SIGNATURE_REQUIRED", "message": "Wallet identities must be registered with signed SIWE"})
		return
	}
	if input.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "EMAIL_REQUIRED", "message": "Provide an email address; wallet accounts must use signed SIWE"})
		return
	}
	if !services.IsValidEmailFormat(input.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_EMAIL", "message": "Provide a valid email address"})
		return
	}
	if len(input.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PASSWORD_TOO_SHORT", "message": "Password must be at least 8 characters"})
		return
	}
	if len([]byte(input.Password)) > 72 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PASSWORD_TOO_LONG", "message": "Password must be no more than 72 bytes"})
		return
	}

	// Check if already exists in this application
	var existing models.AppUser
	query := db.DB.Where("app_id = ? AND environment = ?", app.ID, env)
	if input.Email != "" {
		query = query.Where("email = ?", input.Email)
	} else {
		query = query.Where("wallet_address = ?", input.WalletAddress)
	}

	if query.First(&existing).Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "USER_EXISTS", "message": "User already exists in this application"})
		return
	}
	if _, _, err := getAppTokenSigningKey(app.ID, env); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "TOKEN_SIGNING_UNAVAILABLE", "message": "Application token signing is not configured"})
		return
	}

	// Hash password if provided
	var passwordHash string
	if input.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "HASH_ERROR", "message": "Failed to secure password"})
			return
		}
		passwordHash = string(h)
	}

	appUser := models.AppUser{
		AppID:         app.ID,
		Email:         input.Email,
		WalletAddress: input.WalletAddress,
		Name:          input.Name,
		Role:          "member",
		Active:        true,
		Environment:   env,
		PasswordHash:  passwordHash,
	}

	if err := db.DB.Create(&appUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to create user"})
		return
	}

	// ── Anchor to Blockchain Ledger ───────────────────────────────────────────
	ledgerSvc := ledger.Get()
	if ledgerSvc == nil {
		_ = db.DB.Delete(&appUser).Error
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LEDGER_UNAVAILABLE", "message": "Identity registration is temporarily unavailable"})
		return
	}
	ident, regErr := ledgerSvc.RegisterIdentity(ledger.RegistrationRequest{
		UserID: appUser.ID,
		OrgID:  app.ID,
		Role:   "user",
		Attributes: map[string]string{
			"email":       appUser.Email,
			"app_id":      app.ID,
			"environment": env,
			"event":       "USER_SIGNUP",
		},
		Caller: ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true},
	})
	if regErr != nil || ident == nil || ident.Status != "active" {
		_ = db.DB.Delete(&appUser).Error
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "IDENTITY_ANCHOR_FAILED", "message": "Could not register an active identity on the configured ledger"})
		return
	}
	ledgerProof := gin.H{
		"identity_hash": ident.IdentityHash,
		"asset_key":     appUser.LedgerAssetKey,
		"mode":          ledgerSvc.Mode(),
		"verified":      true,
		"block_time":    ident.CreatedAt,
		"identity_ref":  ident.UserID,
	}

	// Generate JWT
	token, tokenErr := generateAppUserJWT(&appUser, app)
	if tokenErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_ERROR", "message": "Failed to sign token"})
		return
	}

	// Dispatch real-time webhooks
	dispatchWebhooks(app, "user.created", gin.H{
		"id":             appUser.ID,
		"email":          appUser.Email,
		"name":           appUser.Name,
		"wallet_address": appUser.WalletAddress,
		"created_at":     appUser.CreatedAt,
	})

	// Record immutable audit event
	actor := appUser.Email
	if actor == "" {
		actor = appUser.WalletAddress
	}
	services.RecordEvent(
		c,
		app.ID,
		appUser.ID,
		actor,
		"USER_SIGNUP",
		fmt.Sprintf("User account registered with on-chain identity anchor (%s)", appUser.Role),
		"confirmed",
		"LOW",
	)

	c.JSON(http.StatusCreated, gin.H{
		"token":        token,
		"user":         appUser,
		"ledger_proof": ledgerProof,
	})
}

/* ─── POST /api/v1/client/sign-in ─── */

func ClientSignIn(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	if !appProviderEnabled(app, "email") || !appSettingEnabled(app, "signInWithEmail", true) || !appSettingEnabled(app, "passwordEnabled", true) {
		c.JSON(http.StatusForbidden, gin.H{"error": "AUTH_METHOD_DISABLED", "message": "Email and password sign-in is disabled for this application"})
		return
	}

	var input ClientSignInInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	var appUser models.AppUser
	if err := db.DB.Where("app_id = ? AND environment = ? AND email = ?", app.ID, env, strings.ToLower(strings.TrimSpace(input.Email))).First(&appUser).Error; err != nil {
		services.RecordEvent(c, app.ID, "", input.Email, "USER_LOGIN_FAILED", "Failed sign-in attempt: user not found", "failed", "MEDIUM")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS", "message": "Invalid email or password"})
		return
	}

	if !appUser.Active {
		services.RecordEvent(c, app.ID, appUser.ID, appUser.Email, "ACCESS_DENIED", "Deactivated user attempted login", "warning", "HIGH")
		c.JSON(http.StatusForbidden, gin.H{"error": "ACCOUNT_DISABLED", "message": "Account has been deactivated"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(appUser.PasswordHash), []byte(input.Password)); err != nil {
		services.RecordEvent(c, app.ID, appUser.ID, appUser.Email, "USER_LOGIN_FAILED", "Failed sign-in attempt: incorrect password", "failed", "MEDIUM")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS", "message": "Invalid email or password"})
		return
	}
	if appUser.MFAEnabled {
		challenge, challengeErr := generateMFAChallengeToken(&appUser, app)
		if challengeErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_CHALLENGE_FAILED", "message": "Could not create MFA challenge"})
			return
		}
		services.RecordEvent(c, app.ID, appUser.ID, appUser.Email, "MFA_CHALLENGE_CREATED", "Password verified; second factor required", "pending", "LOW")
		c.JSON(http.StatusAccepted, gin.H{"mfa_required": true, "mfa_token": challenge, "expires_in": 300})
		return
	}

	// ── Anchor Session Sign-in to Blockchain Ledger ──────────────────────────
	ledgerSvc := ledger.Get()
	if ledgerSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LEDGER_UNAVAILABLE", "message": "Identity verification is temporarily unavailable"})
		return
	}
	caller := ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true}
	identity, ledgerErr := ledgerSvc.GetIdentity(app.ID, appUser.ID, caller)
	if ledgerErr != nil {
		identity, ledgerErr = ledgerSvc.RegisterIdentity(ledger.RegistrationRequest{
			UserID: appUser.ID,
			OrgID:  app.ID,
			Role:   "user",
			Attributes: map[string]string{
				"email":       appUser.Email,
				"app_id":      app.ID,
				"environment": env,
				"event":       "USER_LOGIN",
			},
			Caller: caller,
		})
	}
	if ledgerErr != nil || identity == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "IDENTITY_UNVERIFIED", "message": "Could not verify this identity on the configured ledger"})
		return
	}
	if identity.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "IDENTITY_INACTIVE", "message": "This identity is not active on the configured ledger"})
		return
	}
	ledgerProof := gin.H{
		"identity_hash": identity.IdentityHash,
		"asset_key":     appUser.LedgerAssetKey,
		"mode":          ledgerSvc.Mode(),
		"verified":      true,
		"block_time":    identity.UpdatedAt,
	}

	token, tokenErr := generateAppUserJWT(&appUser, app)
	if tokenErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_ERROR", "message": "Failed to sign token"})
		return
	}

	// Dispatch session.created webhook
	dispatchWebhooks(app, "session.created", gin.H{
		"user_id":    appUser.ID,
		"email":      appUser.Email,
		"session_at": time.Now().UTC(),
	})

	// Record audit event
	services.RecordEvent(
		c,
		app.ID,
		appUser.ID,
		appUser.Email,
		"SESSION_CREATED",
		fmt.Sprintf("Cryptographic JWT issued and authenticated via %s pipeline", appUser.Environment),
		"verified",
		"LOW",
	)

	c.JSON(http.StatusOK, gin.H{
		"token":        token,
		"user":         appUser,
		"ledger_proof": ledgerProof,
	})
}

/* ─── POST /api/v1/client/siwe (Sign-In with Ethereum) ─── */

func ClientMFASetup(c *gin.Context) {
	app, user, _, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	if user.MFAEnabled {
		c.JSON(http.StatusConflict, gin.H{"error": "MFA_ALREADY_ENABLED", "message": "Disable MFA before enrolling a new authenticator"})
		return
	}
	secret, err := services.GenerateTOTPSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_SETUP_FAILED", "message": "Could not generate authenticator secret"})
		return
	}
	encrypted, err := services.EncryptMFASecret(secret)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "MFA_ENCRYPTION_UNAVAILABLE", "message": "Server MFA encryption is not configured"})
		return
	}
	if err := db.DB.Model(user).Updates(map[string]interface{}{"mfa_secret": encrypted, "mfa_enabled": false, "mfa_recovery_codes": "[]"}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_SETUP_FAILED", "message": "Could not save authenticator setup"})
		return
	}
	account := user.Email
	if account == "" {
		account = user.WalletAddress
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret, "otpauth_uri": services.TOTPProvisioningURI(secret, account, app.Name), "message": "Add this authenticator to your TOTP app, then confirm with a current six-digit code. The secret is shown only during setup."})
}

func ClientMFAConfirm(c *gin.Context) {
	_, user, _, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	var input ClientMFACodeInput
	if err := c.ShouldBindJSON(&input); err != nil || input.Code == "" || user.MFASecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA_SETUP_REQUIRED", "message": "Start MFA setup and provide a six-digit authenticator code"})
		return
	}
	secret, err := services.DecryptMFASecret(user.MFASecret)
	if err != nil || !services.VerifyTOTP(secret, input.Code, time.Now().UTC()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA_CODE_INVALID", "message": "Authenticator code is invalid"})
		return
	}
	recoveryCodes, hashes, err := services.GenerateRecoveryCodes(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_SETUP_FAILED", "message": "Could not generate recovery codes"})
		return
	}
	hashedJSON, _ := json.Marshal(hashes)
	if err := db.DB.Model(user).Updates(map[string]interface{}{"mfa_enabled": true, "mfa_recovery_codes": string(hashedJSON)}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_SETUP_FAILED", "message": "Could not enable MFA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"mfa_enabled": true, "recovery_codes": recoveryCodes, "message": "Save these recovery codes securely. They are shown only once."})
}

func ClientMFADisable(c *gin.Context) {
	_, user, _, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	var input ClientMFACodeInput
	if err := c.ShouldBindJSON(&input); err != nil || input.Code == "" || !user.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA_CODE_REQUIRED", "message": "An active MFA setup and current authenticator code are required"})
		return
	}
	secret, err := services.DecryptMFASecret(user.MFASecret)
	if err != nil || !services.VerifyTOTP(secret, input.Code, time.Now().UTC()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA_CODE_INVALID", "message": "Authenticator code is invalid"})
		return
	}
	if err := db.DB.Model(user).Updates(map[string]interface{}{"mfa_enabled": false, "mfa_secret": "", "mfa_recovery_codes": "[]"}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_DISABLE_FAILED", "message": "Could not disable MFA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"mfa_enabled": false})
}

func ClientMFAVerify(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	var input ClientMFAVerifyInput
	if err := c.ShouldBindJSON(&input); err != nil || (input.Code == "") == (input.RecoveryCode == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Provide exactly one authenticator code or recovery code"})
		return
	}
	claims, err := parseClientToken(input.MFAToken, app, env)
	if err != nil || claims["typ"] != "mfa_challenge" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA_CHALLENGE_INVALID", "message": "MFA challenge is invalid or expired"})
		return
	}
	var user models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ? AND environment = ? AND active = ?", claims["sub"], app.ID, env, true).First(&user).Error; err != nil || !user.MFAEnabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA_CHALLENGE_INVALID", "message": "MFA challenge is invalid or expired"})
		return
	}
	ledgerSvc := ledger.Get()
	if ledgerSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LEDGER_UNAVAILABLE", "message": "Identity verification is temporarily unavailable"})
		return
	}
	caller := ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true}
	identity, err := ledgerSvc.GetIdentity(app.ID, user.ID, caller)
	if err != nil || identity == nil || identity.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "IDENTITY_INACTIVE", "message": "Identity is not active on the configured ledger"})
		return
	}
	if _, _, err := getAppTokenSigningKey(app.ID, env); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "TOKEN_SIGNING_UNAVAILABLE", "message": "Application token signing is not configured"})
		return
	}
	usedRecoveryCode := false
	if input.Code != "" {
		secret, err := services.DecryptMFASecret(user.MFASecret)
		if err != nil || !services.VerifyTOTP(secret, input.Code, time.Now().UTC()) {
			services.RecordEvent(c, app.ID, user.ID, user.Email, "MFA_VERIFICATION_FAILED", "Invalid TOTP code", "failed", "HIGH")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA_CODE_INVALID", "message": "Authenticator code is invalid"})
			return
		}
	} else {
		usedRecoveryCode = true
	}
	challengeID, challengeIDOK := claims["jti"].(string)
	if !challengeIDOK || !consumeMFAChallenge(challengeID, app.ID, env, user.ID, input.RecoveryCode) {
		services.RecordEvent(c, app.ID, user.ID, user.Email, "MFA_VERIFICATION_FAILED", "Invalid, expired, or already used MFA proof", "failed", "HIGH")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA_CHALLENGE_USED", "message": "MFA challenge is expired or has already been used"})
		return
	}
	accessToken, err := generateAppUserJWT(&user, app)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_ERROR", "message": "Failed to sign token"})
		return
	}
	services.RecordEvent(c, app.ID, user.ID, user.Email, "MFA_VERIFIED", "Second factor verified and session issued", "verified", "LOW")
	c.JSON(http.StatusOK, gin.H{"token": accessToken, "user": user, "ledger_proof": gin.H{"identity_hash": identity.IdentityHash, "asset_key": user.LedgerAssetKey, "mode": ledgerSvc.Mode(), "verified": true}, "recovery_code_used": usedRecoveryCode})
}

func consumeMFAChallenge(challengeID, appID, environment, userID, recoveryCode string) bool {
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.MFAChallenge{}).
			Where("id = ? AND app_id = ? AND environment = ? AND user_id = ? AND used = ? AND expires_at > ?", challengeID, appID, environment, userID, false, time.Now().UTC()).
			Update("used", true)
		if result.Error != nil || result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		if recoveryCode == "" {
			return nil
		}
		var user models.AppUser
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND app_id = ? AND environment = ? AND active = ? AND mfa_enabled = ?", userID, appID, environment, true, true).First(&user).Error; err != nil {
			return err
		}
		var hashes []string
		if err := json.Unmarshal([]byte(user.MFARecoveryCodes), &hashes); err != nil {
			return err
		}
		codeHash := services.RecoveryCodeHash(recoveryCode)
		for index, existing := range hashes {
			if subtle.ConstantTimeCompare([]byte(existing), []byte(codeHash)) == 1 {
				hashes = append(hashes[:index], hashes[index+1:]...)
				updated, _ := json.Marshal(hashes)
				return tx.Model(&user).Update("mfa_recovery_codes", string(updated)).Error
			}
		}
		return gorm.ErrRecordNotFound
	})
	return err == nil
}

func ClientSIWE(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	if !appProviderEnabled(app, "wallet") {
		c.JSON(http.StatusForbidden, gin.H{"error": "AUTH_METHOD_DISABLED", "message": "Wallet sign-in is disabled for this application"})
		return
	}

	var input ClientSIWEInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	addr := strings.ToLower(strings.TrimSpace(input.WalletAddress))
	matched, _ := regexp.MatchString(`^0x[0-9a-fA-F]{40}$`, addr)
	if !matched {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_WALLET", "message": "Must be a valid 42-character 0x-prefixed Ethereum address"})
		return
	}

	if strings.TrimSpace(input.Message) == "" || strings.TrimSpace(input.Signature) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SIGNATURE_REQUIRED", "message": "Message and cryptographic signature are required for SIWE authentication"})
		return
	}

	var challenge models.SIWENonce
	if err := db.DB.Where("app_id = ? AND environment = ? AND wallet_address = ? AND message = ? AND used = false AND expires_at > ?", app.ID, env, addr, input.Message, time.Now().UTC()).First(&challenge).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "CHALLENGE_INVALID", "message": "Request a new wallet sign-in challenge and try again"})
		return
	}

	validSig, sigErr := verifyEthereumSignature(addr, input.Message, input.Signature)
	if !validSig {
		services.RecordEvent(c, app.ID, "", addr, "SIWE_AUTH_FAILED", fmt.Sprintf("Cryptographic signature mismatch for %s: %v", addr, sigErr), "failed", "HIGH")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "SIGNATURE_INVALID", "message": "Cryptographic signature verification failed"})
		return
	}
	if _, _, err := getAppTokenSigningKey(app.ID, env); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "TOKEN_SIGNING_UNAVAILABLE", "message": "Application token signing is not configured"})
		return
	}
	consumed := db.DB.Model(&models.SIWENonce{}).Where("nonce = ? AND used = false AND expires_at > ?", challenge.Nonce, time.Now().UTC()).Update("used", true)
	if consumed.Error != nil || consumed.RowsAffected != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "CHALLENGE_ALREADY_USED", "message": "This wallet sign-in challenge has already been used"})
		return
	}

	// Find or create AppUser
	var appUser models.AppUser
	err = db.DB.Where("app_id = ? AND environment = ? AND wallet_address = ?", app.ID, env, addr).First(&appUser).Error
	if err != nil {
		// Create new Web3 user
		appUser = models.AppUser{
			AppID:         app.ID,
			WalletAddress: addr,
			Name:          fmt.Sprintf("0x...%s", addr[len(addr)-4:]),
			Role:          "member",
			Active:        true,
			Environment:   env,
		}
		if dbErr := db.DB.Create(&appUser).Error; dbErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "DB_ERROR", "message": "Failed to create web3 user"})
			return
		}
		dispatchWebhooks(app, "user.created", gin.H{
			"id":             appUser.ID,
			"wallet_address": appUser.WalletAddress,
			"auth_method":    "web3",
		})
	}

	if !appUser.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "ACCOUNT_DISABLED", "message": "This account has been deactivated"})
		return
	}
	if appUser.MFAEnabled {
		challenge, challengeErr := generateMFAChallengeToken(&appUser, app)
		if challengeErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_CHALLENGE_FAILED", "message": "Could not create MFA challenge"})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"mfa_required": true, "mfa_token": challenge, "expires_in": 300})
		return
	}

	// ── Anchor to Blockchain Ledger ───────────────────────────────────────────
	ledgerSvc := ledger.Get()
	if ledgerSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LEDGER_UNAVAILABLE", "message": "Identity verification is temporarily unavailable"})
		return
	}
	identity, ledgerErr := ledgerSvc.RegisterIdentity(ledger.RegistrationRequest{
		UserID: appUser.ID,
		OrgID:  app.ID,
		Role:   "user",
		Attributes: map[string]string{
			"app_id":         app.ID,
			"wallet_address": addr,
			"environment":    env,
		},
		Caller: ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true},
	})
	if ledgerErr != nil || identity == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "IDENTITY_ANCHOR_FAILED", "message": "Could not verify this identity on the configured ledger"})
		return
	}
	if identity.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "IDENTITY_INACTIVE", "message": "This identity is not active on the configured ledger"})
		return
	}
	ledgerProof := gin.H{
		"identity_hash":  identity.IdentityHash,
		"asset_key":      appUser.LedgerAssetKey,
		"mode":           ledgerSvc.Mode(),
		"verified":       true,
		"wallet_address": addr,
		"block_time":     identity.CreatedAt,
	}

	token, tokenErr := generateAppUserJWT(&appUser, app)
	if tokenErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_ERROR", "message": "Failed to sign token"})
		return
	}

	dispatchWebhooks(app, "session.created", gin.H{
		"user_id":        appUser.ID,
		"wallet_address": appUser.WalletAddress,
		"auth_method":    "web3",
	})

	// Record audit event
	services.RecordEvent(
		c,
		app.ID,
		appUser.ID,
		addr,
		"SIWE_AUTHENTICATED",
		fmt.Sprintf("Web3 wallet authenticated via Sign-In with Ethereum (%s)", addr),
		"verified",
		"LOW",
	)

	c.JSON(http.StatusOK, gin.H{
		"token":        token,
		"user":         appUser,
		"ledger_proof": ledgerProof,
	})
}

func ClientSIWENonce(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	if !appProviderEnabled(app, "wallet") {
		c.JSON(http.StatusForbidden, gin.H{"error": "AUTH_METHOD_DISABLED", "message": "Wallet sign-in is disabled for this application"})
		return
	}
	var input ClientSIWENonceInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}
	addr := strings.ToLower(strings.TrimSpace(input.WalletAddress))
	if matched, _ := regexp.MatchString(`^0x[0-9a-f]{40}$`, addr); !matched {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_WALLET", "message": "Provide a valid Ethereum address"})
		return
	}
	origin, err := url.Parse(c.GetHeader("Origin"))
	if err != nil || origin.Host == "" || (origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1"))) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_ORIGIN", "message": "A secure application Origin is required"})
		return
	}
	now := time.Now().UTC()
	_ = db.DB.Where("expires_at < ? OR used = true", now.Add(-time.Hour)).Delete(&models.SIWENonce{}).Error
	expiresAt := now.Add(5 * time.Minute)
	nonce := strings.ReplaceAll(uuid.NewString(), "-", "")
	message := fmt.Sprintf("%s wants you to sign in with your Ethereum account:\n%s\n\nSign in to %s with this wallet.\n\nURI: %s\nVersion: 1\nChain ID: %d\nNonce: %s\nIssued At: %s\nExpiration Time: %s", origin.Host, addr, app.Name, origin.String(), input.ChainID, nonce, now.Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	challenge := models.SIWENonce{Nonce: nonce, AppID: app.ID, Environment: env, WalletAddress: addr, Message: message, ExpiresAt: expiresAt}
	if err := db.DB.Create(&challenge).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "CHALLENGE_CREATE_FAILED", "message": "Could not save wallet sign-in challenge"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": message, "expires_at": expiresAt})
}

/* ─── POST /api/v1/client/verify-token (For Edge Functions / Backend Servers) ─── */

func ClientVerifyToken(c *gin.Context) {
	app, environment, err := getAppFromSecretKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}

	var input ClientVerifyTokenInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	claims, err := parseClientToken(input.Token, app, environment)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "TOKEN_INVALID", "message": "Token verification failed"})
		return
	}
	if claims["typ"] == "mfa_challenge" {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "MFA_REQUIRED", "message": "Second-factor challenges are not access tokens"})
		return
	}

	// Verify app_id matches
	if claims["app_id"] != app.ID {
		c.JSON(http.StatusForbidden, gin.H{"valid": false, "error": "APP_MISMATCH", "message": "Token not issued for this application"})
		return
	}

	userID, _ := claims["sub"].(string)
	var appUser models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ? AND environment = ? AND active = ?", userID, app.ID, environment, true).First(&appUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"valid": false, "error": "USER_NOT_FOUND"})
		return
	}

	// Verify ledger status
	ledgerVerified := true
	ledgerSvc := ledger.Get()
	if ledgerSvc != nil {
		caller := ledger.CallerContext{UserIdentity: appUser.ID, OrgID: app.ID, MSPID: "BrickMSP", IsAdmin: true}
		ident, getErr := ledgerSvc.GetIdentity(app.ID, appUser.ID, caller)
		if getErr == nil && ident != nil && ident.Status == "revoked" {
			c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "REVOKED_ON_LEDGER", "message": "Identity session revoked on blockchain ledger"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":           true,
		"user":            appUser,
		"claims":          claims,
		"ledger_verified": ledgerVerified,
	})
}

/* ─── GET /api/v1/client/jwks.json ─── */

func ClientJWKS(c *gin.Context) {
	app, environment, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	var signingKeys []models.TokenSigningKey
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	if err := db.DB.Where("app_id = ? AND environment = ? AND (active = ? OR retired_at > ?)", app.ID, environment, true, cutoff).Find(&signingKeys).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWKS_UNAVAILABLE", "message": "Could not load public signing keys"})
		return
	}
	keys := make([]gin.H, 0, len(signingKeys))
	for _, signingKey := range signingKeys {
		block, _ := pem.Decode([]byte(signingKey.PublicKeyPEM))
		if block == nil {
			continue
		}
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		exponent := big.NewInt(int64(rsaKey.E)).Bytes()
		keys = append(keys, gin.H{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": signingKey.ID,
			"n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(exponent),
		})
	}
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}
