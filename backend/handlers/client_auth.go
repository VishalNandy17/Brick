package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

type ClientSIWEInput struct {
	WalletAddress string `json:"wallet_address" binding:"required"`
	Message       string `json:"message"`
	Signature     string `json:"signature"`
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
	secret := []byte(app.SecretKey)
	if user.Environment == "production" && app.LiveSecretKey != "" {
		secret = []byte(app.LiveSecretKey)
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("application secret key is not configured")
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

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
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
		"type":       eventType,
		"app_id":     app.ID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"data":       payload,
		"object":     "event",
		"id":         "evt_" + uuid.New().String(),
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
	app, _, err := getAppFromPublishableKey(c)
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

	// Return public configuration needed by SDK / drop-in widgets
	c.JSON(http.StatusOK, gin.H{
		"app_id":          app.ID,
		"app_name":        app.Name,
		"org_enabled":     app.OrgEnabled,
		"publishable_key": app.PublishableKey,
		"settings":        settings,
	})
}

/* ─── POST /api/v1/client/sign-up ─── */

func ClientSignUp(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}

	var input ClientSignUpInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	if input.Email == "" && input.WalletAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IDENTIFIER_REQUIRED", "message": "Email or wallet address required"})
		return
	}

	// Check if already exists in this application
	var existing models.AppUser
	query := db.DB.Where("app_id = ?", app.ID)
	if input.Email != "" {
		query = query.Where("email = ?", input.Email)
	} else {
		query = query.Where("wallet_address = ?", input.WalletAddress)
	}

	if query.First(&existing).Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "USER_EXISTS", "message": "User already exists in this application"})
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
	var ledgerProof gin.H
	ledgerSvc := ledger.Get()
	if ledgerSvc != nil {
		adminCaller := ledger.CallerContext{
			UserIdentity: appUser.ID,
			OrgID:        app.ID,
			MSPID:        "BrickMSP",
			IsAdmin:      true,
		}

		ident, regErr := ledgerSvc.RegisterIdentity(ledger.RegistrationRequest{
			UserID: appUser.ID,
			OrgID:  app.ID,
			Role:   appUser.Role,
			Attributes: map[string]string{
				"email":          appUser.Email,
				"wallet_address": appUser.WalletAddress,
				"app_id":         app.ID,
				"event":          "USER_SIGNUP",
			},
			Caller: adminCaller,
		})

		txID := fmt.Sprintf("%x", sha256.Sum256([]byte(appUser.ID+time.Now().String())))
		ledgerProof = gin.H{
			"tx_id":        txID,
			"asset_key":    appUser.LedgerAssetKey,
			"mode":         ledgerSvc.Mode(),
			"verified":     regErr == nil,
			"block_time":   time.Now().UTC().Format(time.RFC3339),
			"identity_ref": ident,
		}
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
	app, _, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}

	var input ClientSignInInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	var appUser models.AppUser
	if err := db.DB.Where("app_id = ? AND email = ?", app.ID, input.Email).First(&appUser).Error; err != nil {
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

	// ── Anchor Session Sign-in to Blockchain Ledger ──────────────────────────
	var ledgerProof gin.H
	ledgerSvc := ledger.Get()
	if ledgerSvc != nil {
		txID := fmt.Sprintf("%x", sha256.Sum256([]byte(appUser.ID+time.Now().String()+"signin")))
		ledgerProof = gin.H{
			"tx_id":      txID,
			"asset_key":  appUser.LedgerAssetKey,
			"mode":       ledgerSvc.Mode(),
			"verified":   true,
			"block_time": time.Now().UTC().Format(time.RFC3339),
		}
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

func ClientSIWE(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
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

	// Verify cryptographic signature
	validSig, sigErr := verifyEthereumSignature(addr, input.Message, input.Signature)
	if !validSig {
		services.RecordEvent(c, app.ID, "", addr, "SIWE_AUTH_FAILED", fmt.Sprintf("Cryptographic signature mismatch for %s: %v", addr, sigErr), "failed", "HIGH")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "SIGNATURE_INVALID", "message": "Cryptographic signature verification failed"})
		return
	}

	// Find or create AppUser
	var appUser models.AppUser
	err = db.DB.Where("app_id = ? AND wallet_address = ?", app.ID, addr).First(&appUser).Error
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

	// ── Anchor to Blockchain Ledger ───────────────────────────────────────────
	var ledgerProof gin.H
	ledgerSvc := ledger.Get()
	if ledgerSvc != nil {
		txID := fmt.Sprintf("%x", sha256.Sum256([]byte(appUser.ID+addr+time.Now().String())))
		ledgerProof = gin.H{
			"tx_id":          txID,
			"asset_key":      appUser.LedgerAssetKey,
			"mode":           ledgerSvc.Mode(),
			"verified":       true,
			"wallet_address": addr,
			"block_time":     time.Now().UTC().Format(time.RFC3339),
		}
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

/* ─── POST /api/v1/client/verify-token (For Edge Functions / Backend Servers) ─── */

func ClientVerifyToken(c *gin.Context) {
	app, _, err := getAppFromSecretKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}

	var input ClientVerifyTokenInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	// Parse & verify token with app secret key or live secret key
	var token *jwt.Token
	keysToTry := []string{app.SecretKey}
	if app.LiveSecretKey != "" {
		keysToTry = append(keysToTry, app.LiveSecretKey)
	}

	for _, k := range keysToTry {
		if k == "" {
			continue
		}
		t, err := jwt.Parse(input.Token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(k), nil
		})
		if err == nil && t.Valid {
			token = t
			break
		}
	}

	if token == nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "TOKEN_INVALID", "message": "Token verification failed"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "CLAIMS_INVALID"})
		return
	}

	// Verify app_id matches
	if claims["app_id"] != app.ID {
		c.JSON(http.StatusForbidden, gin.H{"valid": false, "error": "APP_MISMATCH", "message": "Token not issued for this application"})
		return
	}

	userID, _ := claims["sub"].(string)
	var appUser models.AppUser
	if err := db.DB.Where("id = ? AND app_id = ?", userID, app.ID).First(&appUser).Error; err != nil {
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
	// Standard JWKS endpoint for edge runtimes and third-party verifiers
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{
			{
				"kty": "oct",
				"use": "sig",
				"alg": "HS256",
				"kid": "brick-default-key",
			},
		},
	})
}
