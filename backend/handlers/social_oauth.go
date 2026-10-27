package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"brick/db"
	"brick/ledger"
	"brick/models"
	"brick/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type socialProviderConfig struct {
	ClientID     string
	ClientSecret string
	AuthorizeURL string
	TokenURL     string
	Scope        string
}

type socialUserInfo struct {
	Subject string
	Email   string
	Name    string
}

func socialProvider(provider string) (socialProviderConfig, bool) {
	switch provider {
	case "google":
		return socialProviderConfig{os.Getenv("GOOGLE_OAUTH_CLIENT_ID"), os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"), "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "openid email profile"}, true
	case "github":
		return socialProviderConfig{os.Getenv("GITHUB_OAUTH_CLIENT_ID"), os.Getenv("GITHUB_OAUTH_CLIENT_SECRET"), "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "read:user user:email"}, true
	case "apple":
		return socialProviderConfig{os.Getenv("APPLE_OAUTH_CLIENT_ID"), os.Getenv("APPLE_OAUTH_CLIENT_SECRET"), "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token", "name email"}, true
	default:
		return socialProviderConfig{}, false
	}
}

func brickOAuthCallbackURL() (string, error) {
	callback, err := url.Parse(strings.TrimSpace(os.Getenv("BRICK_OAUTH_CALLBACK_URL")))
	if err != nil || callback.Scheme != "https" || callback.Host == "" || callback.User != nil || callback.Fragment != "" {
		return "", fmt.Errorf("BRICK_OAUTH_CALLBACK_URL must be a valid HTTPS callback URL")
	}
	return callback.String(), nil
}

func validSocialRedirectURI(app *models.Application, candidate string) bool {
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))) {
		return false
	}
	var settings struct {
		SocialRedirectURIs []string `json:"socialRedirectUris"`
	}
	if json.Unmarshal([]byte(app.SettingsJSON), &settings) != nil {
		return false
	}
	for _, allowed := range settings.SocialRedirectURIs {
		if strings.TrimSpace(allowed) == candidate {
			return true
		}
	}
	return false
}

func StartSocialOAuth(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	config, supported := socialProvider(provider)
	if !supported {
		c.JSON(http.StatusNotFound, gin.H{"error": "OAUTH_PROVIDER_UNSUPPORTED", "message": "Supported providers are Google, GitHub, and Apple"})
		return
	}
	if config.ClientID == "" || config.ClientSecret == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OAUTH_PROVIDER_UNAVAILABLE", "message": "This social sign-in provider is not configured"})
		return
	}
	app, environment, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED", "message": err.Error()})
		return
	}
	if !appProviderEnabled(app, provider) {
		c.JSON(http.StatusForbidden, gin.H{"error": "AUTH_METHOD_DISABLED", "message": "This social sign-in provider is disabled for the application"})
		return
	}
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))
	if !validSocialRedirectURI(app, redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "REDIRECT_URI_NOT_ALLOWED", "message": "Register this exact HTTPS redirect URI in application settings"})
		return
	}
	callbackURL, err := brickOAuthCallbackURL()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OAUTH_CALLBACK_UNAVAILABLE", "message": "Social sign-in callback is not configured"})
		return
	}
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OAUTH_START_FAILED", "message": "Could not start social sign-in"})
		return
	}
	state := hex.EncodeToString(stateBytes)
	stateHash := sha256.Sum256([]byte(state))
	nonceHash := ""
	nonce := ""
	if provider == "apple" {
		nonceBytes := make([]byte, 32)
		if _, err := rand.Read(nonceBytes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OAUTH_START_FAILED", "message": "Could not start social sign-in"})
			return
		}
		nonce = hex.EncodeToString(nonceBytes)
		nonceDigest := sha256.Sum256([]byte(nonce))
		nonceHash = hex.EncodeToString(nonceDigest[:])
	}
	_ = db.DB.Where("expires_at < ?", time.Now().UTC()).Delete(&models.OAuthTransaction{}).Error
	transaction := models.OAuthTransaction{StateHash: hex.EncodeToString(stateHash[:]), NonceHash: nonceHash, AppID: app.ID, Environment: environment, Provider: provider, RedirectURI: redirectURI, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	if err := db.DB.Create(&transaction).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OAUTH_START_FAILED", "message": "Could not start social sign-in"})
		return
	}
	params := url.Values{"client_id": {config.ClientID}, "redirect_uri": {callbackURL}, "response_type": {"code"}, "scope": {config.Scope}, "state": {state}}
	if provider == "google" {
		params.Set("include_granted_scopes", "true")
	} else if provider == "apple" {
		params.Set("response_mode", "form_post")
		params.Set("nonce", nonce)
	}
	c.Redirect(http.StatusFound, config.AuthorizeURL+"?"+params.Encode())
}

func CompleteSocialOAuth(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAUTH_RESPONSE_INVALID", "message": "Social sign-in response is invalid"})
		return
	}
	state := c.Request.Form.Get("state")
	if len(state) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAUTH_STATE_INVALID", "message": "Social sign-in state is missing or invalid"})
		return
	}
	stateHash := sha256.Sum256([]byte(state))
	var transaction models.OAuthTransaction
	now := time.Now().UTC()
	consume := db.DB.Model(&models.OAuthTransaction{}).Where("state_hash = ? AND used = ? AND expires_at > ?", hex.EncodeToString(stateHash[:]), false, now).Updates(map[string]interface{}{"used": true})
	if consume.Error != nil || consume.RowsAffected != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAUTH_STATE_EXPIRED", "message": "Social sign-in state is invalid, expired, or already used"})
		return
	}
	if err := db.DB.Where("state_hash = ?", hex.EncodeToString(stateHash[:])).First(&transaction).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAUTH_STATE_INVALID", "message": "Social sign-in state is invalid"})
		return
	}
	redirect, _ := url.Parse(transaction.RedirectURI)
	finishWithError := func(code string) {
		fragment := url.Values{"brick_error": {code}}
		redirect.Fragment = fragment.Encode()
		c.Redirect(http.StatusFound, redirect.String())
	}
	code := c.Request.Form.Get("code")
	if c.Request.Form.Get("error") != "" || code == "" {
		finishWithError("access_denied")
		return
	}
	var app models.Application
	if err := db.DB.Where("id = ?", transaction.AppID).First(&app).Error; err != nil || !appProviderEnabled(&app, transaction.Provider) {
		finishWithError("provider_unavailable")
		return
	}
	if _, _, err := getAppTokenSigningKey(app.ID, transaction.Environment); err != nil {
		finishWithError("token_unavailable")
		return
	}
	identity, err := fetchSocialIdentity(transaction.Provider, code, transaction.NonceHash)
	if err != nil || identity.Subject == "" || (identity.Email != "" && !services.IsValidEmailFormat(identity.Email)) {
		finishWithError("identity_unverified")
		return
	}
	var social models.SocialIdentity
	var socialUser models.AppUser
	socialErr := db.DB.Where("app_id = ? AND environment = ? AND provider = ? AND subject = ?", app.ID, transaction.Environment, transaction.Provider, identity.Subject).First(&social).Error
	if socialErr == nil {
		if err := db.DB.Where("id = ? AND app_id = ? AND environment = ? AND active = ?", social.UserID, app.ID, transaction.Environment, true).First(&socialUser).Error; err != nil {
			finishWithError("account_unavailable")
			return
		}
	} else if errors.Is(socialErr, gorm.ErrRecordNotFound) {
		if identity.Email == "" {
			finishWithError("identity_unverified")
			return
		}
		userErr := db.DB.Where("app_id = ? AND environment = ? AND lower(email) = ?", app.ID, transaction.Environment, strings.ToLower(identity.Email)).First(&socialUser).Error
		if userErr != nil && !errors.Is(userErr, gorm.ErrRecordNotFound) {
			finishWithError("account_unavailable")
			return
		}
		if errors.Is(userErr, gorm.ErrRecordNotFound) {
			socialUser = models.AppUser{AppID: app.ID, Environment: transaction.Environment, Email: strings.ToLower(identity.Email), Name: identity.Name, Role: "member", Active: true}
			if err := db.DB.Create(&socialUser).Error; err != nil {
				finishWithError("account_create_failed")
				return
			}
			ledgerSvc := ledger.Get()
			if ledgerSvc == nil {
				_ = db.DB.Delete(&socialUser).Error
				finishWithError("identity_anchor_failed")
				return
			}
			anchored, anchorErr := ledgerSvc.RegisterIdentity(ledger.RegistrationRequest{UserID: socialUser.ID, OrgID: app.ID, Role: "user", Attributes: map[string]string{"email": socialUser.Email, "app_id": app.ID, "environment": transaction.Environment, "event": "SOCIAL_SIGNUP"}, Caller: ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true}})
			if anchorErr != nil || anchored == nil || anchored.Status != "active" {
				_ = db.DB.Delete(&socialUser).Error
				finishWithError("identity_anchor_failed")
				return
			}
		} else if !socialUser.Active {
			finishWithError("account_unavailable")
			return
		}
		social = models.SocialIdentity{AppID: app.ID, Environment: transaction.Environment, Provider: transaction.Provider, Subject: identity.Subject, UserID: socialUser.ID}
		if err := db.DB.Create(&social).Error; err != nil {
			if errors.Is(userErr, gorm.ErrRecordNotFound) {
				_ = db.DB.Delete(&socialUser).Error
			}
			finishWithError("identity_link_failed")
			return
		}
	} else {
		finishWithError("account_unavailable")
		return
	}
	ledgerSvc := ledger.Get()
	if ledgerSvc == nil {
		finishWithError("identity_unavailable")
		return
	}
	ledgerIdentity, ledgerErr := ledgerSvc.GetIdentity(app.ID, socialUser.ID, ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true})
	if ledgerErr != nil || ledgerIdentity == nil || ledgerIdentity.Status != "active" {
		finishWithError("identity_unverified")
		return
	}
	if socialUser.MFAEnabled {
		mfaToken, err := generateMFAChallengeToken(&socialUser, &app)
		if err != nil {
			finishWithError("mfa_unavailable")
			return
		}
		services.RecordEvent(c, app.ID, socialUser.ID, socialUser.Email, "MFA_CHALLENGE_CREATED", "Social identity verified; second factor required", "pending", "LOW")
		redirect.Fragment = url.Values{"mfa_required": {"true"}, "mfa_token": {mfaToken}, "expires_in": {"300"}}.Encode()
		c.Redirect(http.StatusFound, redirect.String())
		return
	}
	accessToken, err := generateAppUserJWT(&socialUser, &app)
	if err != nil {
		finishWithError("token_unavailable")
		return
	}
	fragment := url.Values{"brick_token": {accessToken}, "user_id": {socialUser.ID}}
	redirect.Fragment = fragment.Encode()
	dispatchWebhooks(&app, "session.created", gin.H{"user_id": socialUser.ID, "email": socialUser.Email, "provider": transaction.Provider, "session_at": time.Now().UTC()})
	services.RecordEvent(c, app.ID, socialUser.ID, socialUser.Email, "SOCIAL_LOGIN", "Verified social provider sign-in", "verified", "LOW")
	c.Redirect(http.StatusFound, redirect.String())
}

var socialHTTPClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(request *http.Request, previous []*http.Request) error { return http.ErrUseLastResponse }}

var appleKeysMu sync.RWMutex
var appleKeys map[string]*rsa.PublicKey
var appleKeysExpiresAt time.Time

type appleJWKSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func appleSigningKey(kid string) (*rsa.PublicKey, error) {
	appleKeysMu.RLock()
	key, found := appleKeys[kid]
	fresh := time.Now().UTC().Before(appleKeysExpiresAt)
	appleKeysMu.RUnlock()
	if found && fresh {
		return key, nil
	}
	request, err := http.NewRequest(http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return nil, err
	}
	response, err := socialHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Apple signing keys are unavailable")
	}
	var keySet appleJWKSet
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&keySet); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(keySet.Keys))
	for _, jwk := range keySet.Keys {
		if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Kid == "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil || len(modulus) < 256 {
			continue
		}
		exponent, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			continue
		}
		exponentValue := binary.BigEndian.Uint32(append(make([]byte, 4-len(exponent)), exponent...))
		if exponentValue < 3 || exponentValue%2 == 0 {
			continue
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponentValue)}
	}
	appleKeysMu.Lock()
	appleKeys = keys
	appleKeysExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	key = appleKeys[kid]
	appleKeysMu.Unlock()
	if key == nil {
		return nil, fmt.Errorf("Apple signing key identifier is unknown")
	}
	return key, nil
}

func verifyAppleIDToken(rawToken, expectedNonceHash, clientID string) (jwt.MapClaims, error) {
	if rawToken == "" || expectedNonceHash == "" || clientID == "" {
		return nil, fmt.Errorf("Apple identity token is incomplete")
	}
	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("Apple identity token uses an unsupported signing method")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("Apple identity token has no key identifier")
		}
		return appleSigningKey(kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://appleid.apple.com"), jwt.WithAudience(clientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(time.Minute))
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("Apple identity token is invalid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Apple identity token claims are invalid")
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil || issuedAt.After(time.Now().UTC().Add(time.Minute)) {
		return nil, fmt.Errorf("Apple identity token issue time is invalid")
	}
	subject, _ := claims["sub"].(string)
	nonce, _ := claims["nonce"].(string)
	actualNonceHash := sha256.Sum256([]byte(nonce))
	if subject == "" || nonce == "" || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(actualNonceHash[:])), []byte(expectedNonceHash)) != 1 {
		return nil, fmt.Errorf("Apple identity token nonce or subject is invalid")
	}
	audiences, _ := claims.GetAudience()
	if authorizedParty, ok := claims["azp"].(string); (ok && authorizedParty != clientID) || (len(audiences) > 1 && !ok) {
		return nil, fmt.Errorf("Apple identity token authorized party is invalid")
	}
	return claims, nil
}

func fetchSocialIdentity(provider, code, nonceHash string) (*socialUserInfo, error) {
	config, ok := socialProvider(provider)
	if !ok || config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("social provider is not configured")
	}
	callback, err := brickOAuthCallbackURL()
	if err != nil {
		return nil, err
	}
	form := url.Values{"client_id": {config.ClientID}, "client_secret": {config.ClientSecret}, "code": {code}, "redirect_uri": {callback}}
	tokenRequest, err := http.NewRequest(http.MethodPost, config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set("Accept", "application/json")
	tokenResponse, err := socialHTTPClient.Do(tokenRequest)
	if err != nil {
		return nil, err
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider token exchange failed")
	}
	var tokenData struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResponse.Body, 1<<20)).Decode(&tokenData); err != nil || tokenData.AccessToken == "" {
		return nil, fmt.Errorf("provider returned an invalid token response")
	}
	if provider == "google" {
		request, _ := http.NewRequest(http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
		request.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
		response, err := socialHTTPClient.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Google user-info verification failed")
		}
		var info struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&info); err != nil || !info.EmailVerified {
			return nil, fmt.Errorf("Google account email is not verified")
		}
		return &socialUserInfo{Subject: info.Sub, Email: info.Email, Name: info.Name}, nil
	}
	if provider == "apple" {
		claims, err := verifyAppleIDToken(tokenData.IDToken, nonceHash, config.ClientID)
		if err != nil {
			return nil, err
		}
		email, _ := claims["email"].(string)
		subject, _ := claims["sub"].(string)
		verified := claims["email_verified"] == true || claims["email_verified"] == "true"
		if !verified {
			return nil, fmt.Errorf("Apple account email is not verified")
		}
		return &socialUserInfo{Subject: subject, Email: email}, nil
	}
	request, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	request.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := socialHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub user verification failed")
	}
	var user struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&user); err != nil || user.ID == 0 {
		return nil, fmt.Errorf("GitHub returned an invalid user")
	}
	emailRequest, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
	emailRequest.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	emailRequest.Header.Set("Accept", "application/vnd.github+json")
	emailResponse, err := socialHTTPClient.Do(emailRequest)
	if err != nil {
		return nil, err
	}
	defer emailResponse.Body.Close()
	if emailResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub verified email lookup failed")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(io.LimitReader(emailResponse.Body, 1<<20)).Decode(&emails); err != nil {
		return nil, err
	}
	for _, email := range emails {
		if email.Primary && email.Verified {
			return &socialUserInfo{Subject: fmt.Sprint(user.ID), Email: email.Email, Name: user.Name}, nil
		}
	}
	return nil, fmt.Errorf("GitHub has no verified primary email")
}
