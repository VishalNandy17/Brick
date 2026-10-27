package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"brick/db"
	"brick/ledger"
	"brick/models"
	"brick/services"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type passkeyUser struct {
	user        models.AppUser
	credentials []webauthn.Credential
}

func (user *passkeyUser) WebAuthnID() []byte { return []byte(user.user.ID) }
func (user *passkeyUser) WebAuthnName() string {
	if user.user.Email != "" {
		return user.user.Email
	}
	return user.user.ID
}
func (user *passkeyUser) WebAuthnDisplayName() string {
	if user.user.Name != "" {
		return user.user.Name
	}
	return user.WebAuthnName()
}
func (user *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return user.credentials }

type passkeySettings struct {
	PasskeyRPID    string   `json:"passkeyRPID"`
	PasskeyOrigins []string `json:"passkeyOrigins"`
}

func getWebAuthn(app *models.Application) (*webauthn.WebAuthn, error) {
	if !appSettingEnabled(app, "passkeysEnabled", false) {
		return nil, http.ErrNotSupported
	}
	var settings passkeySettings
	if err := json.Unmarshal([]byte(app.SettingsJSON), &settings); err != nil {
		return nil, err
	}
	rpID := strings.TrimSpace(strings.ToLower(settings.PasskeyRPID))
	if rpID == "" || len(settings.PasskeyOrigins) == 0 {
		return nil, http.ErrNotSupported
	}
	for _, raw := range settings.PasskeyOrigins {
		origin, err := url.Parse(raw)
		if err != nil || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || (origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1"))) {
			return nil, http.ErrNotSupported
		}
		host := strings.ToLower(origin.Hostname())
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return nil, http.ErrNotSupported
		}
	}
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: app.Name, RPOrigins: settings.PasskeyOrigins})
}

func loadPasskeyUser(user models.AppUser, appID, environment string) (*passkeyUser, []models.PasskeyCredential, error) {
	var records []models.PasskeyCredential
	if err := db.DB.Where("app_id = ? AND environment = ? AND user_id = ?", appID, environment, user.ID).Find(&records).Error; err != nil {
		return nil, nil, err
	}
	result := &passkeyUser{user: user}
	for _, record := range records {
		data, err := services.DecryptWebAuthnCredential(record.CredentialData)
		if err != nil {
			return nil, nil, err
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(data, &credential); err != nil {
			return nil, nil, err
		}
		result.credentials = append(result.credentials, credential)
	}
	return result, records, nil
}

func saveWebAuthnChallenge(appID, environment, userID, ceremonyType string, session *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	challenge := models.WebAuthnChallenge{AppID: appID, Environment: environment, UserID: userID, Type: ceremonyType, SessionData: string(data), ExpiresAt: time.Now().Add(5 * time.Minute)}
	if err := db.DB.Create(&challenge).Error; err != nil {
		return "", err
	}
	return challenge.ID, nil
}

func consumeWebAuthnChallenge(id, appID, environment, userID, ceremonyType string) (*webauthn.SessionData, bool) {
	var challenge models.WebAuthnChallenge
	now := time.Now()
	if db.DB.Where("id = ? AND app_id = ? AND environment = ? AND user_id = ? AND type = ? AND used = ? AND expires_at > ?", id, appID, environment, userID, ceremonyType, false, now).First(&challenge).Error != nil {
		return nil, false
	}
	if db.DB.Model(&challenge).Where("used = ? AND expires_at > ?", false, now).Update("used", true).RowsAffected != 1 {
		return nil, false
	}
	var session webauthn.SessionData
	if json.Unmarshal([]byte(challenge.SessionData), &session) != nil {
		return nil, false
	}
	return &session, true
}

type passkeyBeginInput struct {
	Email string `json:"email"`
}
type passkeyFinishInput struct {
	CeremonyID string          `json:"ceremony_id" binding:"required"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential" binding:"required"`
}

var errLastPasskeySignInMethod = errors.New("last sign-in method")

func ListClientPasskeys(c *gin.Context) {
	app, user, env, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var passkeys []models.PasskeyCredential
	if err := db.DB.Select("id, app_id, environment, user_id, name, created_at, last_used_at").Where("app_id = ? AND environment = ? AND user_id = ?", app.ID, env, user.ID).Order("created_at desc").Find(&passkeys).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"passkeys": passkeys})
}

func DeleteClientPasskey(c *gin.Context) {
	app, user, env, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var lockedUser models.AppUser
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND app_id = ? AND environment = ? AND active = ?", user.ID, app.ID, env, true).First(&lockedUser).Error; err != nil {
			return err
		}
		var target models.PasskeyCredential
		if err := tx.Where("id = ? AND app_id = ? AND environment = ? AND user_id = ?", c.Param("credentialId"), app.ID, env, user.ID).First(&target).Error; err != nil {
			return err
		}
		var total int64
		if err := tx.Model(&models.PasskeyCredential{}).Where("app_id = ? AND environment = ? AND user_id = ?", app.ID, env, user.ID).Count(&total).Error; err != nil {
			return err
		}
		var socialCount int64
		if err := tx.Model(&models.SocialIdentity{}).Where("app_id = ? AND environment = ? AND user_id = ?", app.ID, env, user.ID).Count(&socialCount).Error; err != nil {
			return err
		}
		if total <= 1 && lockedUser.PasswordHash == "" && lockedUser.WalletAddress == "" && socialCount == 0 {
			return errLastPasskeySignInMethod
		}
		return tx.Delete(&target).Error
	})
	if err != nil {
		if errors.Is(err, errLastPasskeySignInMethod) {
			c.JSON(http.StatusConflict, gin.H{"error": "LAST_SIGN_IN_METHOD", "message": "Add another sign-in method before removing this passkey"})
			return
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "PASSKEY_NOT_FOUND"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	services.RecordEvent(c, app.ID, user.ID, user.Email, "PASSKEY_REMOVED", "User removed a passkey credential", "confirmed", "LOW")
	c.JSON(http.StatusOK, gin.H{"success": true, "id": c.Param("credentialId")})
}

func PasskeyRegistrationBegin(c *gin.Context) {
	app, user, env, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	wa, err := getWebAuthn(app)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "PASSKEYS_DISABLED_OR_UNCONFIGURED"})
		return
	}
	account, _, err := loadPasskeyUser(*user, app.ID, env)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	options, session, err := wa.BeginRegistration(account, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirement("required")), webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_REGISTRATION_FAILED"})
		return
	}
	id, err := saveWebAuthnChallenge(app.ID, env, user.ID, "registration", session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_REGISTRATION_FAILED"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ceremony_id": id, "options": options})
}

func PasskeyRegistrationFinish(c *gin.Context) {
	app, user, env, err := authenticatedClientUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var input passkeyFinishInput
	if c.ShouldBindJSON(&input) != nil || len(input.Credential) == 0 || len(input.Credential) > 65536 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}
	wa, err := getWebAuthn(app)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "PASSKEYS_DISABLED_OR_UNCONFIGURED"})
		return
	}
	session, ok := consumeWebAuthnChallenge(input.CeremonyID, app.ID, env, user.ID, "registration")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_OR_EXPIRED_CEREMONY"})
		return
	}
	account, _, err := loadPasskeyUser(*user, app.ID, env)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	request, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(input.Credential))
	request.Header.Set("Content-Type", "application/json")
	credential, err := wa.FinishRegistration(account, *session, request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PASSKEY_VERIFICATION_FAILED"})
		return
	}
	data, err := json.Marshal(credential)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	encrypted, err := services.EncryptWebAuthnCredential(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	name := strings.TrimSpace(input.Name)
	if len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		name = "Passkey"
	}
	record := models.PasskeyCredential{AppID: app.ID, Environment: env, UserID: user.ID, CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID), CredentialData: encrypted, Name: name}
	if err := db.DB.Create(&record).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "PASSKEY_ALREADY_REGISTERED"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": record.ID, "name": record.Name, "created_at": record.CreatedAt})
}

func PasskeyLoginBegin(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var input passkeyBeginInput
	if c.ShouldBindJSON(&input) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}
	wa, err := getWebAuthn(app)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "PASSKEYS_DISABLED_OR_UNCONFIGURED"})
		return
	}
	var user models.AppUser
	if db.DB.Where("app_id = ? AND environment = ? AND email = ? AND active = ?", app.ID, env, strings.ToLower(strings.TrimSpace(input.Email)), true).First(&user).Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS"})
		return
	}
	account, records, err := loadPasskeyUser(user, app.ID, env)
	if err != nil || len(records) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS"})
		return
	}
	options, session, err := wa.BeginLogin(account, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_LOGIN_FAILED"})
		return
	}
	id, err := saveWebAuthnChallenge(app.ID, env, user.ID, "login", session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_LOGIN_FAILED"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ceremony_id": id, "options": options})
}

func PasskeyLoginFinish(c *gin.Context) {
	app, env, err := getAppFromPublishableKey(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	var input passkeyFinishInput
	if c.ShouldBindJSON(&input) != nil || len(input.Credential) == 0 || len(input.Credential) > 65536 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}
	wa, err := getWebAuthn(app)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "PASSKEYS_DISABLED_OR_UNCONFIGURED"})
		return
	}
	var challenge models.WebAuthnChallenge
	if db.DB.Where("id = ? AND app_id = ? AND environment = ? AND type = ? AND used = ? AND expires_at > ?", input.CeremonyID, app.ID, env, "login", false, time.Now()).First(&challenge).Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_OR_EXPIRED_CEREMONY"})
		return
	}
	session, ok := consumeWebAuthnChallenge(input.CeremonyID, app.ID, env, challenge.UserID, "login")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_OR_EXPIRED_CEREMONY"})
		return
	}
	var user models.AppUser
	if db.DB.Where("id = ? AND app_id = ? AND environment = ? AND active = ?", challenge.UserID, app.ID, env, true).First(&user).Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CREDENTIALS"})
		return
	}
	account, records, err := loadPasskeyUser(user, app.ID, env)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	request, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(input.Credential))
	request.Header.Set("Content-Type", "application/json")
	credential, err := wa.FinishLogin(account, *session, request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "PASSKEY_VERIFICATION_FAILED"})
		return
	}
	data, err := json.Marshal(credential)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	encrypted, err := services.EncryptWebAuthnCredential(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	var record *models.PasskeyCredential
	encodedID := base64.RawURLEncoding.EncodeToString(credential.ID)
	for index := range records {
		if records[index].CredentialID == encodedID {
			record = &records[index]
			break
		}
	}
	if record == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "PASSKEY_VERIFICATION_FAILED"})
		return
	}
	if err := db.DB.Model(record).Updates(map[string]interface{}{"credential_data": encrypted, "last_used_at": time.Now()}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PASSKEY_STORAGE_ERROR"})
		return
	}
	if user.MFAEnabled && !appSettingEnabled(app, "passkeySatisfiesMfa", false) {
		token, tokenErr := generateMFAChallengeToken(&user, app)
		if tokenErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA_CHALLENGE_FAILED"})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"mfa_required": true, "mfa_token": token, "expires_in": 300})
		return
	}
	ledgerSvc := ledger.Get()
	if ledgerSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LEDGER_UNAVAILABLE", "message": "Identity verification is temporarily unavailable"})
		return
	}
	caller := ledger.CallerContext{UserIdentity: "brick-auth", OrgID: app.ID, MSPID: app.ID, IsAdmin: true}
	identity, ledgerErr := ledgerSvc.GetIdentity(app.ID, user.ID, caller)
	if ledgerErr != nil || identity == nil || identity.Status != "active" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "IDENTITY_UNVERIFIED", "message": "Could not verify this identity on the configured ledger"})
		return
	}
	token, err := generateAppUserJWT(&user, app)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "user": user, "ledger_proof": gin.H{"identity_hash": identity.IdentityHash, "asset_key": user.LedgerAssetKey, "mode": ledgerSvc.Mode(), "verified": true, "block_time": identity.UpdatedAt}})
}
