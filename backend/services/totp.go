package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func TOTPProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", "6")
	query.Set("period", "30")
	return "otpauth://totp/" + label + "?" + query.Encode()
}

func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	for offset := int64(-1); offset <= 1; offset++ {
		counter := uint64(now.Unix()/30 + offset)
		var message [8]byte
		binary.BigEndian.PutUint64(message[:], counter)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(message[:])
		digest := mac.Sum(nil)
		index := digest[len(digest)-1] & 0x0f
		value := (uint32(digest[index])&0x7f)<<24 | (uint32(digest[index+1])&0xff)<<16 | (uint32(digest[index+2])&0xff)<<8 | uint32(digest[index+3])&0xff
		generated := fmt.Sprintf("%06d", value%1000000)
		if subtle.ConstantTimeCompare([]byte(generated), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func EncryptMFASecret(plaintext string) (string, error) {
	key := mfaEncryptionKey()
	if len(key) == 0 {
		return "", fmt.Errorf("BRICK_MFA_ENCRYPTION_KEY is not configured")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)
	combined := append(nonce, ciphertext...)
	return "v1:" + base64.RawStdEncoding.EncodeToString(combined), nil
}

func DecryptMFASecret(value string) (string, error) {
	key := mfaEncryptionKey()
	if len(key) == 0 {
		return "", fmt.Errorf("BRICK_MFA_ENCRYPTION_KEY is not configured")
	}
	if !strings.HasPrefix(value, "v1:") {
		return "", fmt.Errorf("unsupported encrypted MFA secret format")
	}
	encoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "v1:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(encoded) < aead.NonceSize() {
		return "", fmt.Errorf("encrypted MFA secret is truncated")
	}
	nonce, ciphertext := encoded[:aead.NonceSize()], encoded[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt MFA secret: %w", err)
	}
	return string(plaintext), nil
}

func GenerateRecoveryCodes(count int) ([]string, []string, error) {
	if count < 1 || count > 20 {
		return nil, nil, fmt.Errorf("recovery code count out of range")
	}
	plain := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for range count {
		bytes := make([]byte, 10)
		if _, err := rand.Read(bytes); err != nil {
			return nil, nil, err
		}
		code := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes))
		plain = append(plain, code)
		hash := sha256.Sum256([]byte(code))
		hashes = append(hashes, base64.RawURLEncoding.EncodeToString(hash[:]))
	}
	return plain, hashes, nil
}

func RecoveryCodeHash(code string) string {
	hash := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func mfaEncryptionKey() []byte {
	secret := strings.TrimSpace(os.Getenv("BRICK_MFA_ENCRYPTION_KEY"))
	if len([]byte(secret)) < 32 {
		return nil
	}
	key := sha256.Sum256([]byte(secret))
	return key[:]
}
