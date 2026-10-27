package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func EncryptTokenPrivateKey(plaintext []byte) (string, error) {
	key := tokenKeyEncryptionKey()
	if len(key) == 0 {
		return "", fmt.Errorf("JWT_SECRET must contain at least 32 bytes to protect signing keys")
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
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return "v1:" + base64.RawStdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func DecryptTokenPrivateKey(value string) ([]byte, error) {
	key := tokenKeyEncryptionKey()
	if len(key) == 0 {
		return nil, fmt.Errorf("JWT_SECRET must contain at least 32 bytes to unlock signing keys")
	}
	if !strings.HasPrefix(value, "v1:") {
		return nil, fmt.Errorf("unsupported signing key encryption format")
	}
	data, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "v1:"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("encrypted signing key is truncated")
	}
	return aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
}

func tokenKeyEncryptionKey() []byte {
	return deriveEncryptionKey("brick:app-token-signing-key-encryption:v1")
}

func deriveEncryptionKey(context string) []byte {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if len([]byte(secret)) < 32 {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(context))
	return mac.Sum(nil)
}

func EncryptWebAuthnCredential(plaintext []byte) (string, error) {
	return encryptWithContext(plaintext, "brick:webauthn-credential-encryption:v1")
}

func DecryptWebAuthnCredential(value string) ([]byte, error) {
	return decryptWithContext(value, "brick:webauthn-credential-encryption:v1")
}

func encryptWithContext(plaintext []byte, context string) (string, error) {
	key := deriveEncryptionKey(context)
	if len(key) == 0 {
		return "", fmt.Errorf("JWT_SECRET must contain at least 32 bytes to protect passkey credentials")
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
	return "v1:" + base64.RawStdEncoding.EncodeToString(append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)), nil
}

func decryptWithContext(value, context string) ([]byte, error) {
	key := deriveEncryptionKey(context)
	if len(key) == 0 {
		return nil, fmt.Errorf("JWT_SECRET must contain at least 32 bytes to unlock passkey credentials")
	}
	if !strings.HasPrefix(value, "v1:") {
		return nil, fmt.Errorf("unsupported credential encryption format")
	}
	data, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "v1:"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("encrypted credential is truncated")
	}
	return aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
}
