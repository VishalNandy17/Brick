package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
)

// ConnectionProfile represents Fabric network connection configuration
type ConnectionProfile struct {
	PeerHost      string `json:"peerHost"`
	PeerPort      int    `json:"peerPort"`
	PeerAddress   string `json:"peerAddress"`
	TLSCertPath   string `json:"tlsCertPath"`
	CertPath      string `json:"certPath"`
	KeyPath       string `json:"keyPath"`
	OrgName       string `json:"orgName"`
	OrgMSPID      string `json:"orgMspId"`
	ChannelName   string `json:"channelName"`
	ChaincodeName string `json:"chaincodeName"`
}

// LoadConnectionProfile reads connection profile from JSON file
func LoadConnectionProfile(configPath string) (*ConnectionProfile, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var profile ConnectionProfile
	err = json.Unmarshal(data, &profile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Validate required fields
	if profile.PeerHost == "" || profile.PeerPort == 0 {
		return nil, fmt.Errorf("peerHost and peerPort are required in connection profile")
	}

	if profile.OrgName == "" || profile.OrgMSPID == "" {
		return nil, fmt.Errorf("orgName and orgMspId are required in connection profile")
	}

	// Construct peer address if not provided
	if profile.PeerAddress == "" {
		profile.PeerAddress = fmt.Sprintf("%s:%d", profile.PeerHost, profile.PeerPort)
	}

	return &profile, nil
}

// loadTLSCert reads and parses TLS certificate
func loadTLSCert(certPath string) (*x509.Certificate, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS cert: %w", err)
	}

	// Parse PEM certificate
	cert, err := tls.X509KeyPair(certData, []byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS cert: %w", err)
	}

	// Extract X509 certificate
	x509Certs, err := x509.ParseCertificates(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 cert: %w", err)
	}

	if len(x509Certs) == 0 {
		return nil, fmt.Errorf("no certificates found in cert file")
	}

	return x509Certs[0], nil
}

// loadUserCredentials loads user certificate and private key
func loadUserCredentials(certPath, keyPath string) (*x509.Certificate, interface{}, error) {
	// Read certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read user cert: %w", err)
	}

	// Read private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read user key: %w", err)
	}

	// Parse certificate and key
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse cert/key pair: %w", err)
	}

	// Parse X509 certificate
	x509Certs, err := x509.ParseCertificates(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse X509 cert: %w", err)
	}

	if len(x509Certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}

	return x509Certs[0], cert.PrivateKey, nil
}

// PrivateDataCollectionStub demonstrates PDC pattern for PII data minimization
// This is a code stub showing how to integrate Private Data Collections
type PrivateDataCollectionStub struct {
	// Collection name for PDC (e.g., "userProfilesPDC")
	CollectionName string

	// Example: Store encrypted profile details separately
	// Only accessible by authorized parties within the org
	EncryptedProfile map[string]interface{}
}

// Note: Production implementation would use:
// ctx.GetStub().PutPrivateData(CollectionName, key, encryptedData)
// ctx.GetStub().GetPrivateData(CollectionName, key)
//
// This keeps sensitive PII off the main ledger while maintaining
// cryptographic proof of identity on the public ledger.

// StrictTypeValidation demonstrates TypeScript-like error handling
type ValidationError struct {
	Field   string
	Message string
	Code    string
}

type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// ValidateIdentityRequest performs strict type validation
func ValidateIdentityRequest(req IdentityRegistrationPayload) ValidationResult {
	result := ValidationResult{Valid: true}

	// Validate UserID
	if req.UserID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "userId",
			Message: "UserID cannot be empty",
			Code:    "INVALID_USER_ID",
		})
	}

	// Validate OrgID
	if req.OrgID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "orgId",
			Message: "OrgID cannot be empty",
			Code:    "INVALID_ORG_ID",
		})
	}

	// Validate Role
	validRoles := map[string]bool{
		"admin":   true,
		"user":    true,
		"auditor": true,
	}
	if !validRoles[req.Role] {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "role",
			Message: "Role must be admin, user, or auditor",
			Code:    "INVALID_ROLE",
		})
	}

	return result
}
