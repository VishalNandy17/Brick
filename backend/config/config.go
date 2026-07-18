package config

import (
	"os"
)

type Config struct {
	ServerPort            string
	FabricCfgPath         string
	ChannelName           string
	ChaincodeName         string
	PeerHost              string
	PeerPort              string
	CAHost                string
	CAPort                string
	OrgName               string
	OrgMSPID              string
	AdminUser             string
	AdminPassword         string
	LedgerMode            string
	LedgerDataPath        string
	ConnectionProfilePath string
	JWTSecret             string
	// Database
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
	// Twilio SendGrid
	SendGridAPIKey   string
	SendGridFrom     string
	SendGridFromName string
}

func NewConfig() *Config {
	return &Config{
		ServerPort:            getEnv("SERVER_PORT", "8080"),
		FabricCfgPath:         getEnv("FABRIC_CFG_PATH", "../blockchain/config"),
		ChannelName:           getEnv("CHANNEL_NAME", "mychannel"),
		ChaincodeName:         getEnv("CHAINCODE_NAME", "brick-identity"),
		PeerHost:              getEnv("PEER_HOST", "localhost"),
		PeerPort:              getEnv("PEER_PORT", "7051"),
		CAHost:                getEnv("CA_HOST", "localhost"),
		CAPort:                getEnv("CA_PORT", "7054"),
		OrgName:               getEnv("ORG_NAME", "Org1"),
		OrgMSPID:              getEnv("ORG_MSPID", "Org1MSP"),
		AdminUser:             getEnv("ADMIN_USER", "admin"),
		AdminPassword:         getEnv("ADMIN_PASSWORD", "adminpw"),
		LedgerMode:            getEnv("BRICK_LEDGER_MODE", "cloud"),
		LedgerDataPath:        getEnv("BRICK_LEDGER_DATA", "../data/cloud-ledger.json"),
		ConnectionProfilePath: getEnv("CONNECTION_PROFILE", "../connection-cloud.json"),
		JWTSecret:             getEnv("JWT_SECRET", "dev-secret"),
		// Database
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "brick_user"),
		DBPassword: getEnv("DB_PASSWORD", "brick_password"),
		DBName:     getEnv("DB_NAME", "brick_db"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),
		// Twilio SendGrid
		SendGridAPIKey:   getEnv("SENDGRID_API_KEY", ""),
		SendGridFrom:     getEnv("SENDGRID_FROM_EMAIL", "noreply@brickauth.io"),
		SendGridFromName: getEnv("SENDGRID_FROM_NAME", "Brick Auth"),
	}
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}
