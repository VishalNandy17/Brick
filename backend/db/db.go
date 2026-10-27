package db

import (
	"brick/models"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Connect initializes the database connection.
// It tries PostgreSQL first. If unavailable, falls back to local SQLite.
func Connect() {
	db, mode := tryPostgres()
	if db == nil {
		log.Println("⚠️  PostgreSQL unavailable — falling back to SQLite (brick.db)")
		db = mustSQLite()
		mode = "sqlite"
	}

	// Auto-migrate all models
	if err := db.AutoMigrate(
		&models.User{},
		&models.OTPRecord{},
		&models.RefreshToken{},
		&models.Application{},
		&models.AppUser{},
		&models.AuditLog{},
	); err != nil {
		log.Fatalf("❌ Database migration failed: %v", err)
	}

	DB = db
	log.Printf("✅ Database ready [%s]", mode)
}

// tryPostgres attempts to connect to Postgres and returns nil on failure
func tryPostgres() (*gorm.DB, string) {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "brick_user")
	password := getEnv("DB_PASSWORD", "brick_password")
	dbname := getEnv("DB_NAME", "brick_db")
	sslmode := getEnv("DB_SSLMODE", "disable")

	// Check if a Neon/remote DSN is provided directly
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		db, err := gorm.Open(postgres.Open(dsn), gormConfig())
		if err == nil {
			log.Println("✅ Connected to PostgreSQL via DATABASE_URL")
			return db, "postgres"
		}
		log.Printf("⚠️  DATABASE_URL connection failed: %v", err)
		return nil, ""
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		host, user, password, dbname, port, sslmode,
	)

	db, err := gorm.Open(postgres.Open(dsn), gormConfig())
	if err != nil {
		return nil, ""
	}
	log.Println("✅ Connected to PostgreSQL (local)")
	return db, "postgres"
}

// mustSQLite opens a local SQLite database file — no install required
func mustSQLite() *gorm.DB {
	dataDir := getEnv("SQLITE_PATH", "../data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("⚠️  Could not create data dir, using current dir: %v", err)
		dataDir = "."
	}
	dbPath := dataDir + "/brick.db"
	db, err := gorm.Open(sqlite.Open(dbPath), gormConfig())
	if err != nil {
		log.Fatalf("❌ Failed to open SQLite at %s: %v", dbPath, err)
	}
	log.Printf("✅ SQLite database opened at %s", dbPath)
	return db
}

func gormConfig() *gorm.Config {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             1500 * time.Millisecond, // 1.5s threshold for remote cloud database
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
	return &gorm.Config{
		Logger: newLogger,
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
