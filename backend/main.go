package main

import (
	"brick/config"
	"brick/db"
	"brick/handlers"
	"brick/ledger"
	"brick/middleware"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func loadEnv() {
	candidates := []string{
		"../.env",
		".env",
		"/app/.env",
	}
	for _, path := range candidates {
		if err := godotenv.Load(path); err == nil {
			log.Printf("Loaded environment from %s", path)
			return
		}
	}
	log.Println("No .env file found, using system environment")
}

func main() {
	loadEnv()

	cfg := config.NewConfig()
	fmt.Println("Starting BRICK Backend Server...")

	// ── Database (Postgres + GORM) ──────────────────────────────────────
	db.Connect()

	// ── Blockchain Ledger ───────────────────────────────────────────────
	if err := ledger.Initialize(ledger.InitOptions{
		Mode:                  cfg.LedgerMode,
		DataPath:              cfg.LedgerDataPath,
		ConnectionProfilePath: cfg.ConnectionProfilePath,
	}); err != nil {
		log.Fatal("Failed to initialize ledger:", err)
	}
	log.Printf("Ledger initialized in %s mode", ledger.Get().Mode())

	// ── Router ──────────────────────────────────────────────────────────
	router := gin.Default()
	_ = router.SetTrustedProxies(nil)
	router.Use(middleware.ErrorRecoveryMiddleware())
	router.Use(middleware.SecurityHeadersMiddleware())
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.LoggingMiddleware())

	// Health
	router.GET("/api/health", Health)
	router.GET("/health", Health)

	// ── Auth Routes (OTP + JWT) — Public ─────────────────────────────────────────────
	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/request-otp", handlers.RequestOTP)   // Signup: send email OTP
		authGroup.POST("/verify-otp", handlers.VerifyOTP)     // Signup: verify OTP + set password
		authGroup.POST("/login", handlers.LoginWithPassword)   // Login: email + password
		authGroup.POST("/refresh", handlers.RefreshTokenHandler) // silent token renewal
	}

	// ── Developer Client Auth Routes (For external apps & edge functions) ────────
	clientGroup := router.Group("/api/v1/client")
	{
		clientGroup.GET("/config", handlers.GetClientConfig)
		clientGroup.POST("/sign-up", handlers.ClientSignUp)
		clientGroup.POST("/sign-in", handlers.ClientSignIn)
		clientGroup.POST("/siwe", handlers.ClientSIWE)
		clientGroup.POST("/verify-token", handlers.ClientVerifyToken)
		clientGroup.GET("/jwks.json", handlers.ClientJWKS)
	}

	// ── Blockchain / Identity Routes ─────────────────────────────────────
	blockchainGroup := router.Group("/api/blockchain")
	{
		blockchainGroup.GET("/query", handlers.QueryBlockchain)
		blockchainGroup.POST("/invoke", handlers.InvokeChaincode)
		blockchainGroup.GET("/history/:key", handlers.GetHistory)
	}

	// ── User CRUD (BrickAuth-protected) ───────────────────────────────────────
	userGroup := router.Group("/api/users")
	userGroup.Use(middleware.BrickAuthMiddleware()) // upgraded: JWT + ledger revocation check
	{
		userGroup.GET("/me", handlers.GetMe)
		userGroup.GET("", handlers.GetUsers)
		userGroup.POST("", handlers.CreateUser)
		userGroup.GET("/:id", handlers.GetUserByID)
		userGroup.PUT("/:id", handlers.UpdateUser)
		userGroup.DELETE("/:id", handlers.DeleteUser)
	}

	v1Users := router.Group("/api/v1/users")
	v1Users.Use(middleware.BrickAuthMiddleware())
	{
		v1Users.GET("/me", handlers.GetMe)
	}

	// ── Transaction Routes (BrickAuth-protected) ───────────────────────────────
	txGroup := router.Group("/api/transactions")
	txGroup.Use(middleware.BrickAuthMiddleware())
	{
		txGroup.GET("", handlers.GetTransactions)
		txGroup.POST("", handlers.CreateTransaction)
		txGroup.GET("/:id", handlers.GetTransactionByID)
	}

	// ── Fabric Gateway Identity Routes ───────────────────────────────────────
	v1 := router.Group("/api/v1/brick")
	{
		v1.POST("/enroll", EnrollIdentity)
		v1.GET("/session/:userId", GetSession)
		v1.GET("/identities", ListIdentities)
	}

	// ── Admin Routes (BrickAuth + AdminGuard) ───────────────────────────────
	adminGroup := router.Group("/api/v1/brick/admin")
	adminGroup.Use(middleware.BrickAuthMiddleware(), middleware.AdminGuard())
	{
		adminGroup.POST("/revoke-session", handlers.RevokeSession)
	}

	// ── Application (Developer Dashboard) Routes ────────────────────────────
	appsGroup := router.Group("/api/v1/apps")
	appsGroup.Use(middleware.BrickAuthMiddleware())
	{
		appsGroup.POST("", handlers.CreateApplication)
		appsGroup.GET("", handlers.GetApplications)
		appsGroup.GET("/:id", handlers.GetApplicationByID)
		appsGroup.PUT("/:id", handlers.UpdateApplication)
		appsGroup.POST("/:id/rotate-keys", handlers.RotateAPIKeys)
		appsGroup.POST("/test-webhook", handlers.TestWebhook)
		appsGroup.GET("/:id/users", handlers.GetApplicationUsers)
		appsGroup.POST("/:id/users", handlers.CreateApplicationUser)
		appsGroup.PUT("/:id/users/:userId", handlers.UpdateApplicationUser)
		appsGroup.DELETE("/:id/users/:userId", handlers.DeleteApplicationUser)
		appsGroup.GET("/:id/logs", handlers.GetApplicationLogs)
	}

	port := cfg.ServerPort
	fmt.Printf("Server running on port %s (ledger: %s)\n", port, ledger.Get().Mode())

	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
