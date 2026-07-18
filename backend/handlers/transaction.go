package handlers

import (
	"brick/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// GetTransactions retrieves all transactions
func GetTransactions(c *gin.Context) {
	// TODO: Implement database query
	transactions := []models.Transaction{
		{
			ID:          "tx_001",
			TxHash:      "0x123abc",
			FromUser:    "user_1",
			ToUser:      "user_2",
			Amount:      100.50,
			Description: "Payment for services",
			Status:      "confirmed",
			Timestamp:   time.Now(),
			BlockNumber: 12345,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    transactions,
		"count":   len(transactions),
	})
}

// CreateTransaction creates a new transaction
func CreateTransaction(c *gin.Context) {
	var req models.TransactionRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// TODO: Implement transaction creation on blockchain
	tx := models.Transaction{
		ID:            "tx_" + time.Now().Format("20060102150405"),
		TxHash:        "0x" + time.Now().Format("150405"),
		FromUser:      req.FromUser,
		ToUser:        req.ToUser,
		Amount:        req.Amount,
		Description:   req.Description,
		Status:        "pending",
		Timestamp:     time.Now(),
		TransactionID: "txid_pending",
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    tx,
		"message": "Transaction created successfully",
	})
}

// GetTransactionByID retrieves a transaction by ID
func GetTransactionByID(c *gin.Context) {
	id := c.Param("id")

	// TODO: Implement database query
	tx := models.Transaction{
		ID:          id,
		TxHash:      "0x123abc",
		FromUser:    "user_1",
		ToUser:      "user_2",
		Amount:      100.50,
		Description: "Payment for services",
		Status:      "confirmed",
		Timestamp:   time.Now(),
		BlockNumber: 12345,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    tx,
	})
}
