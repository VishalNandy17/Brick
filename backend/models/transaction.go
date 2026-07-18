package models

import "time"

// Transaction represents a blockchain transaction
type Transaction struct {
	ID            string    `json:"id"`
	TxHash        string    `json:"tx_hash"`
	FromUser      string    `json:"from_user"`
	ToUser        string    `json:"to_user"`
	Amount        float64   `json:"amount"`
	Description   string    `json:"description"`
	Status        string    `json:"status"` // pending, confirmed, failed
	Timestamp     time.Time `json:"timestamp"`
	BlockNumber   int64     `json:"block_number"`
	TransactionID string    `json:"transaction_id"`
}

// TransactionRequest is the request body for creating transactions
type TransactionRequest struct {
	FromUser    string  `json:"from_user" binding:"required"`
	ToUser      string  `json:"to_user" binding:"required"`
	Amount      float64 `json:"amount" binding:"required,gt=0"`
	Description string  `json:"description"`
}

// TransactionResponse wraps transaction data with metadata
type TransactionResponse struct {
	Success bool         `json:"success"`
	Message string       `json:"message"`
	Data    *Transaction `json:"data,omitempty"`
}
