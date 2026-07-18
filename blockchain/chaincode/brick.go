package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// BrickContract defines the methods for interacting with the ledger
type BrickContract struct {
	contractapi.Contract
}

// Asset represents a basic asset in the blockchain
type Asset struct {
	ID          string    `json:"id"`
	Owner       string    `json:"owner"`
	Description string    `json:"description"`
	Value       float64   `json:"value"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Metadata    string    `json:"metadata"`
}

// Transaction represents a transaction record
type Transaction struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	AssetID   string    `json:"asset_id"`
	Value     float64   `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

// User represents a user in the system
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"` // admin, user, auditor
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateAsset creates a new asset on the ledger
func (bc *BrickContract) CreateAsset(ctx contractapi.TransactionContextInterface, assetID string, owner string, description string, value float64, metadata string) error {
	asset := Asset{
		ID:          assetID,
		Owner:       owner,
		Description: description,
		Value:       value,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata:    metadata,
	}

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %w", err)
	}

	return ctx.GetStub().PutState(assetID, assetJSON)
}

// ReadAsset retrieves an asset from the ledger
func (bc *BrickContract) ReadAsset(ctx contractapi.TransactionContextInterface, assetID string) (*Asset, error) {
	assetJSON, err := ctx.GetStub().GetState(assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to read asset: %w", err)
	}

	if assetJSON == nil {
		return nil, fmt.Errorf("asset %s not found", assetID)
	}

	var asset Asset
	err = json.Unmarshal(assetJSON, &asset)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal asset: %w", err)
	}

	return &asset, nil
}

// UpdateAsset updates an existing asset on the ledger
func (bc *BrickContract) UpdateAsset(ctx contractapi.TransactionContextInterface, assetID string, description string, value float64, metadata string) error {
	asset, err := bc.ReadAsset(ctx, assetID)
	if err != nil {
		return err
	}

	asset.Description = description
	asset.Value = value
	asset.Metadata = metadata
	asset.UpdatedAt = time.Now()

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %w", err)
	}

	return ctx.GetStub().PutState(assetID, assetJSON)
}

// DeleteAsset deletes an asset from the ledger
func (bc *BrickContract) DeleteAsset(ctx contractapi.TransactionContextInterface, assetID string) error {
	return ctx.GetStub().DelState(assetID)
}

// TransferAsset transfers ownership of an asset
func (bc *BrickContract) TransferAsset(ctx contractapi.TransactionContextInterface, assetID string, newOwner string) error {
	asset, err := bc.ReadAsset(ctx, assetID)
	if err != nil {
		return err
	}

	// Record transaction
	tx := Transaction{
		ID:        fmt.Sprintf("tx_%s_%d", assetID, time.Now().Unix()),
		From:      asset.Owner,
		To:        newOwner,
		AssetID:   assetID,
		Value:     asset.Value,
		Timestamp: time.Now(),
		Status:    "completed",
	}

	txJSON, _ := json.Marshal(tx)
	ctx.GetStub().PutState(tx.ID, txJSON)

	// Update asset ownership
	asset.Owner = newOwner
	asset.UpdatedAt = time.Now()

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %w", err)
	}

	return ctx.GetStub().PutState(assetID, assetJSON)
}

// GetAssetHistory retrieves the history of an asset
func (bc *BrickContract) GetAssetHistory(ctx contractapi.TransactionContextInterface, assetID string) (string, error) {
	resultsIterator, err := ctx.GetStub().GetHistoryForKey(assetID)
	if err != nil {
		return "", fmt.Errorf("failed to get history: %w", err)
	}
	defer resultsIterator.Close()

	var records []interface{}
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return "", fmt.Errorf("failed to iterate history: %w", err)
		}

		records = append(records, map[string]interface{}{
			"timestamp": response.Timestamp,
			"value":     string(response.Value),
		})
	}

	resultsJSON, _ := json.Marshal(records)
	return string(resultsJSON), nil
}

// CreateUser registers a new user on the ledger
func (bc *BrickContract) CreateUser(ctx contractapi.TransactionContextInterface, userID string, email string, name string, role string) error {
	user := User{
		ID:        userID,
		Email:     email,
		Name:      name,
		Role:      role,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	userJSON, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	return ctx.GetStub().PutState(userID, userJSON)
}

// ReadUser retrieves a user from the ledger
func (bc *BrickContract) ReadUser(ctx contractapi.TransactionContextInterface, userID string) (*User, error) {
	userJSON, err := ctx.GetStub().GetState(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to read user: %w", err)
	}

	if userJSON == nil {
		return nil, fmt.Errorf("user %s not found", userID)
	}

	var user User
	err = json.Unmarshal(userJSON, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// QueryAssets queries all assets using a range query
func (bc *BrickContract) QueryAssets(ctx contractapi.TransactionContextInterface, startKey string, endKey string) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return "", fmt.Errorf("failed to query assets: %w", err)
	}
	defer resultsIterator.Close()

	var results []interface{}
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return "", fmt.Errorf("failed to iterate results: %w", err)
		}

		var asset interface{}
		err = json.Unmarshal(response.Value, &asset)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal asset: %w", err)
		}

		results = append(results, asset)
	}

	resultsJSON, _ := json.Marshal(results)
	return string(resultsJSON), nil
}

// GetTransactionHistory retrieves all transactions for an asset
func (bc *BrickContract) GetTransactionHistory(ctx contractapi.TransactionContextInterface, assetID string) (string, error) {
	// Query for all transactions related to the asset
	queryString := fmt.Sprintf(`{"selector":{"asset_id":"%s"}}`, assetID)
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return "", fmt.Errorf("failed to query transactions: %w", err)
	}
	defer resultsIterator.Close()

	var transactions []Transaction
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return "", fmt.Errorf("failed to iterate transactions: %w", err)
		}

		var tx Transaction
		err = json.Unmarshal(response.Value, &tx)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal transaction: %w", err)
		}

		transactions = append(transactions, tx)
	}

	resultsJSON, _ := json.Marshal(transactions)
	return string(resultsJSON), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&BrickContract{}, &BrickIdentityContract{})
	if err != nil {
		log.Panicf("Error creating brick chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting brick chaincode: %v", err)
	}
}
