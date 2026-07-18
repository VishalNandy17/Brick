package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-contract-api-go/metadata"
)

// BrickIdentityContract implements the Fabric smart contract for decentralized IAM
type BrickIdentityContract struct {
	contractapi.Contract
}

// BrickIdentity represents a user identity in the BRICK system
type BrickIdentity struct {
	UserID       string `json:"userId"`
	OrgID        string `json:"orgId"`
	Role         string `json:"role"`
	Status       string `json:"status"` // active, suspended, revoked
	IdentityHash string `json:"identityHash"`
	MSPID        string `json:"mspId"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	Attributes   map[string]string `json:"attributes"`
}

// IdentityRegistrationRequest represents enrollment request
type IdentityRegistrationRequest struct {
	UserID      string            `json:"userId"`
	OrgID       string            `json:"orgId"`
	Role        string            `json:"role"`
	Attributes  map[string]string `json:"attributes"`
}

// RegisterIdentity enrolls a new identity with dynamic MSP extraction
func (bic *BrickIdentityContract) RegisterIdentity(
	ctx contractapi.TransactionContextInterface,
	userID string,
	orgID string,
	role string,
	attributesJSON string,
) (*BrickIdentity, error) {
	
	// Extract caller's identity from client context
	clientIdentity := ctx.GetClientIdentity()
	if clientIdentity == nil {
		return nil, fmt.Errorf("client identity not available")
	}

	// Get caller's MSP ID
	callerMSPID, err := clientIdentity.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get caller MSP ID: %v", err)
	}

	// Verify ABAC: Check for brick-admin attribute for sensitive operations
	adminVal, found, err := clientIdentity.GetAttributeValue("brick-admin")
	if err != nil {
		return nil, fmt.Errorf("failed to verify admin attribute: %v", err)
	}
	if !found || adminVal != "true" {
		return nil, fmt.Errorf("caller lacks brick-admin attribute for identity registration")
	}

	// Parse attributes
	var attributes map[string]string
	err = json.Unmarshal([]byte(attributesJSON), &attributes)
	if err != nil {
		return nil, fmt.Errorf("invalid attributes JSON: %v", err)
	}

	// Generate identity hash (SHA256 of userID + OrgID + timestamp)
	stub := ctx.GetStub()
	txTime, err := stub.GetTxTimestamp()
	if err != nil {
		return nil, fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	identityHashInput := fmt.Sprintf("%s:%s:%d", userID, orgID, txTime.Seconds)
	identityHash := sha256.Sum256([]byte(identityHashInput))
	identityHashStr := hex.EncodeToString(identityHash[:])

	// Create new identity record
	identity := &BrickIdentity{
		UserID:       userID,
		OrgID:        orgID,
		Role:         role,
		Status:       "active",
		IdentityHash: identityHashStr,
		MSPID:        callerMSPID,
		CreatedAt:    txTime.String(),
		UpdatedAt:    txTime.String(),
		Attributes:   attributes,
	}

	// Validate organization matching
	if orgID != callerMSPID {
		return nil, fmt.Errorf("organization mismatch: requested %s, caller MSP %s", orgID, callerMSPID)
	}

	// Store identity on ledger
	identityKey := fmt.Sprintf("identity_%s_%s", orgID, userID)
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal identity: %v", err)
	}

	err = ctx.GetStub().PutState(identityKey, identityBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to store identity: %v", err)
	}

	// Emit registration event
	registrationEvent := map[string]interface{}{
		"userID":   userID,
		"orgID":    orgID,
		"role":     role,
		"mspId":    callerMSPID,
		"status":   "registered",
	}
	registrationEventBytes, _ := json.Marshal(registrationEvent)
	ctx.GetStub().SetEvent("IdentityRegistered", registrationEventBytes)

	return identity, nil
}

// GetIdentity retrieves identity details with authorization check
func (bic *BrickIdentityContract) GetIdentity(
	ctx contractapi.TransactionContextInterface,
	orgID string,
	userID string,
) (*BrickIdentity, error) {
	
	// Extract caller's MSP ID
	clientIdentity := ctx.GetClientIdentity()
	callerMSPID, err := clientIdentity.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get caller MSP ID: %v", err)
	}

	// Verify caller has access to requested org
	if orgID != callerMSPID {
		return nil, fmt.Errorf("unauthorized: caller MSP %s cannot access org %s", callerMSPID, orgID)
	}

	// Retrieve identity from ledger
	identityKey := fmt.Sprintf("identity_%s_%s", orgID, userID)
	identityBytes, err := ctx.GetStub().GetState(identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve identity: %v", err)
	}

	if identityBytes == nil {
		return nil, fmt.Errorf("identity not found: %s", identityKey)
	}

	var identity BrickIdentity
	err = json.Unmarshal(identityBytes, &identity)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity: %v", err)
	}

	return &identity, nil
}

// UpdateIdentityStatus updates the status of an identity (suspend/activate/revoke)
func (bic *BrickIdentityContract) UpdateIdentityStatus(
	ctx contractapi.TransactionContextInterface,
	orgID string,
	userID string,
	newStatus string,
) error {
	
	// ABAC validation: Check for brick-admin attribute
	clientIdentity := ctx.GetClientIdentity()
	adminVal, found, err := clientIdentity.GetAttributeValue("brick-admin")
	if err != nil {
		return fmt.Errorf("failed to verify admin attribute: %v", err)
	}
	if !found || adminVal != "true" {
		return fmt.Errorf("unauthorized: caller lacks brick-admin attribute")
	}

	// Validate status value
	validStatuses := map[string]bool{
		"active":    true,
		"suspended": true,
		"revoked":   true,
	}
	if !validStatuses[newStatus] {
		return fmt.Errorf("invalid status: %s", newStatus)
	}

	// Retrieve current identity
	identityKey := fmt.Sprintf("identity_%s_%s", orgID, userID)
	identityBytes, err := ctx.GetStub().GetState(identityKey)
	if err != nil {
		return fmt.Errorf("failed to retrieve identity: %v", err)
	}

	if identityBytes == nil {
		return fmt.Errorf("identity not found")
	}

	var identity BrickIdentity
	err = json.Unmarshal(identityBytes, &identity)
	if err != nil {
		return fmt.Errorf("failed to unmarshal identity: %v", err)
	}

	// Update status
	identity.Status = newStatus
	stub := ctx.GetStub()
	txTime, err := stub.GetTxTimestamp()
	if err == nil {
		identity.UpdatedAt = txTime.String()
	}

	// Store updated identity
	updatedBytes, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("failed to marshal updated identity: %v", err)
	}

	err = ctx.GetStub().PutState(identityKey, updatedBytes)
	if err != nil {
		return fmt.Errorf("failed to update identity status: %v", err)
	}

	// Emit status change event
	statusChangeEvent := map[string]interface{}{
		"userID":    userID,
		"orgID":     orgID,
		"newStatus": newStatus,
	}
	statusChangeEventBytes, _ := json.Marshal(statusChangeEvent)
	ctx.GetStub().SetEvent("IdentityStatusChanged", statusChangeEventBytes)

	return nil
}

// QueryIdentitiesByOrg lists all identities in an organization
func (bic *BrickIdentityContract) QueryIdentitiesByOrg(
	ctx contractapi.TransactionContextInterface,
	orgID string,
) ([]*BrickIdentity, error) {
	
	// Verify caller's MSP matches requested org
	clientIdentity := ctx.GetClientIdentity()
	callerMSPID, err := clientIdentity.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get caller MSP ID: %v", err)
	}

	if orgID != callerMSPID {
		return nil, fmt.Errorf("unauthorized: cannot query org %s", orgID)
	}

	// Query ledger for all identities in org
	queryString := fmt.Sprintf(`{"selector": {"orgId": "%s"}}`, orgID)
	iterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to query identities: %v", err)
	}
	defer iterator.Close()

	var identities []*BrickIdentity
	for iterator.HasNext() {
		queryResult, err := iterator.Next()
		if err != nil {
			return nil, err
		}

		var identity BrickIdentity
		err = json.Unmarshal(queryResult.Value, &identity)
		if err != nil {
			return nil, err
		}

		identities = append(identities, &identity)
	}

	return identities, nil
}

// GetIdentityHistory retrieves the transaction history of an identity
func (bic *BrickIdentityContract) GetIdentityHistory(
	ctx contractapi.TransactionContextInterface,
	orgID string,
	userID string,
) ([]*map[string]interface{}, error) {
	
	identityKey := fmt.Sprintf("identity_%s_%s", orgID, userID)
	
	iterator, err := ctx.GetStub().GetHistoryForKey(identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %v", err)
	}
	defer iterator.Close()

	var history []*map[string]interface{}
	for iterator.HasNext() {
		historyRecord, err := iterator.Next()
		if err != nil {
			return nil, err
		}

		record := map[string]interface{}{
			"timestamp": historyRecord.Timestamp.String(),
			"isDelete":  historyRecord.IsDelete,
		}

		if !historyRecord.IsDelete {
			var identity BrickIdentity
			err := json.Unmarshal(historyRecord.Value, &identity)
			if err == nil {
				record["value"] = identity
			}
		}

		history = append(history, &record)
	}

	return history, nil
}

// Info provides metadata about the contract
func (bic *BrickIdentityContract) Info() metadata.InfoMetadata {
	return metadata.InfoMetadata{
		Version:     "1.0.0",
		Title:       "BRICK Identity Access Management Contract",
		Description: "Production-grade decentralized IAM engine powered by Hyperledger Fabric",
	}
}

// main is defined in brick.go which registers all contracts
