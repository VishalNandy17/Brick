package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type cloudState struct {
	Identities map[string]*Identity   `json:"identities"`
	Assets     map[string]string      `json:"assets"`
	History    map[string][]HistoryEntry `json:"history"`
	Events     []LedgerEvent          `json:"events"`
}

// CloudLedger implements chaincode-equivalent identity logic without Docker.
// Data persists to a JSON file so the app works on low-spec machines.
type CloudLedger struct {
	mu       sync.RWMutex
	dataPath string
	state    cloudState
}

func NewCloudLedger(dataPath string) (*CloudLedger, error) {
	if dataPath == "" {
		dataPath = "../data/cloud-ledger.json"
	}

	cl := &CloudLedger{
		dataPath: dataPath,
		state: cloudState{
			Identities: make(map[string]*Identity),
			Assets:     make(map[string]string),
			History:    make(map[string][]HistoryEntry),
			Events:     []LedgerEvent{},
		},
	}

	if err := cl.load(); err != nil {
		return nil, err
	}

	// Seed demo admin identity for first-run experience.
	if len(cl.state.Identities) == 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		hashInput := fmt.Sprintf("admin:Org1MSP:%d", time.Now().Unix())
		hash := sha256.Sum256([]byte(hashInput))
		key := identityKey("Org1MSP", "admin")
		cl.state.Identities[key] = &Identity{
			UserID:       "admin",
			OrgID:        "Org1MSP",
			Role:         "admin",
			Status:       "active",
			IdentityHash: hex.EncodeToString(hash[:]),
			MSPID:        "Org1MSP",
			Attributes:   map[string]string{"brick-admin": "true"},
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		cl.appendHistory(key, cl.state.Identities[key], "genesis")
		_ = cl.persist()
	}

	return cl, nil
}

func (cl *CloudLedger) Mode() string   { return "cloud" }
func (cl *CloudLedger) Healthy() bool  { return true }

func normalizeOrg(org string) string {
	org = strings.TrimSpace(org)
	return strings.TrimSuffix(org, "MSP")
}

func (cl *CloudLedger) RegisterIdentity(req RegistrationRequest) (*Identity, error) {
	if !req.Caller.IsAdmin {
		return nil, fmt.Errorf("caller lacks brick-admin attribute for identity registration")
	}

	validRoles := map[string]bool{"admin": true, "user": true, "auditor": true}
	if !validRoles[req.Role] {
		return nil, fmt.Errorf("invalid role: %s", req.Role)
	}

	callerMSPID := req.Caller.MSPID
	if callerMSPID == "" {
		callerMSPID = req.OrgID
	}
	if !req.Caller.IsAdmin && normalizeOrg(req.OrgID) != normalizeOrg(callerMSPID) {
		return nil, fmt.Errorf("organization mismatch: requested %s, caller MSP %s", req.OrgID, callerMSPID)
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	key := identityKey(req.OrgID, req.UserID)
	if existing, exists := cl.state.Identities[key]; exists {
		return existing, nil
	}
	keyMSP := identityKey(normalizeOrg(req.OrgID)+"MSP", req.UserID)
	if existing, exists := cl.state.Identities[keyMSP]; exists {
		return existing, nil
	}

	now := time.Now().UTC()
	hashInput := fmt.Sprintf("%s:%s:%d", req.UserID, req.OrgID, now.Unix())
	hash := sha256.Sum256([]byte(hashInput))

	attrs := req.Attributes
	if attrs == nil {
		attrs = map[string]string{}
	}

	identity := &Identity{
		UserID:       req.UserID,
		OrgID:        req.OrgID,
		Role:         req.Role,
		Status:       "active",
		IdentityHash: hex.EncodeToString(hash[:]),
		MSPID:        callerMSPID,
		Attributes:   attrs,
		CreatedAt:    now.Format(time.RFC3339),
		UpdatedAt:    now.Format(time.RFC3339),
	}

	cl.state.Identities[key] = identity
	cl.appendHistory(key, identity, fmt.Sprintf("tx_%d", now.UnixNano()))
	cl.state.Events = append(cl.state.Events, LedgerEvent{
		Type: "IdentityRegistered",
		Payload: map[string]string{
			"userId": req.UserID,
			"orgId":  req.OrgID,
			"role":   req.Role,
		},
		Timestamp: now,
	})

	if err := cl.persist(); err != nil {
		return nil, err
	}
	return identity, nil
}

func (cl *CloudLedger) GetIdentity(orgID, userID string, caller CallerContext) (*Identity, error) {
	callerMSPID := caller.MSPID
	if callerMSPID == "" {
		callerMSPID = caller.OrgID
	}
	if !caller.IsAdmin && normalizeOrg(orgID) != normalizeOrg(callerMSPID) {
		return nil, fmt.Errorf("unauthorized: caller MSP %s cannot access org %s", callerMSPID, orgID)
	}

	cl.mu.RLock()
	defer cl.mu.RUnlock()

	key := identityKey(orgID, userID)
	identity, ok := cl.state.Identities[key]
	if !ok {
		keyMSP := identityKey(normalizeOrg(orgID)+"MSP", userID)
		identity, ok = cl.state.Identities[keyMSP]
	}
	if !ok {
		return nil, fmt.Errorf("identity not found: %s", key)
	}
	return identity, nil
}

func (cl *CloudLedger) UpdateIdentityStatus(orgID, userID, newStatus string, caller CallerContext) (*Identity, error) {
	if !caller.IsAdmin {
		return nil, fmt.Errorf("unauthorized: caller lacks brick-admin attribute")
	}

	validStatuses := map[string]bool{"active": true, "suspended": true, "revoked": true}
	if !validStatuses[newStatus] {
		return nil, fmt.Errorf("invalid status: %s", newStatus)
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	key := identityKey(orgID, userID)
	identity, ok := cl.state.Identities[key]
	if !ok {
		return nil, fmt.Errorf("identity not found")
	}

	now := time.Now().UTC()
	identity.Status = newStatus
	identity.UpdatedAt = now.Format(time.RFC3339)
	cl.appendHistory(key, identity, fmt.Sprintf("tx_%d", now.UnixNano()))

	if err := cl.persist(); err != nil {
		return nil, err
	}
	return identity, nil
}

func (cl *CloudLedger) QueryIdentitiesByOrg(orgID string, caller CallerContext) ([]*Identity, error) {
	callerMSPID := caller.MSPID
	if callerMSPID == "" {
		callerMSPID = caller.OrgID
	}
	if orgID != callerMSPID {
		return nil, fmt.Errorf("unauthorized: cannot query org %s", orgID)
	}

	cl.mu.RLock()
	defer cl.mu.RUnlock()

	var identities []*Identity
	for _, id := range cl.state.Identities {
		if id.OrgID == orgID {
			identities = append(identities, id)
		}
	}
	return identities, nil
}

func (cl *CloudLedger) QueryState(key string) (string, error) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if val, ok := cl.state.Assets[key]; ok {
		return val, nil
	}
	if id, ok := cl.state.Identities[key]; ok {
		bytes, err := json.Marshal(id)
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}
	return "", fmt.Errorf("key not found: %s", key)
}

func (cl *CloudLedger) GetHistory(key string) ([]HistoryEntry, error) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	history, ok := cl.state.History[key]
	if !ok || len(history) == 0 {
		return []HistoryEntry{}, nil
	}
	return history, nil
}

func (cl *CloudLedger) Invoke(function string, args map[string]interface{}) (map[string]interface{}, error) {
	switch function {
	case "CreateAsset":
		key, _ := args["key"].(string)
		value, _ := args["value"].(string)
		if key == "" {
			return nil, fmt.Errorf("key is required")
		}
		cl.mu.Lock()
		cl.state.Assets[key] = value
		cl.appendHistory(key, value, fmt.Sprintf("tx_%d", time.Now().UnixNano()))
		cl.mu.Unlock()
		_ = cl.persist()
		return map[string]interface{}{"key": key, "value": value}, nil
	default:
		return nil, fmt.Errorf("unsupported function: %s", function)
	}
}

func (cl *CloudLedger) load() error {
	if err := os.MkdirAll(filepath.Dir(cl.dataPath), 0o755); err != nil {
		return err
	}

	data, err := os.ReadFile(cl.dataPath)
	if os.IsNotExist(err) {
		return cl.persist()
	}
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &cl.state)
}

func (cl *CloudLedger) persist() error {
	if err := os.MkdirAll(filepath.Dir(cl.dataPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cl.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cl.dataPath, data, 0o644)
}

func (cl *CloudLedger) appendHistory(key string, value interface{}, txID string) {
	cl.state.History[key] = append(cl.state.History[key], HistoryEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Value:     value,
		TxID:      txID,
	})
}

func identityKey(orgID, userID string) string {
	return fmt.Sprintf("identity_%s_%s", orgID, userID)
}
