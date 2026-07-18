package ledger

import "time"

// Identity mirrors the on-chain BrickIdentity record.
type Identity struct {
	UserID       string            `json:"userId"`
	OrgID        string            `json:"orgId"`
	Role         string            `json:"role"`
	Status       string            `json:"status"`
	IdentityHash string            `json:"identityHash"`
	MSPID        string            `json:"mspId"`
	Attributes   map[string]string `json:"attributes"`
	CreatedAt    string            `json:"createdAt"`
	UpdatedAt    string            `json:"updatedAt"`
}

// HistoryEntry represents a ledger history record.
type HistoryEntry struct {
	Timestamp string      `json:"timestamp"`
	Value     interface{} `json:"value"`
	TxID      string      `json:"txid"`
	IsDelete  bool        `json:"isDelete,omitempty"`
}

// CallerContext carries authenticated caller metadata.
type CallerContext struct {
	UserIdentity string
	OrgID        string
	MSPID        string
	IsAdmin      bool
}

// RegistrationRequest is the input for identity enrollment.
type RegistrationRequest struct {
	UserID     string
	OrgID      string
	Role       string
	Attributes map[string]string
	Caller     CallerContext
}

// LedgerEvent is emitted for audit trails.
type LedgerEvent struct {
	Type      string    `json:"type"`
	Payload   any       `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}
