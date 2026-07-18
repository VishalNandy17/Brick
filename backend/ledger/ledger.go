package ledger

import (
	"fmt"
	"sync"
)

// Service defines ledger operations used by the API gateway.
type Service interface {
	Mode() string
	Healthy() bool
	RegisterIdentity(req RegistrationRequest) (*Identity, error)
	GetIdentity(orgID, userID string, caller CallerContext) (*Identity, error)
	UpdateIdentityStatus(orgID, userID, newStatus string, caller CallerContext) (*Identity, error)
	QueryIdentitiesByOrg(orgID string, caller CallerContext) ([]*Identity, error)
	QueryState(key string) (string, error)
	GetHistory(key string) ([]HistoryEntry, error)
	Invoke(function string, args map[string]interface{}) (map[string]interface{}, error)
}

var (
	instance Service
	initOnce sync.Once
	initErr  error
)

// InitOptions configures ledger initialization.
type InitOptions struct {
	Mode                  string
	DataPath              string
	ConnectionProfilePath string
}

// Initialize creates the active ledger service singleton.
func Initialize(opts InitOptions) error {
	initOnce.Do(func() {
		mode := opts.Mode
		if mode == "" {
			mode = "cloud"
		}

		switch mode {
		case "cloud", "simulator":
			instance, initErr = NewCloudLedger(opts.DataPath)
		case "fabric":
			profilePath := opts.ConnectionProfilePath
			if profilePath == "" {
				profilePath = "../connection.json"
			}
			instance, initErr = NewFabricLedger(profilePath)
		default:
			initErr = fmt.Errorf("unsupported ledger mode: %s", mode)
		}
	})
	return initErr
}

// Get returns the initialized ledger service.
func Get() Service {
	return instance
}
