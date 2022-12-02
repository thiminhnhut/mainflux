package clients

import (
	"context"
	"time"
)

// Credentials represent client credentials: its
// "identity" which can be a username, email, generated name;
// and "secret" which can be a password or access token.
type Credentials struct {
	Identity string `json:"identity"` // username or generated login ID
	Secret   string `json:"secret"`   // password or token
}

// Client represents generic Client.
type Client struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Tags        []string    `json:"tags,omitempty"`
	Owner       string      `json:"owner,omitempty"` // nullable
	Credentials Credentials `json:"credentials"`
	Metadata    Metadata    `json:"metadata"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Status      uint16      `json:"status"` // 1 for enabled, 2 for disabled and 3 for all as 0 is usually null
}

// ClientsPage contains page related metadata as well as list
// of Clients that belong to the page.
type ClientsPage struct {
	Page
	Clients []Client
}

// MembershipsPage contains page related metadata as well as list of memberships that
// belong to this page.
type MembershipsPage struct {
	Page
	Memberships []Group
}

// ClientRepository specifies an account persistence API.
type ClientRepository interface {
	// Save persists the client account. A non-nil error is returned to indicate
	// operation failure.
	Save(ctx context.Context, client Client) (Client, error)

	// RetrieveByID retrieves client by its unique ID.
	RetrieveByID(ctx context.Context, id string) (Client, error)

	// RetrieveByIdentity retrieves client by its unique credentials
	RetrieveByIdentity(ctx context.Context, identity string) (Client, error)

	// RetrieveAll retrieves all clients.
	RetrieveAll(ctx context.Context, pm Page) (ClientsPage, error)

	// Memberships retrieves everything that is assigned to a group identified by clientID.
	Memberships(ctx context.Context, clientID string, gm GroupsPage) (MembershipsPage, error)

	// Update updates the client name and metadata.
	Update(ctx context.Context, client Client) (Client, error)

	// UpdateTags updates the client tags.
	UpdateTags(ctx context.Context, client Client) (Client, error)

	// UpdateIdentity updates identity for client with given id.
	UpdateIdentity(ctx context.Context, client Client) (Client, error)

	// UpdateSecret updates secret for client with given identity.
	UpdateSecret(ctx context.Context, client Client) (Client, error)

	// UpdateOwner updates owner for client with given id.
	UpdateOwner(ctx context.Context, client Client) (Client, error)

	// ChangeStatus changes client status to enabled or disabled
	ChangeStatus(ctx context.Context, id string, status uint16) (Client, error)
}

// ClientService specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type ClientService interface {
	// RegisterClient creates new client. In case of the failed registration, a
	// non-nil error value is returned.
	RegisterClient(ctx context.Context, token string, client Client) (Client, error)

	// LoginClient authenticates the client given its credentials. Successful
	// authentication generates new access token. Failed invocations are
	// identified by the non-nil error values in the response.

	// ViewClient retrieves client info for a given client ID and an authorized token.
	ViewClient(ctx context.Context, token, id string) (Client, error)

	// ListClients retrieves clients list for a valid auth token.
	ListClients(ctx context.Context, token string, pm Page) (ClientsPage, error)

	// ListMemberships retrieves everything that is assigned to a group identified by clientID.
	ListMemberships(ctx context.Context, token, clientID string, gm GroupsPage) (MembershipsPage, error)

	// UpdateClient updates the client's name and metadata.
	UpdateClient(ctx context.Context, token string, client Client) (Client, error)

	// UpdateClientTags updates the client's tags.
	UpdateClientTags(ctx context.Context, token string, client Client) (Client, error)

	// UpdateClientIdentity updates the client's identity
	UpdateClientIdentity(ctx context.Context, token, id, identity string) (Client, error)

	// UpdateClientSecret updates the client's secret
	UpdateClientSecret(ctx context.Context, token, oldSecret, newSecret string) (Client, error)

	// UpdateClientOwner updates the client's owner.
	UpdateClientOwner(ctx context.Context, token string, client Client) (Client, error)

	// EnableClient logically enableds the client identified with the provided ID
	EnableClient(ctx context.Context, token, id string) (Client, error)

	// DisableClient logically disables the client identified with the provided ID
	DisableClient(ctx context.Context, token, id string) (Client, error)
}
