package sdk

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

type csdk struct {
	clientsURL string
	client     *http.Client
}

// ContentType represents all possible content types.
type ContentType string

const (
	clientsEndpoint              = "clients"
	groupsEndpoint               = "groups"
	policiesEndpoint             = "policies"
	ctJSON           ContentType = "application/json"
)

var (
	// ErrFailedCreation indicates that entity creation failed.
	ErrFailedCreation = errors.New("failed to create entity")

	// ErrFailedList indicates that entities list failed.
	ErrFailedList = errors.New("failed to list entities")

	// ErrFailedUpdate indicates that entity update failed.
	ErrFailedUpdate = errors.New("failed to update entity")

	// ErrFailedFetch indicates that fetching of entity data failed.
	ErrFailedFetch = errors.New("failed to fetch entity")

	// ErrFailedRemoval indicates that entity removal failed.
	ErrFailedRemoval = errors.New("failed to remove entity")

	// ErrFailedEnable indicates that client enable failed.
	ErrFailedEnable = errors.New("failed to enable client")

	// ErrFailedDisable indicates that client disable failed.
	ErrFailedDisable = errors.New("failed to disable client")
)

var _ SDK = (*csdk)(nil)

// SDK represents a wrapper around Clients service API to
// provide a simple and easy integration with the service.
type SDK interface {
	// CreateClient creates a new client returning its id.
	CreateClient(token string, client Client) (string, error)

	// ListClients returns page of clients.
	ListClients(token string, meta Page) (ClientsPage, error)

	// ListMemberships lists groups for client.
	ListMemberships(token, clientID string, meta GroupsPage) (MembershipsPage, error)

	// UpdateClient updates existing client.
	UpdateClient(token string, clients Client) error

	// GetClient returns client object by id.
	Client(token, id string) (Client, error)

	// EnableClient changes client status to enabled.
	EnableClient(token, id string) error

	// DisableClient changes client status to disabled - soft delete.
	DisableClient(token, id string) error

	// CreateGroup creates a new clients group returning its id.
	CreateGroup(token string, g Group) (string, error)

	// UpdateGroup updates the group identified by the provided ID.
	UpdateGroup(token string, g Group) error

	// ViewGroup retrieves data about the group identified by ID.
	ViewGroup(token, id string) (Group, error)

	// ListGroups retrieves groups.
	ListGroups(token string, g GroupsPage) (GroupsPage, error)

	// ListMembers retrieves everything that is assigned to a group identified by groupID.
	ListMembers(token, groupID string, pm Page) (MembersPage, error)

	// RemoveGroup removes the group identified with the provided ID.
	RemoveGroup(token, id string) error

	// AddPolicy creates a policy for the given subject, so that, after
	// AddPolicy, `subject` has a `relation` on `object`. Returns a non-nil
	// error in case of failures.
	AddPolicy(token string, p Policy) error

	// UpdatePolicy updates policies based on the given policy structure.
	UpdatePolicy(token string, p Policy) error

	// ListPolicies lists policies based on the given policy structure.
	ListPolicies(token string, pm Page) (PoliciesPage, error)

	// DeletePolicy removes a policy.
	DeletePolicy(token string, p Policy) error
}

// NewSDK returns new CoCoS SDK instance.
func NewSDK(URL string) SDK {
	return csdk{
		clientsURL: URL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (sdk csdk) sendRequest(req *http.Request, token string) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	req.Header.Add("Content-Type", string(ctJSON))

	return sdk.client.Do(req)
}

func (sdk csdk) withQueryParams(baseURL, endpoint string, pm Page) (string, error) {
	q, err := pm.query()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s?%s", baseURL, endpoint, q), nil
}

func (pm Page) query() (string, error) {
	q := url.Values{}
	q.Add("total", strconv.FormatUint(pm.Total, 10))
	q.Add("offset", strconv.FormatUint(pm.Offset, 10))
	q.Add("limit", strconv.FormatUint(pm.Limit, 10))
	if pm.Status != 0 {
		q.Add("status", strconv.FormatUint(uint64(pm.Status), 10))
	}
	if pm.Name != "" {
		q.Add("name", pm.Name)
	}
	if pm.Identifier != "" {
		q.Add("identifier", pm.Identifier)
	}
	if pm.OwnerID != "" {
		q.Add("ownerID", pm.OwnerID)
	}
	if pm.Subject != "" {
		q.Add("subject", pm.Subject)
	}
	if pm.Object != "" {
		q.Add("object", pm.Object)
	}
	if pm.Action != "" {
		q.Add("action", pm.Action)
	}
	if pm.Metadata != nil {
		md, err := json.Marshal(pm.Metadata)
		if err != nil {
			return "", err
		}
		q.Add("metadata", string(md))
	}
	return q.Encode(), nil
}

func (sdk csdk) withQueryParamsGP(baseURL, endpoint string, gp GroupsPage) (string, error) {
	q, err := gp.query()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s?%s", baseURL, endpoint, q), nil
}

func (gp GroupsPage) query() (string, error) {
	q := url.Values{}
	q.Add("total", strconv.FormatUint(gp.Total, 10))
	q.Add("offset", strconv.FormatUint(gp.Offset, 10))
	q.Add("limit", strconv.FormatUint(gp.Limit, 10))
	if gp.Level != 0 {
		q.Add("level", strconv.FormatUint(gp.Level, 10))
	}
	if gp.Name != "" {
		q.Add("name", gp.Name)
	}
	if gp.Metadata != nil {
		md, err := json.Marshal(gp.Metadata)
		if err != nil {
			return "", err
		}
		q.Add("metadata", string(md))
	}
	return q.Encode(), nil
}
