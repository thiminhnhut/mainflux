package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Client represents generic Client.
type Client struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Credentials Credentials            `json:"credentials"`
	Tags        []string               `json:"tags,omitempty"`
	Owner       string                 `json:"owner,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Status      uint16                 `json:"status"`
}

// Credentials represent client credentials: its
// "identity" which can be a username, email, generated name;
// and "secret" which can be a password or access token.
type Credentials struct {
	Identity string `json:"identity"` // username or generated login ID
	Secret   string `json:"secret"`   // password or token
}

// ClientsPage contains page related metadata as well as list
// of Clients that belong to the page.
type ClientsPage struct {
	Client []Client `json:"clients"`
	pageRes
}

// MembershipsPage contains page related metadata as well as list of memberships that
// belong to this page.
type MembershipsPage struct {
	Page
	Memberships []Group
}

// CreateClient creates a new client returning its id.
func (sdk csdk) CreateClient(token string, c Client) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", sdk.clientsURL, clientsEndpoint)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", ErrFailedCreation
	}

	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", clientsEndpoint))
	return id, nil
}

// ListClients returns page of clients.
func (sdk csdk) ListClients(token string, pm Page) (ClientsPage, error) {
	url, err := sdk.withQueryParams(sdk.clientsURL, clientsEndpoint, pm)
	if err != nil {
		return ClientsPage{}, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ClientsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return ClientsPage{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ClientsPage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return ClientsPage{}, ErrFailedList
	}
	var lc ClientsPage
	if err := json.Unmarshal(body, &lc); err != nil {
		return ClientsPage{}, err
	}

	return lc, nil
}

// ListMemberships lists groups for client.
func (sdk csdk) ListMemberships(token, clientID string, meta GroupsPage) (MembershipsPage, error) {
	url, err := sdk.withQueryParamsGP(sdk.clientsURL, fmt.Sprintf("%s/%s/memberships", clientsEndpoint, clientID), meta)
	if err != nil {
		return MembershipsPage{}, err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return MembershipsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return MembershipsPage{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MembershipsPage{}, ErrFailedList
	}

	var mp MembershipsPage
	if err := json.NewDecoder(resp.Body).Decode(&mp); err != nil {
		return MembershipsPage{}, err
	}

	return mp, nil
}

// GetClient returns client object by id.
func (sdk csdk) Client(token, id string) (Client, error) {
	url := fmt.Sprintf("%s/%s/%s", sdk.clientsURL, clientsEndpoint, id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Client{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return Client{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Client{}, ErrFailedFetch
	}
	var c Client
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return Client{}, err
	}

	return c, nil
}

// UpdateClient updates existing client.
func (sdk csdk) UpdateClient(token string, c Client) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s", sdk.clientsURL, clientsEndpoint)

	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return ErrFailedUpdate
	}

	return nil
}

// EnableClient changes client status to enabled.
func (sdk csdk) EnableClient(token, id string) error {
	url := fmt.Sprintf("%s/%s/%s/enable", sdk.clientsURL, clientsEndpoint, id)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return ErrFailedEnable
	}

	return nil
}

// DisableClient changes client status to disabled - soft delete.
func (sdk csdk) DisableClient(token, id string) error {
	url := fmt.Sprintf("%s/%s/%s/disable", sdk.clientsURL, clientsEndpoint, id)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return ErrFailedDisable
	}

	return nil
}
