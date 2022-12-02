package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MembersPage contains page related metadata as well as list of members that
// belong to this page.
type MembersPage struct {
	Page
	Members []Client
}

// GroupsPage contains page related metadata as well as list
// of Groups that belong to the page.
type GroupsPage struct {
	Page
	Path      string
	Level     uint64
	ID        string
	Direction int64
	Groups    []Group
}

// Group represents the group of Clients.
// Indicates a level in tree hierarchy. Root node is level 1.
// Path in a tree consisting of group IDs
// Paths are unique per owner.
type Group struct {
	ID          string                 `json:"id"`
	OwnerID     string                 `json:"owner_id"`
	ParentID    string                 `json:"parent_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Level       int                    `json:"level"`
	Path        string                 `json:"path"`
	Children    []*Group               `json:"children"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Page contains page metadata that helps navigation.
type Page struct {
	Status     uint16
	Total      uint64
	Offset     uint64
	Limit      uint64
	Name       string
	Identifier string
	OwnerID    string
	Subject    string
	Object     string
	Action     string
	Metadata   map[string]interface{}
}

// CreateGroup creates a new clients group returning its id.
func (sdk csdk) CreateGroup(token string, g Group) (string, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", sdk.clientsURL, groupsEndpoint)
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

	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", groupsEndpoint))
	return id, nil
}

// ListGroups retrieves groups.
func (sdk csdk) ListGroups(token string, gp GroupsPage) (GroupsPage, error) {
	url, err := sdk.withQueryParamsGP(sdk.clientsURL, groupsEndpoint, gp)
	if err != nil {
		return GroupsPage{}, err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return GroupsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return GroupsPage{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GroupsPage{}, ErrFailedList
	}

	if err := json.NewDecoder(resp.Body).Decode(&gp); err != nil {
		return GroupsPage{}, err
	}

	return gp, nil
}

// ViewGroup retrieves data about the group identified by ID.
func (sdk csdk) ViewGroup(token, id string) (Group, error) {
	url := fmt.Sprintf("%s/%s/%s", sdk.clientsURL, groupsEndpoint, id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Group{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return Group{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Group{}, ErrFailedFetch
	}

	var g Group
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		return Group{}, err
	}

	return g, nil
}

// UpdateGroup updates the group identified by the provided ID.
func (sdk csdk) UpdateGroup(token string, g Group) error {
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.clientsURL, groupsEndpoint, g.ID)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
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

// ListMembers retrieves everything that is assigned to a group identified by groupID.
func (sdk csdk) ListMembers(token, groupID string, meta Page) (MembersPage, error) {
	url, err := sdk.withQueryParams(sdk.clientsURL, fmt.Sprintf("%s/%s/members", groupsEndpoint, groupID), meta)
	if err != nil {
		return MembersPage{}, err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return MembersPage{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return MembersPage{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MembersPage{}, ErrFailedList
	}

	var mp MembersPage
	if err := json.NewDecoder(resp.Body).Decode(&mp); err != nil {
		return MembersPage{}, err
	}

	return mp, nil
}

// RemoveGroup removes the group identified with the provided ID.
func (sdk csdk) RemoveGroup(token, id string) error {
	url := fmt.Sprintf("%s/%s/%s", sdk.clientsURL, groupsEndpoint, id)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return ErrFailedRemoval
	}

	return nil
}
