package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Policy represents an argument struct for making a policy related function calls.
type Policy struct {
	OwnerID   string    `json:"owner_id"`
	Subject   string    `json:"subject"`
	Object    string    `json:"object"`
	Actions   []string  `json:"actions"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PoliciesPage contains a page of policies.
type PoliciesPage struct {
	Page
	Policies []Policy
}

// AddPolicy creates a policy for the given subject, so that, after
// AddPolicy, `subject` has a `relation` on `object`. Returns a non-nil
// error in case of failures.
func (sdk csdk) AddPolicy(token string, p Policy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s", sdk.clientsURL, policiesEndpoint)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return ErrFailedCreation
	}

	return nil
}

// UpdatePolicy updates policies based on the given policy structure.
func (sdk csdk) UpdatePolicy(token string, p Policy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s/%s/%s", sdk.clientsURL, policiesEndpoint, p.Object, p.Subject)

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

// ListPolicy lists policies based on the given policy structure.
func (sdk csdk) ListPolicies(token string, pm Page) (PoliciesPage, error) {
	url, err := sdk.withQueryParams(sdk.clientsURL, policiesEndpoint, pm)
	if err != nil {
		return PoliciesPage{}, err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return PoliciesPage{}, err
	}

	resp, err := sdk.sendRequest(req, token)
	if err != nil {
		return PoliciesPage{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PoliciesPage{}, ErrFailedList
	}

	var pp PoliciesPage
	if err := json.NewDecoder(resp.Body).Decode(&pp); err != nil {
		return PoliciesPage{}, err
	}

	return pp, nil
}

// DeletePolicy removes a policy.
func (sdk csdk) DeletePolicy(token string, p Policy) error {
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.clientsURL, policiesEndpoint, p.Object, p.Subject)

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
