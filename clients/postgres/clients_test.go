package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/clients/postgres"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/ulid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	maxNameSize = 254
)

var (
	idProvider     = ulid.New()
	invalidName    = strings.Repeat("m", maxNameSize+10)
	password       = "$tr0ngPassw0rd"
	clientIdentity = "client-identity@example.com"
	clientName     = "client name"
	wrongName      = "wrong-name"
	wrongID        = "wrong-id"
)

func generateULID(t *testing.T) string {
	ulid, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	return ulid
}
func TestClientsSave(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	uid := generateULID(t)

	cases := []struct {
		desc   string
		client clients.Client
		err    error
	}{
		{
			desc: "add new client successfully",
			client: clients.Client{
				ID:   uid,
				Name: clientName,
				Credentials: clients.Credentials{
					Identity: clientIdentity,
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: nil,
		},
		{
			desc: "add new client with an owner",
			client: clients.Client{
				ID:    generateULID(t),
				Owner: uid,
				Name:  clientName,
				Credentials: clients.Credentials{
					Identity: "withowner-client@example.com",
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: nil,
		},
		{
			desc: "add client with duplicate client identity",
			client: clients.Client{
				ID:   generateULID(t),
				Name: clientName,
				Credentials: clients.Credentials{
					Identity: clientIdentity,
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: errors.ErrConflict,
		},
		{
			desc: "add client with invalid client id",
			client: clients.Client{
				ID:   invalidName,
				Name: clientName,
				Credentials: clients.Credentials{
					Identity: "invalidid-client@example.com",
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "add client with invalid client name",
			client: clients.Client{
				ID:   generateULID(t),
				Name: invalidName,
				Credentials: clients.Credentials{
					Identity: "invalidname-client@example.com",
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "add client with non-existent client owner",
			client: clients.Client{
				ID:    generateULID(t),
				Owner: generateULID(t),
				Credentials: clients.Credentials{
					Identity: "nonexistentowner-client@example.com",
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: nil,
		},
		{
			desc: "add client with invalid client owner",
			client: clients.Client{
				ID:    generateULID(t),
				Owner: invalidName,
				Credentials: clients.Credentials{
					Identity: "invalidowner-client@example.com",
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "add client with invalid client identity",
			client: clients.Client{
				ID:   generateULID(t),
				Name: clientName,
				Credentials: clients.Credentials{
					Identity: invalidName,
					Secret:   password,
				},
				Metadata: clients.Metadata{},
				Status:   clients.EnabledStatusKey,
			},
			err: errors.ErrMalformedEntity,
		},
	}
	for _, tc := range cases {
		rClient, err := repo.Save(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		rClient.Credentials.Secret = tc.client.Credentials.Secret
		if err == nil {
			assert.Equal(t, tc.client, rClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.client, rClient))
		}
	}
}

func TestClientsRetrieveByID(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client := clients.Client{
		ID:   generateULID(t),
		Name: clientName,
		Credentials: clients.Credentials{
			Identity: clientIdentity,
			Secret:   password,
		},
		Status: clients.EnabledStatusKey,
	}

	client, err := repo.Save(context.Background(), client)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := map[string]struct {
		ID  string
		err error
	}{
		"retrieve existing client":     {client.ID, nil},
		"retrieve non-existing client": {wrongID, errors.ErrNotFound},
	}

	for desc, tc := range cases {
		cli, err := repo.RetrieveByID(context.Background(), tc.ID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
		if err == nil {
			assert.Equal(t, client.ID, cli.ID, fmt.Sprintf("retrieve client by ID : client ID : expected %s got %s\n", client.ID, cli.ID))
			assert.Equal(t, client.Name, cli.Name, fmt.Sprintf("retrieve client by ID : client Name : expected %s got %s\n", client.Name, cli.Name))
			assert.Equal(t, client.Credentials.Identity, cli.Credentials.Identity, fmt.Sprintf("retrieve client by ID : client Identity : expected %s got %s\n", client.Credentials.Identity, cli.Credentials.Identity))
			assert.Equal(t, client.Status, cli.Status, fmt.Sprintf("retrieve client by ID : client Status : expected %d got %d\n", client.Status, cli.Status))
		}
	}
}

func TestClientsRetrieveByIdentity(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client := clients.Client{
		ID:   generateULID(t),
		Name: clientName,
		Credentials: clients.Credentials{
			Identity: clientIdentity,
			Secret:   password,
		},
		Status: clients.EnabledStatusKey,
	}

	_, err := repo.Save(context.Background(), client)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := map[string]struct {
		identity string
		err      error
	}{
		"retrieve existing client":     {clientIdentity, nil},
		"retrieve non-existing client": {wrongID, errors.ErrNotFound},
	}

	for desc, tc := range cases {
		_, err := repo.RetrieveByIdentity(context.Background(), tc.identity)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
	}
}

func TestClientsRetrieveAll(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)
	var nClients = uint64(200)
	var ownerID string

	meta := clients.Metadata{
		"admin": "true",
	}
	wrongMeta := clients.Metadata{
		"admin": "false",
	}
	var expectedClients = []clients.Client{}

	for i := uint64(0); i < nClients; i++ {
		identity := fmt.Sprintf("TestRetrieveAll%d@example.com", i)
		client := clients.Client{
			ID:   generateULID(t),
			Name: identity,
			Credentials: clients.Credentials{
				Identity: identity,
				Secret:   password,
			},
			Metadata: clients.Metadata{},
			Status:   clients.EnabledStatusKey,
		}
		if i == 1 {
			ownerID = client.ID
		}
		if i == 3 {
			client.Owner = ownerID
			client.Metadata = meta
			client.Tags = []string{"Test"}
		}
		if i == 199 {
			client.Status = clients.DisabledStatusKey
		}
		_, err := repo.Save(context.Background(), client)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		client.Credentials.Secret = ""
		expectedClients = append(expectedClients, client)
	}

	cases := map[string]struct {
		size     uint64
		pm       clients.Page
		response []clients.Client
	}{
		"retrieve all clients empty page": {
			pm:       clients.Page{},
			response: []clients.Client{},
			size:     0,
		},
		"retrieve all clients": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
			},
			response: expectedClients,
			size:     200,
		},
		"retrieve all clients with limit": {
			pm: clients.Page{
				Offset: 0,
				Limit:  50,
			},
			response: expectedClients[0:50],
			size:     50,
		},
		"retrieve all clients with offset": {
			pm: clients.Page{
				Offset: 10,
				Limit:  nClients,
			},
			response: expectedClients[10:200],
			size:     190,
		},
		"retrieve all clients with limit and offset": {
			pm: clients.Page{
				Offset: 50,
				Limit:  50,
			},
			response: expectedClients[50:100],
			size:     50,
		},
		"retrieve all clients with limit and offset not full": {
			pm: clients.Page{
				Offset: 170,
				Limit:  50,
			},
			response: expectedClients[170:200],
			size:     30,
		},
		"retrieve all clients by metadata": {
			pm: clients.Page{
				Offset:   0,
				Limit:    nClients,
				Total:    nClients,
				Metadata: meta,
			},
			response: []clients.Client{expectedClients[3]},
			size:     1,
		},
		"retrieve clients by wrong metadata": {
			pm: clients.Page{
				Offset:   0,
				Limit:    nClients,
				Total:    nClients,
				Metadata: wrongMeta,
			},
			response: []clients.Client{},
			size:     0,
		},
		"retrieve all clients by name": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Name:   "TestRetrieveAll3@example.com",
			},
			response: []clients.Client{expectedClients[3]},
			size:     1,
		},
		"retrieve clients by wrong name": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Name:   wrongName,
			},
			response: []clients.Client{},
			size:     0,
		},
		"retrieve all clients by owner": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nClients,
				Total:   nClients,
				OwnerID: ownerID,
			},
			response: []clients.Client{expectedClients[3]},
			size:     1,
		},
		"retrieve clients by wrong owner": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nClients,
				Total:   nClients,
				OwnerID: wrongID,
			},
			response: []clients.Client{},
			size:     0,
		},
		"retrieve all clients by enabled status": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Status: clients.EnabledStatusKey,
			},
			response: expectedClients[:199],
			size:     199,
		},
		"retrieve all clients by disabled status": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Status: clients.DisabledStatusKey,
			},
			response: []clients.Client{expectedClients[199]},
			size:     1,
		},
		"retrieve all clients by combined status": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Status: clients.AllClientsStatusKey,
			},
			response: expectedClients,
			size:     200,
		},
		"retrieve clients by the wrong status": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Status: 10,
			},
			response: []clients.Client{},
			size:     0,
		},
		"retrieve all clients by tags": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Tags:   "Test",
			},
			response: []clients.Client{expectedClients[3]},
			size:     1,
		},
		"retrieve clients by wrong tags": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nClients,
				Total:  nClients,
				Tags:   "wrongTags",
			},
			response: []clients.Client{},
			size:     0,
		},
	}
	for desc, tc := range cases {
		page, err := repo.RetrieveAll(context.Background(), tc.pm)
		size := uint64(len(page.Clients))
		assert.ElementsMatch(t, page.Clients, tc.response, fmt.Sprintf("%s: expected %v got %v\n", desc, tc.response, page.Clients))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", desc, tc.size, size))
		assert.Nil(t, err, fmt.Sprintf("%s: expected no error got %d\n", desc, err))
	}
}

func TestClientsUpdateMetadata(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "enabled-client",
		Credentials: clients.Credentials{
			Identity: "client1-update@example.com",
			Secret:   password,
		},
		Metadata: clients.Metadata{
			"name": "enabled-client",
		},
		Tags:   []string{"enabled", "tag1"},
		Status: clients.EnabledStatusKey,
	}

	client2 := clients.Client{
		ID:   generateULID(t),
		Name: "disabled-client",
		Credentials: clients.Credentials{
			Identity: "client2-update@example.com",
			Secret:   password,
		},
		Metadata: clients.Metadata{
			"name": "disabled-client",
		},
		Tags:   []string{"disabled", "tag1"},
		Status: clients.DisabledStatusKey,
	}

	client1, err := repo.Save(context.Background(), client1)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new client with metadata: expected %v got %s\n", nil, err))
	client2, err = repo.Save(context.Background(), client2)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new disabled client: expected %v got %s\n", nil, err))

	ucases := []struct {
		desc   string
		update string
		client clients.Client
		err    error
	}{
		{
			desc:   "update metadata for enabled client",
			update: "metadata",
			client: clients.Client{
				ID: client1.ID,
				Metadata: clients.Metadata{
					"update": "metadata",
				},
			},
			err: nil,
		},
		{
			desc:   "update metadata for disabled client",
			update: "metadata",
			client: clients.Client{
				ID: client2.ID,
				Metadata: clients.Metadata{
					"update": "metadata",
				},
			},
			err: errors.ErrNotFound,
		},
		{
			desc:   "update name for enabled client",
			update: "name",
			client: clients.Client{
				ID:   client1.ID,
				Name: "updated name",
			},
			err: nil,
		},
		{
			desc:   "update name for disabled client",
			update: "name",
			client: clients.Client{
				ID:   client2.ID,
				Name: "updated name",
			},
			err: errors.ErrNotFound,
		},
		{
			desc:   "update name and metadata for enabled client",
			update: "both",
			client: clients.Client{
				ID:   client1.ID,
				Name: "updated name and metadata",
				Metadata: clients.Metadata{
					"update": "name and metadata",
				},
			},
			err: nil,
		},
		{
			desc:   "update name and metadata for a disabled client",
			update: "both",
			client: clients.Client{
				ID:   client2.ID,
				Name: "updated name and metadata",
				Metadata: clients.Metadata{
					"update": "name and metadata",
				},
			},
			err: errors.ErrNotFound,
		},
		{
			desc:   "update metadata for invalid client",
			update: "metadata",
			client: clients.Client{
				ID: wrongID,
				Metadata: clients.Metadata{
					"update": "metadata",
				},
			},
			err: errors.ErrNotFound,
		},
		{
			desc:   "update name for invalid client",
			update: "name",
			client: clients.Client{
				ID:   wrongID,
				Name: "updated name",
			},
			err: errors.ErrNotFound,
		},
		{
			desc:   "update name and metadata for invalid client",
			update: "both",
			client: clients.Client{
				ID:   client2.ID,
				Name: "updated name and metadata",
				Metadata: clients.Metadata{
					"update": "name and metadata",
				},
			},
			err: errors.ErrNotFound,
		},
	}
	for _, tc := range ucases {
		expected, err := repo.Update(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			if tc.client.Name != "" {
				assert.Equal(t, expected.Name, tc.client.Name, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected.Name, tc.client.Name))
			}
			if tc.client.Metadata != nil {
				assert.Equal(t, expected.Metadata, tc.client.Metadata, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected.Metadata, tc.client.Metadata))
			}

		}
	}
}

func TestClientsUpdateTags(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "enabled-client-with-tags",
		Credentials: clients.Credentials{
			Identity: "client1-update-tags@example.com",
			Secret:   password,
		},
		Tags:   []string{"test", "enabled"},
		Status: clients.EnabledStatusKey,
	}
	client2 := clients.Client{
		ID:   generateULID(t),
		Name: "disabled-client-with-tags",
		Credentials: clients.Credentials{
			Identity: "client2-update-tags@example.com",
			Secret:   password,
		},
		Tags:   []string{"test", "disabled"},
		Status: clients.DisabledStatusKey,
	}

	client1, err := repo.Save(context.Background(), client1)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new client with tags: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client1.ID, client1.ID, fmt.Sprintf("add new client with tags: expected %v got %s\n", nil, err))
	}
	client2, err = repo.Save(context.Background(), client2)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new disabled client with tags: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client2.ID, client2.ID, fmt.Sprintf("add new disabled client with tags: expected %v got %s\n", nil, err))
	}
	ucases := []struct {
		desc   string
		client clients.Client
		err    error
	}{
		{
			desc: "update tags for enabled client",
			client: clients.Client{
				ID:   client1.ID,
				Tags: []string{"updated"},
			},
			err: nil,
		},
		{
			desc: "update tags for disabled client",
			client: clients.Client{
				ID:   client2.ID,
				Tags: []string{"updated"},
			},
			err: errors.ErrNotFound,
		},
		{
			desc: "update tags for invalid client",
			client: clients.Client{
				ID:   wrongID,
				Tags: []string{"updated"},
			},
			err: errors.ErrNotFound,
		},
	}
	for _, tc := range ucases {
		expected, err := repo.UpdateTags(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.client.Tags, expected.Tags, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.client.Tags, expected.Tags))
		}
	}
}

func TestClientsUpdateSecret(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "enabled-client",
		Credentials: clients.Credentials{
			Identity: "client1-update@example.com",
			Secret:   password,
		},
		Status: clients.EnabledStatusKey,
	}
	client2 := clients.Client{
		ID:   generateULID(t),
		Name: "disabled-client",
		Credentials: clients.Credentials{
			Identity: "client2-update@example.com",
			Secret:   password,
		},
		Status: clients.DisabledStatusKey,
	}

	rClient1, err := repo.Save(context.Background(), client1)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new client: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client1.ID, rClient1.ID, fmt.Sprintf("add new client: expected %v got %s\n", nil, err))
	}
	rClient2, err := repo.Save(context.Background(), client2)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new disabled client: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client2.ID, rClient2.ID, fmt.Sprintf("add new disabled client: expected %v got %s\n", nil, err))
	}

	ucases := []struct {
		desc   string
		client clients.Client
		err    error
	}{
		{
			desc: "update secret for enabled client",
			client: clients.Client{
				ID: client1.ID,
				Credentials: clients.Credentials{
					Identity: "client1-update@example.com",
					Secret:   "newpassword",
				},
			},
			err: nil,
		},
		{
			desc: "update secret for disabled client",
			client: clients.Client{
				ID: client2.ID,
				Credentials: clients.Credentials{
					Identity: "client2-update@example.com",
					Secret:   "newpassword",
				},
			},
			err: errors.ErrNotFound,
		},
		{
			desc: "update secret for invalid client",
			client: clients.Client{
				ID: wrongID,
				Credentials: clients.Credentials{
					Identity: "client3-update@example.com",
					Secret:   "newpassword",
				},
			},
			err: errors.ErrNotFound,
		},
	}
	for _, tc := range ucases {
		_, err := repo.UpdateSecret(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			c, err := repo.RetrieveByIdentity(context.Background(), tc.client.Credentials.Identity)
			require.Nil(t, err, fmt.Sprintf("retrieve client by id during update of secret unexpected error: %s", err))
			assert.Equal(t, tc.client.Credentials.Secret, c.Credentials.Secret, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.client.Credentials.Secret, c.Credentials.Secret))
		}
	}
}

func TestClientsUpdateIdentity(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "enabled-client",
		Credentials: clients.Credentials{
			Identity: "client1-update@example.com",
			Secret:   password,
		},
		Status: clients.EnabledStatusKey,
	}
	client2 := clients.Client{
		ID:   generateULID(t),
		Name: "disabled-client",
		Credentials: clients.Credentials{
			Identity: "client2-update@example.com",
			Secret:   password,
		},
		Status: clients.DisabledStatusKey,
	}

	rClient1, err := repo.Save(context.Background(), client1)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new client: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client1.ID, rClient1.ID, fmt.Sprintf("add new client: expected %v got %s\n", nil, err))
	}
	rClient2, err := repo.Save(context.Background(), client2)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new disabled client: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client2.ID, rClient2.ID, fmt.Sprintf("add new disabled client: expected %v got %s\n", nil, err))
	}

	ucases := []struct {
		desc   string
		client clients.Client
		err    error
	}{
		{
			desc: "update identity for enabled client",
			client: clients.Client{
				ID: client1.ID,
				Credentials: clients.Credentials{
					Identity: "client1-updated@example.com",
				},
			},
			err: nil,
		},
		{
			desc: "update identity for disabled client",
			client: clients.Client{
				ID: client2.ID,
				Credentials: clients.Credentials{
					Identity: "client2-updated@example.com",
				},
			},
			err: errors.ErrNotFound,
		},
		{
			desc: "update identity for invalid client",
			client: clients.Client{
				ID: wrongID,
				Credentials: clients.Credentials{
					Identity: "client3-updated@example.com",
				},
			},
			err: errors.ErrNotFound,
		},
	}
	for _, tc := range ucases {
		expected, err := repo.UpdateIdentity(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.client.Credentials.Identity, expected.Credentials.Identity, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.client.Credentials.Identity, expected.Credentials.Identity))
		}
	}
}

func TestClientsUpdateOwner(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "enabled-client-with-owner",
		Credentials: clients.Credentials{
			Identity: "client1-update-owner@example.com",
			Secret:   password,
		},
		Owner:  generateULID(t),
		Status: clients.EnabledStatusKey,
	}
	client2 := clients.Client{
		ID:   generateULID(t),
		Name: "disabled-client-with-owner",
		Credentials: clients.Credentials{
			Identity: "client2-update-owner@example.com",
			Secret:   password,
		},
		Owner:  generateULID(t),
		Status: clients.DisabledStatusKey,
	}

	client1, err := repo.Save(context.Background(), client1)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new client with owner: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client1.ID, client1.ID, fmt.Sprintf("add new client with owner: expected %v got %s\n", nil, err))
	}
	client2, err = repo.Save(context.Background(), client2)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new disabled client with owner: expected %v got %s\n", nil, err))
	if err == nil {
		assert.Equal(t, client2.ID, client2.ID, fmt.Sprintf("add new disabled client with owner: expected %v got %s\n", nil, err))
	}
	ucases := []struct {
		desc   string
		client clients.Client
		err    error
	}{
		{
			desc: "update owner for enabled client",
			client: clients.Client{
				ID:    client1.ID,
				Owner: generateULID(t),
			},
			err: nil,
		},
		{
			desc: "update owner for disabled client",
			client: clients.Client{
				ID:    client2.ID,
				Owner: generateULID(t),
			},
			err: errors.ErrNotFound,
		},
		{
			desc: "update owner for invalid client",
			client: clients.Client{
				ID:    wrongID,
				Owner: generateULID(t),
			},
			err: errors.ErrNotFound,
		},
	}
	for _, tc := range ucases {
		expected, err := repo.UpdateOwner(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.client.Owner, expected.Owner, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.client.Owner, expected.Owner))
		}
	}
}

func TestClientsChangeStatus(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewClientRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "enabled-client",
		Credentials: clients.Credentials{
			Identity: "client1-update@example.com",
			Secret:   password,
		},
		Status: clients.EnabledStatusKey,
	}

	client1, err := repo.Save(context.Background(), client1)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("add new client: expected %v got %s\n", nil, err))

	ucases := []struct {
		desc   string
		client clients.Client
		err    error
	}{
		{
			desc: "change client status for an enabled client",
			client: clients.Client{
				ID:     client1.ID,
				Status: 0,
			},
			err: nil,
		},
		{
			desc: "change client status for a disabled client",
			client: clients.Client{
				ID:     client1.ID,
				Status: 1,
			},
			err: nil,
		},
		{
			desc: "change client status for non-existing client",
			client: clients.Client{
				ID:     "invalid",
				Status: 2,
			},
			err: errors.ErrNotFound,
		},
	}

	for _, tc := range ucases {
		expected, err := repo.ChangeStatus(context.Background(), tc.client.ID, tc.client.Status)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.client.Status, expected.Status, fmt.Sprintf("%s: expected %d got %d\n", tc.desc, tc.client.Status, expected.Status))
		}
	}
}

func TestClientsMemberships(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
	postgres.NewDatabase(db, tracer)
	crepo := postgres.NewClientRepo(database)
	grepo := postgres.NewGroupRepo(database)
	prepo := postgres.NewPolicyRepo(database)

	client := clients.Client{
		ID:   generateULID(t),
		Name: "client-memberships",
		Credentials: clients.Credentials{
			Identity: "client-membershipse@example.com",
			Secret:   password,
		},
		Metadata: clients.Metadata{},
		Status:   clients.EnabledStatusKey,
	}
	group := clients.Group{
		ID:       generateULID(t),
		Name:     "group-membership",
		OwnerID:  client.ID,
		Metadata: clients.Metadata{},
	}

	policy := clients.Policy{
		Subject: client.ID,
		Object:  group.ID,
		Actions: []string{"membership"},
	}

	_, err := crepo.Save(context.Background(), client)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("save client: expected %v got %s\n", nil, err))
	_, err = grepo.Save(context.Background(), group)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("save client: expected %v got %s\n", nil, err))
	err = prepo.Save(context.Background(), policy)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("save policy: expected %v got %s\n", nil, err))

	cases := map[string]struct {
		ID  string
		err error
	}{
		"retrieve membership for existing client":     {client.ID, nil},
		"retrieve membership for non-existing client": {wrongID, nil},
	}

	for desc, tc := range cases {
		mp, err := crepo.Memberships(context.Background(), tc.ID, clients.GroupsPage{Page: clients.Page{Total: 10, Offset: 0, Limit: 10}})
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
		if tc.ID == client.ID {
			assert.ElementsMatch(t, mp.Memberships, []clients.Group{group}, fmt.Sprintf("%s: expected %v got %v\n", desc, []clients.Group{group}, mp.Memberships))
		}
	}
}

func cleanUpClient(t *testing.T) {
	_, err := db.Exec("DELETE FROM policies")
	require.Nil(t, err, fmt.Sprintf("clean policies unexpected error: %s", err))
	_, err = db.Exec("DELETE FROM groups")
	require.Nil(t, err, fmt.Sprintf("clean groups unexpected error: %s", err))
	_, err = db.Exec("DELETE FROM clients")
	require.Nil(t, err, fmt.Sprintf("clean clients unexpected error: %s", err))
}
