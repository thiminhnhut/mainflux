package clients_test

import (
	context "context"
	fmt "fmt"
	"testing"
	"time"

	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/clients/internal/apiutil"
	"github.com/mainflux/mainflux/clients/jwt"
	"github.com/mainflux/mainflux/clients/mocks"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/ulid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	idProvider    = ulid.New()
	secret        = "strongsecret"
	validMetadata = clients.Metadata{"role": "client"}
	client        = clients.Client{
		ID:          generateULID(&testing.T{}),
		Name:        "clientname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: clients.Credentials{Identity: "clientidentity", Secret: secret},
		Metadata:    validMetadata,
		Status:      clients.EnabledStatusKey,
	}
	inValidToken = "invalidToken"
	description  = "shortdescription"
	gName        = "groupname"
	group        = clients.Group{
		Name:        gName,
		Description: description,
		Metadata:    validMetadata,
	}
	memberActions  = []string{"g_list"}
	authoritiesObj = "authorities"
)

func generateValidToken(t *testing.T, svc clients.Service, cRepo *mocks.ClientRepository) string {
	client := clients.Client{
		ID:   generateULID(t),
		Name: "validtoken",
		Credentials: clients.Credentials{
			Identity: "validtoken",
			Secret:   secret,
		},
	}
	repoCall := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(client, nil)
	token, err := svc.IssueToken(context.Background(), client)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("Create token expected nil got %s\n", err))
	repoCall.Unset()
	return token.AccessToken
}

func generateULID(t *testing.T) string {
	ulid, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	return ulid
}

func TestRegisterClient(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	cases := []struct {
		desc   string
		client clients.Client
		token  string
		err    error
	}{
		{
			desc:   "register new client",
			client: client,
			token:  generateValidToken(t, svc, cRepo),
			err:    nil,
		},
		{
			desc:   "register existing client",
			client: client,
			token:  generateValidToken(t, svc, cRepo),
			err:    errors.ErrConflict,
		},
		{
			desc: "register a new client with name",
			client: clients.Client{
				Name: "clientWithName",
				Credentials: clients.Credentials{
					Identity: "newclientwithname@example.com",
					Secret:   secret,
				},
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with tags",
			client: clients.Client{
				Tags: []string{"tag1", "tag2"},
				Credentials: clients.Credentials{
					Identity: "newclientwithtags@example.com",
					Secret:   secret,
				},
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},

		{
			desc: "register a new client with metadata",
			client: clients.Client{
				Credentials: clients.Credentials{
					Identity: "newclientwithmetadata@example.com",
					Secret:   secret,
				},
				Metadata: validMetadata,
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with valid disabled status",
			client: clients.Client{
				Credentials: clients.Credentials{
					Identity: "newclientwithvalidstatus@example.com",
					Secret:   secret,
				},
				Status: clients.DisabledStatusKey,
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with all fields",
			client: clients.Client{
				Name: "newclientwithallfields",
				Tags: []string{"tag1", "tag2"},
				Credentials: clients.Credentials{
					Identity: "newclientwithallfields@example.com",
					Secret:   secret,
				},
				Metadata: clients.Metadata{
					"name": "newclientwithallfields",
				},
				Status: 1,
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with missing identity",
			client: clients.Client{
				Name: "clientWithMissingIdentity",
				Credentials: clients.Credentials{
					Secret: secret,
				},
			},
			err:   errors.ErrMalformedEntity,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with invalid owner",
			client: clients.Client{
				Owner: mocks.WrongID,
				Credentials: clients.Credentials{
					Identity: "newclientwithinvalidowner@example.com",
					Secret:   secret,
				},
			},
			err:   errors.ErrMalformedEntity,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with empty secret",
			client: clients.Client{
				Owner: generateULID(t),
				Credentials: clients.Credentials{
					Identity: "newclientwithemptysecret@example.com",
				},
			},
			err:   errors.ErrMalformedEntity,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "register a new client with invalid status",
			client: clients.Client{
				Credentials: clients.Credentials{
					Identity: "newclientwithinvalidstatus@example.com",
					Secret:   secret,
				},
				Status: 3,
			},
			err:   apiutil.ErrInvalidStatus,
			token: generateValidToken(t, svc, cRepo),
		},
	}

	for _, tc := range cases {
		repoCall := cRepo.On("Save", context.Background(), mock.Anything).Return(&clients.Client{}, tc.err)
		registerTime := time.Now()
		expected, err := svc.RegisterClient(context.Background(), tc.token, tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, expected.ID, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, expected.ID))
			assert.WithinDuration(t, expected.CreatedAt, registerTime, 1*time.Second, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected.CreatedAt, registerTime))
			tc.client.ID = expected.ID
			tc.client.CreatedAt = expected.CreatedAt
			tc.client.UpdatedAt = expected.UpdatedAt
			tc.client.Credentials.Secret = expected.Credentials.Secret
			if tc.client.Status == 0 {
				tc.client.Status = 1
			}
			tc.client.Owner = expected.Owner
			assert.Equal(t, tc.client, expected, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.client, expected))
		}
		repoCall.Unset()
	}
}

func TestViewClient(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	cases := []struct {
		desc     string
		token    string
		clientID string
		response clients.Client
		err      error
	}{
		{
			desc:     "view client successfully",
			response: client,
			token:    generateValidToken(t, svc, cRepo),
			clientID: client.ID,
			err:      nil,
		},
		{
			desc:     "view client with an invalid token",
			response: clients.Client{},
			token:    inValidToken,
			clientID: "",
			err:      errors.ErrAuthentication,
		},
		{
			desc:     "view client with valid token and invalid client id",
			response: clients.Client{},
			token:    generateValidToken(t, svc, cRepo),
			clientID: mocks.WrongID,
			err:      errors.ErrNotFound,
		},
		{
			desc:     "view client with an invalid token and invalid client id",
			response: clients.Client{},
			token:    inValidToken,
			clientID: mocks.WrongID,
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.response, tc.err)
		rClient, err := svc.ViewClient(context.Background(), tc.token, tc.clientID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, rClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, rClient))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListClients(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	var nClients = uint64(10)
	var aClients = []clients.Client{}
	for i := uint64(1); i < nClients; i++ {
		identity := fmt.Sprintf("TestListClients%d@example.com", i)
		client := clients.Client{
			Name: identity,
			Credentials: clients.Credentials{
				Identity: identity,
				Secret:   "password",
			},
			Tags:     []string{"tag1", "tag2"},
			Metadata: clients.Metadata{"role": "client"},
		}
		aClients = append(aClients, client)
	}

	cases := []struct {
		desc     string
		token    string
		page     clients.Page
		response clients.ClientsPage
		size     uint64
		err      error
	}{
		{
			desc:  "list clients with authorized token",
			token: generateValidToken(t, svc, cRepo),

			page: clients.Page{
				Status: clients.AllClientsStatusKey,
			},
			size: 0,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
				Clients: []clients.Client{},
			},
			err: nil,
		},
		{
			desc:  "list clients with an invalid token",
			token: inValidToken,
			page: clients.Page{
				Status: clients.AllClientsStatusKey,
			},
			size: 0,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrAuthentication,
		},
		{
			desc:  "list clients with offset and limit",
			token: generateValidToken(t, svc, cRepo),

			page: clients.Page{
				Offset: 6,
				Limit:  nClients,
				Status: clients.AllClientsStatusKey,
			},
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
				Clients: aClients[6:nClients],
			},
			size: nClients - 6,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, tc.err)
		page, err := svc.ListClients(context.Background(), tc.token, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateClient(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	client1 := client
	client2 := client
	client1.Name = "Updated client"
	client2.Metadata = clients.Metadata{"role": "test"}

	cases := []struct {
		desc     string
		client   clients.Client
		response clients.Client
		token    string
		err      error
	}{
		{
			desc:     "update client name with valid token",
			client:   client1,
			response: client1,
			token:    generateValidToken(t, svc, cRepo),
			err:      nil,
		},
		{
			desc:     "update client name with invalid token",
			client:   client1,
			response: clients.Client{},
			token:    "non-existent",
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update client name with invalid ID",
			client: clients.Client{
				ID:   mocks.WrongID,
				Name: "Updated Client",
			},
			response: clients.Client{},
			token:    "non-existent",
			err:      errors.ErrAuthentication,
		},
		{
			desc:     "update client metadata with valid token",
			client:   client2,
			response: client2,
			token:    generateValidToken(t, svc, cRepo),
			err:      nil,
		},
		{
			desc:     "update client metadata with invalid token",
			client:   client2,
			response: clients.Client{},
			token:    "non-existent",
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("Update", context.Background(), mock.Anything).Return(tc.response, tc.err)
		updatedClient, err := svc.UpdateClient(context.Background(), tc.token, tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, updatedClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, updatedClient))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateClientTags(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	client.Tags = []string{"updated"}

	cases := []struct {
		desc     string
		client   clients.Client
		response clients.Client
		token    string
		err      error
	}{
		{
			desc:     "update client tags with valid token",
			client:   client,
			token:    generateValidToken(t, svc, cRepo),
			response: client,
			err:      nil,
		},
		{
			desc:     "update client tags with invalid token",
			client:   client,
			token:    "non-existent",
			response: clients.Client{},
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update client name with invalid ID",
			client: clients.Client{
				ID:   mocks.WrongID,
				Name: "Updated name",
			},
			response: clients.Client{},
			token:    "non-existent",
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("UpdateTags", context.Background(), mock.Anything).Return(tc.response, tc.err)
		updatedClient, err := svc.UpdateClientTags(context.Background(), tc.token, tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, updatedClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, updatedClient))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateClientIdentity(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	client2 := client
	client2.Credentials.Identity = "updated@example.com"

	cases := []struct {
		desc     string
		identity string
		response clients.Client
		token    string
		id       string
		err      error
	}{
		{
			desc:     "update client identity with valid token",
			identity: "updated@example.com",
			token:    generateValidToken(t, svc, cRepo),
			id:       client.ID,
			response: client2,
			err:      nil,
		},
		{
			desc:     "update client identity with invalid id",
			identity: "updated@example.com",
			token:    generateValidToken(t, svc, cRepo),
			id:       mocks.WrongID,
			response: clients.Client{},
			err:      errors.ErrNotFound,
		},
		{
			desc:     "update client identity with invalid token",
			identity: "updated@example.com",
			token:    "non-existent",
			id:       client2.ID,
			response: clients.Client{},
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repo1Call := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.response, tc.err)
		repo2Call := cRepo.On("UpdateIdentity", context.Background(), mock.Anything).Return(tc.response, tc.err)
		updatedClient, err := svc.UpdateClientIdentity(context.Background(), tc.token, tc.id, tc.identity)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, updatedClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, updatedClient))
		repoCall.Unset()
		repo1Call.Unset()
		repo2Call.Unset()
	}
}

func TestUpdateClientOwner(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	client.Owner = "newowner@mail.com"

	cases := []struct {
		desc     string
		client   clients.Client
		response clients.Client
		token    string
		err      error
	}{
		{
			desc:     "update client owner with valid token",
			client:   client,
			token:    generateValidToken(t, svc, cRepo),
			response: client,
			err:      nil,
		},
		{
			desc:     "update client owner with invalid token",
			client:   client,
			token:    "non-existent",
			response: clients.Client{},
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update client owner with invalid ID",
			client: clients.Client{
				ID:    mocks.WrongID,
				Owner: "updatedowner@mail.com",
			},
			response: clients.Client{},
			token:    "non-existent",
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("UpdateOwner", context.Background(), mock.Anything).Return(tc.response, tc.err)
		updatedClient, err := svc.UpdateClientOwner(context.Background(), tc.token, tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, updatedClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, updatedClient))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateClientSecret(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	repoCall := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(client, nil)
	token, err := svc.IssueToken(context.Background(), client)
	assert.Nil(t, err, fmt.Sprintf("Issue token expected nil got %s\n", err))
	repoCall.Unset()

	cases := []struct {
		desc      string
		oldSecret string
		newSecret string
		token     string
		response  clients.Client
		err       error
	}{
		{
			desc:      "update client secret with valid token",
			oldSecret: client.Credentials.Secret,
			newSecret: "newSecret",
			token:     token.AccessToken,
			response:  client,
			err:       nil,
		},
		{
			desc:      "update client secret with invalid token",
			oldSecret: client.Credentials.Secret,
			newSecret: "newPassword",
			token:     "non-existent",
			response:  clients.Client{},
			err:       errors.ErrAuthentication,
		},
		{
			desc:      "update client secret with wrong old secret",
			oldSecret: "oldSecret",
			newSecret: "newSecret",
			token:     token.AccessToken,
			response:  clients.Client{},
			err:       apiutil.ErrInvalidSecret,
		},
	}

	for _, tc := range cases {
		repoCall1 := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.response, tc.err)
		repoCall2 := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(tc.response, tc.err)
		repoCall3 := cRepo.On("UpdateSecret", context.Background(), mock.Anything).Return(tc.response, tc.err)
		updatedClient, err := svc.UpdateClientSecret(context.Background(), tc.token, tc.oldSecret, tc.newSecret)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, updatedClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, updatedClient))
		repoCall1.Unset()
		repoCall2.Unset()
		repoCall3.Unset()
	}
}

func TestEnableClient(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	enabledClient1 := clients.Client{ID: generateULID(t), Credentials: clients.Credentials{Identity: "client1@example.com", Secret: "password"}, Status: clients.EnabledStatusKey}
	disabledClient1 := clients.Client{ID: generateULID(t), Credentials: clients.Credentials{Identity: "client3@example.com", Secret: "password"}, Status: clients.DisabledStatusKey}
	endisabledClient1 := disabledClient1
	endisabledClient1.Status = clients.EnabledStatusKey

	cases := []struct {
		desc     string
		id       string
		token    string
		client   clients.Client
		response clients.Client
		err      error
	}{
		{
			desc:     "enable disabled client",
			id:       disabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   disabledClient1,
			response: endisabledClient1,
			err:      nil,
		},
		{
			desc:     "enable enabled client",
			id:       enabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   enabledClient1,
			response: enabledClient1,
			err:      clients.ErrStatusAlreadyAssigned,
		},
		{
			desc:     "enable non-existing client",
			id:       mocks.WrongID,
			token:    generateValidToken(t, svc, cRepo),
			client:   clients.Client{},
			response: clients.Client{},
			err:      errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.client, tc.err)
		repoCall2 := cRepo.On("ChangeStatus", context.Background(), mock.Anything, mock.Anything).Return(tc.response, tc.err)
		_, err := svc.EnableClient(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}

	cases2 := []struct {
		desc     string
		status   uint16
		size     uint64
		response clients.ClientsPage
	}{
		{
			desc:   "list enabled clients",
			status: clients.EnabledStatusKey,
			size:   2,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  2,
					Offset: 0,
					Limit:  100,
				},
				Clients: []clients.Client{enabledClient1, endisabledClient1},
			},
		},
		{
			desc:   "list disabled clients",
			status: clients.DisabledStatusKey,
			size:   1,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Clients: []clients.Client{disabledClient1},
			},
		},
		{
			desc:   "list enabled and disabled clients",
			status: clients.AllClientsStatusKey,
			size:   3,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  3,
					Offset: 0,
					Limit:  100,
				},
				Clients: []clients.Client{enabledClient1, disabledClient1, endisabledClient1},
			},
		},
	}

	for _, tc := range cases2 {
		pm := clients.Page{
			Offset: 0,
			Limit:  100,
			Status: tc.status,
		}
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, nil)
		page, err := svc.ListClients(context.Background(), generateValidToken(t, svc, cRepo), pm)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		size := uint64(len(page.Clients))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", tc.desc, tc.size, size))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestDisableClient(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	enabledClient1 := clients.Client{ID: generateULID(t), Credentials: clients.Credentials{Identity: "client1@example.com", Secret: "password"}}
	disabledClient1 := clients.Client{ID: generateULID(t), Credentials: clients.Credentials{Identity: "client3@example.com", Secret: "password"}, Status: clients.DisabledStatusKey}
	disenabledClient1 := enabledClient1
	disenabledClient1.Status = clients.DisabledStatusKey

	cases := []struct {
		desc     string
		id       string
		token    string
		client   clients.Client
		response clients.Client
		err      error
	}{
		{
			desc:     "disable enabled client",
			id:       enabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   enabledClient1,
			response: disenabledClient1,
			err:      nil,
		},
		{
			desc:     "disable disabled client",
			id:       disabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   disabledClient1,
			response: clients.Client{},
			err:      clients.ErrStatusAlreadyAssigned,
		},
		{
			desc:     "disable non-existing client",
			id:       mocks.WrongID,
			client:   clients.Client{},
			token:    generateValidToken(t, svc, cRepo),
			response: clients.Client{},
			err:      errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		_ = cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.client, tc.err)
		repoCall1 := cRepo.On("ChangeStatus", context.Background(), mock.Anything, mock.Anything).Return(tc.response, tc.err)
		_, err := svc.DisableClient(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
	}

	cases2 := []struct {
		desc     string
		status   uint16
		size     uint64
		response clients.ClientsPage
	}{
		{
			desc:   "list enabled clients",
			status: clients.EnabledStatusKey,
			size:   1,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Clients: []clients.Client{enabledClient1},
			},
		},
		{
			desc:   "list disabled clients",
			status: clients.DisabledStatusKey,
			size:   2,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  2,
					Offset: 0,
					Limit:  100,
				},
				Clients: []clients.Client{disenabledClient1, disabledClient1},
			},
		},
		{
			desc:   "list enabled and disabled clients",
			status: clients.AllClientsStatusKey,
			size:   3,
			response: clients.ClientsPage{
				Page: clients.Page{
					Total:  3,
					Offset: 0,
					Limit:  100,
				},
				Clients: []clients.Client{enabledClient1, disabledClient1, disenabledClient1},
			},
		},
	}

	for _, tc := range cases2 {
		pm := clients.Page{
			Offset: 0,
			Limit:  100,
			Status: tc.status,
		}
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, nil)
		page, err := svc.ListClients(context.Background(), generateValidToken(t, svc, cRepo), pm)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		size := uint64(len(page.Clients))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", tc.desc, tc.size, size))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestCreateGroup(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	cases := []struct {
		desc  string
		group clients.Group
		err   error
	}{
		{
			desc:  "create new group",
			group: group,
			err:   nil,
		},
		{
			desc:  "create group with existing name",
			group: group,
			err:   nil,
		},
		{
			desc: "create group with parent",
			group: clients.Group{
				Name:     gName,
				ParentID: generateULID(t),
			},
			err: nil,
		},
		{
			desc: "create group with invalid parent",
			group: clients.Group{
				Name:     gName,
				ParentID: mocks.WrongID,
			},
			err: errors.ErrCreateEntity,
		},
		{
			desc: "create group with invalid owner",
			group: clients.Group{
				Name:    gName,
				OwnerID: mocks.WrongID,
			},
			err: errors.ErrCreateEntity,
		},
		{
			desc:  "create group with missing name",
			group: clients.Group{},
			err:   errors.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := gRepo.On("Save", context.Background(), mock.Anything).Return(tc.group, tc.err)
		createdAt := time.Now()
		expected, err := svc.CreateGroup(context.Background(), generateValidToken(t, svc, cRepo), tc.group)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, expected.ID, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, expected.ID))
			assert.WithinDuration(t, expected.CreatedAt, createdAt, 1*time.Second, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected.CreatedAt, createdAt))
			tc.group.ID = expected.ID
			tc.group.CreatedAt = expected.CreatedAt
			tc.group.UpdatedAt = expected.UpdatedAt
			tc.group.OwnerID = expected.OwnerID
			assert.Equal(t, tc.group, expected, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.group, expected))
		}
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateGroup(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	group.ID = generateULID(t)

	cases := []struct {
		desc     string
		token    string
		group    clients.Group
		response clients.Group
		err      error
	}{
		{
			desc: "update group name",
			group: clients.Group{
				ID:   group.ID,
				Name: "NewName",
			},
			response: clients.Group{
				ID:   group.ID,
				Name: "NewName",
			},
			token: generateValidToken(t, svc, cRepo),

			err: nil,
		},
		{
			desc: "update group description",
			group: clients.Group{
				ID:          group.ID,
				Description: "NewDescription",
			},
			response: clients.Group{
				ID:          group.ID,
				Description: "NewDescription",
			},
			token: generateValidToken(t, svc, cRepo),

			err: nil,
		},
		{
			desc: "update group metadata",
			group: clients.Group{
				ID: group.ID,
				Metadata: clients.Metadata{
					"field": "value2",
				},
			},
			response: clients.Group{
				ID: group.ID,
				Metadata: clients.Metadata{
					"field": "value2",
				},
			},
			token: generateValidToken(t, svc, cRepo),

			err: nil,
		},
		{
			desc: "update group name with invalid group id",
			group: clients.Group{
				ID:   mocks.WrongID,
				Name: "NewName",
			},
			response: clients.Group{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.ErrNotFound,
		},
		{
			desc: "update group description with invalid group id",
			group: clients.Group{
				ID:          mocks.WrongID,
				Description: "NewDescription",
			},
			response: clients.Group{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.ErrNotFound,
		},
		{
			desc: "update group metadata with invalid group id",
			group: clients.Group{
				ID: mocks.WrongID,
				Metadata: clients.Metadata{
					"field": "value2",
				},
			},
			response: clients.Group{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.ErrNotFound,
		},
		{
			desc: "update group name with invalid token",
			group: clients.Group{
				ID:   group.ID,
				Name: "NewName",
			},
			response: clients.Group{},
			token:    inValidToken,
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update group description with invalid token",
			group: clients.Group{
				ID:          group.ID,
				Description: "NewDescription",
			},
			response: clients.Group{},
			token:    inValidToken,
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update group metadata with invalid token",
			group: clients.Group{
				ID: group.ID,
				Metadata: clients.Metadata{
					"field": "value2",
				},
			},
			response: clients.Group{},
			token:    inValidToken,
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := gRepo.On("Update", context.Background(), mock.Anything).Return(tc.response, tc.err)
		expectedGroup, err := svc.UpdateGroup(context.Background(), tc.token, tc.group)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, expectedGroup, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, expectedGroup))
		repoCall.Unset()
		repoCall1.Unset()
	}

}

func TestViewGroup(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	group.ID = generateULID(t)

	cases := []struct {
		desc     string
		token    string
		groupID  string
		response clients.Group
		err      error
	}{
		{

			desc:     "view group",
			token:    generateValidToken(t, svc, cRepo),
			groupID:  group.ID,
			response: group,
			err:      nil,
		},
		{
			desc:     "view group with invalid token",
			token:    "wrongtoken",
			groupID:  group.ID,
			response: clients.Group{},
			err:      errors.ErrAuthentication,
		},
		{
			desc:     "view group for wrong id",
			token:    generateValidToken(t, svc, cRepo),
			groupID:  mocks.WrongID,
			response: clients.Group{},
			err:      errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := gRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.response, tc.err)
		expected, err := svc.ViewGroup(context.Background(), tc.token, tc.groupID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, expected, tc.response, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected, tc.response))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListGroups(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	n := uint64(10)
	parentID := ""
	var aGroups = []clients.Group{}
	for i := uint64(0); i < n; i++ {
		group := clients.Group{
			ID:          generateULID(t),
			Name:        fmt.Sprintf("Group%d", i),
			Description: description,
			Metadata: clients.Metadata{
				"field": "value",
			},
			ParentID: parentID,
		}
		parentID = group.ID
		aGroups = append(aGroups, group)
	}

	cases := []struct {
		desc     string
		token    string
		size     uint64
		response clients.GroupsPage
		page     clients.GroupsPage
		err      error
	}{
		{
			desc:  "list all groups",
			token: generateValidToken(t, svc, cRepo),

			size: 10,
			err:  nil,
			page: clients.GroupsPage{
				Page: clients.Page{
					Offset: 0,
					Total:  100,
					Limit:  100,
				},
			},
			response: clients.GroupsPage{
				Page: clients.Page{
					Offset: 0,
					Total:  100,
					Limit:  100,
				},
				Groups: aGroups,
			},
		},
		{
			desc:  "list groups with an offset",
			token: generateValidToken(t, svc, cRepo),

			size: 5,
			err:  nil,
			page: clients.GroupsPage{
				Page: clients.Page{
					Offset: 5,
					Total:  100,
					Limit:  100,
				},
			},
			response: clients.GroupsPage{
				Page: clients.Page{
					Offset: 0,
					Total:  100,
					Limit:  100,
				},
				Groups: aGroups[5:10],
			},
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall1 := gRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, tc.err)
		page, err := svc.ListGroups(context.Background(), tc.token, tc.page)
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
	}

}

func TestRemoveGroup(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	creationTime := time.Now().UTC()
	group := clients.Group{
		ID:        generateULID(t),
		Name:      gName,
		OwnerID:   generateULID(t),
		CreatedAt: creationTime,
		UpdatedAt: creationTime,
	}

	repo1Call := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
	repoCall := gRepo.On("Save", context.Background(), mock.Anything).Return(group, nil)
	group, err := svc.CreateGroup(context.Background(), generateValidToken(t, svc, cRepo), group)
	require.Nil(t, err, fmt.Sprintf("group save got unexpected error: %s", err))
	repoCall.Unset()
	repo1Call.Unset()

	repo1Call = pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
	repoCall = gRepo.On("Delete", context.Background(), mock.Anything).Return(errors.ErrNotFound)
	err = svc.RemoveGroup(context.Background(), generateValidToken(t, svc, cRepo), "wrongID")
	assert.True(t, errors.Contains(err, errors.ErrNotFound), fmt.Sprintf("Remove group with wrong id: expected %v got %v", errors.ErrNotFound, err))
	repoCall.Unset()
	repo1Call.Unset()

	repo1Call = pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
	repoCall = gRepo.On("Delete", context.Background(), mock.Anything).Return(nil)
	err = svc.RemoveGroup(context.Background(), generateValidToken(t, svc, cRepo), group.ID)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("Remove group with correct id: expected %v got %v", nil, err))
	repoCall.Unset()
	repo1Call.Unset()
}

func TestListMemberships(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	var nGroups = uint64(100)
	var aGroups = []clients.Group{}
	for i := uint64(1); i < nGroups; i++ {
		group := clients.Group{
			Name:     fmt.Sprintf("TestListMemberships%d@example.com", i),
			Metadata: clients.Metadata{"role": "group"},
		}
		aGroups = append(aGroups, group)
	}

	cases := []struct {
		desc     string
		token    string
		clientID string
		page     clients.GroupsPage
		response clients.MembershipsPage
		err      error
	}{
		{
			desc:     "list clients with authorized token",
			token:    generateValidToken(t, svc, cRepo),
			clientID: generateULID(t),
			page:     clients.GroupsPage{},
			response: clients.MembershipsPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
				Memberships: aGroups,
			},
			err: nil,
		},
		{
			desc:     "list clients with offset and limit",
			token:    generateValidToken(t, svc, cRepo),
			clientID: generateULID(t),
			page: clients.GroupsPage{
				Page: clients.Page{
					Offset: 6,
					Total:  nGroups,
					Limit:  nGroups,
					Status: clients.AllClientsStatusKey,
				},
			},
			response: clients.MembershipsPage{
				Page: clients.Page{
					Total: nGroups - 6,
				},
				Memberships: aGroups[6:nGroups],
			},
		},
		{
			desc:     "list clients with an invalid token",
			token:    inValidToken,
			clientID: generateULID(t),
			page:     clients.GroupsPage{},
			response: clients.MembershipsPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrAuthentication,
		},
		{
			desc:     "list clients with an invalid id",
			token:    generateValidToken(t, svc, cRepo),
			clientID: mocks.WrongID,
			page:     clients.GroupsPage{},
			response: clients.MembershipsPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repo1Call := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall := cRepo.On("Memberships", context.Background(), tc.clientID, tc.page).Return(tc.response, tc.err)
		page, err := svc.ListMemberships(context.Background(), tc.token, tc.clientID, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		repoCall.Unset()
		repo1Call.Unset()
	}
}

func TestListMembers(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	var nClients = uint64(10)
	var aClients = []clients.Client{}
	for i := uint64(1); i < nClients; i++ {
		identity := fmt.Sprintf("TestListMembers%d@example.com", i)
		client := clients.Client{
			Name: identity,
			Credentials: clients.Credentials{
				Identity: identity,
				Secret:   "password",
			},
			Tags:     []string{"tag1", "tag2"},
			Metadata: clients.Metadata{"role": "client"},
		}
		aClients = append(aClients, client)
	}

	cases := []struct {
		desc     string
		token    string
		groupID  string
		page     clients.Page
		response clients.MembersPage
		err      error
	}{
		{
			desc:    "list clients with authorized token",
			token:   generateValidToken(t, svc, cRepo),
			groupID: generateULID(t),
			page:    clients.Page{},
			response: clients.MembersPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
				Members: []clients.Client{},
			},
			err: nil,
		},
		{
			desc:    "list clients with offset and limit",
			token:   generateValidToken(t, svc, cRepo),
			groupID: generateULID(t),
			page: clients.Page{
				Offset: 6,
				Limit:  nClients,
				Status: clients.AllClientsStatusKey,
			},
			response: clients.MembersPage{
				Page: clients.Page{
					Total: nClients - 6,
				},
				Members: aClients[6:nClients],
			},
		},
		{
			desc:    "list clients with an invalid token",
			token:   inValidToken,
			groupID: generateULID(t),
			page:    clients.Page{},
			response: clients.MembersPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrAuthentication,
		},
		{
			desc:    "list clients with an invalid id",
			token:   generateValidToken(t, svc, cRepo),
			groupID: mocks.WrongID,
			page:    clients.Page{},
			response: clients.MembersPage{
				Page: clients.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repo1Call := pRepo.On("Evaluate", context.Background(), "group", mock.Anything).Return(nil)
		repoCall := gRepo.On("Members", context.Background(), tc.groupID, tc.page).Return(tc.response, tc.err)
		page, err := svc.ListMembers(context.Background(), tc.token, tc.groupID, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		repoCall.Unset()
		repo1Call.Unset()
	}
}

func TestAddPolicy(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	policy := clients.Policy{Object: "obj1", Actions: []string{"m_read"}, Subject: "sub1"}

	cases := []struct {
		desc   string
		policy clients.Policy
		page   clients.PolicyPage
		token  string
		err    error
	}{
		{
			desc:   "add new policy",
			policy: policy,
			page:   clients.PolicyPage{},
			token:  generateValidToken(t, svc, cRepo),
			err:    nil,
		},
		{
			desc:   "add existing policy",
			policy: policy,
			page:   clients.PolicyPage{Policies: []clients.Policy{policy}},
			token:  generateValidToken(t, svc, cRepo),
			err:    errors.ErrConflict,
		},
		{
			desc: "add a new policy with owner",
			page: clients.PolicyPage{},
			policy: clients.Policy{
				OwnerID: generateULID(t),
				Object:  "objwithowner",
				Actions: []string{"m_read"},
				Subject: "subwithowner",
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "add a new policy with more actions",
			page: clients.PolicyPage{},
			policy: clients.Policy{
				Object:  "obj2",
				Actions: []string{"c_delete", "c_update", "c_add", "c_list"},
				Subject: "sub2",
			},
			err:   nil,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "add a new policy with wrong action",
			page: clients.PolicyPage{},
			policy: clients.Policy{
				Object:  "obj3",
				Actions: []string{"wrong"},
				Subject: "sub3",
			},
			err:   apiutil.ErrMissingPolicyAct,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "add a new policy with empty object",
			page: clients.PolicyPage{},
			policy: clients.Policy{
				Actions: []string{"c_delete"},
				Subject: "sub4",
			},
			err:   apiutil.ErrMissingPolicyObj,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "add a new policy with empty subject",
			page: clients.PolicyPage{},
			policy: clients.Policy{
				Actions: []string{"c_delete"},
				Object:  "obj4",
			},
			err:   apiutil.ErrMissingPolicySub,
			token: generateValidToken(t, svc, cRepo),
		},
		{
			desc: "add a new policy with empty action",
			page: clients.PolicyPage{},
			policy: clients.Policy{
				Subject: "sub5",
				Object:  "obj5",
			},
			err:   apiutil.ErrMissingPolicyAct,
			token: generateValidToken(t, svc, cRepo),
		},
	}

	for _, tc := range cases {
		repo1Call := pRepo.On("Evaluate", context.Background(), "client", mock.Anything).Return(nil)
		repoCall := pRepo.On("Update", context.Background(), tc.policy).Return(tc.err)
		repoCall1 := pRepo.On("Save", context.Background(), mock.Anything).Return(tc.err)
		repoCall2 := pRepo.On("Retrieve", context.Background(), mock.Anything).Return(tc.page, nil)
		err := svc.AddPolicy(context.Background(), tc.token, tc.policy)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			err = svc.Authorize(context.Background(), "client", tc.policy)
			require.Nil(t, err, fmt.Sprintf("checking shared %v policy expected to be succeed: %#v", tc.policy, err))
		}
		repoCall1.Parent.AssertCalled(t, "Save", context.Background(), mock.Anything)
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
		repo1Call.Unset()
	}

}

func TestAuthorize(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	cases := []struct {
		desc   string
		policy clients.Policy
		domain string
		token  string
		err    error
	}{
		{
			desc:   "check valid policy in client domain",
			policy: clients.Policy{Object: "client1", Actions: []string{"c_update"}, Subject: "client2"},
			domain: "client",
			token:  generateValidToken(t, svc, cRepo),
			err:    nil,
		},
		{
			desc:   "check valid policy in group domain",
			policy: clients.Policy{Object: "client1", Actions: []string{"g_update"}, Subject: "group1"},
			domain: "group",
			token:  generateValidToken(t, svc, cRepo),
			err:    errors.ErrConflict,
		},
		{
			desc:   "check invalid policy in client domain",
			policy: clients.Policy{Object: "client3", Actions: []string{"c_update"}, Subject: "client4"},
			domain: "client",
			err:    nil,
			token:  generateValidToken(t, svc, cRepo),
		},
		{
			desc:   "check invalid policy in group domain",
			policy: clients.Policy{Object: "client3", Actions: []string{"g_update"}, Subject: "group2"},
			domain: "group",
			err:    nil,
			token:  generateValidToken(t, svc, cRepo)},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", context.Background(), tc.domain, tc.policy).Return(tc.err)
		err := svc.Authorize(context.Background(), tc.domain, tc.policy)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
	}

}

func TestDeletePolicy(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	pr := clients.Policy{Object: authoritiesObj, Actions: memberActions, Subject: generateULID(t)}

	repoCall := pRepo.On("Delete", context.Background(), mock.Anything).Return(nil)
	repoCall1 := pRepo.On("Retrieve", context.Background(), mock.Anything).Return(clients.PolicyPage{Policies: []clients.Policy{pr}}, nil)
	err := svc.DeletePolicy(context.Background(), generateValidToken(t, svc, cRepo), pr)
	require.Nil(t, err, fmt.Sprintf("deleting %v policy expected to succeed: %s", pr, err))
	repoCall.Parent.AssertCalled(t, "Delete", context.Background(), pr)
	repoCall1.Parent.AssertCalled(t, "Retrieve", context.Background(), mock.Anything)
	repoCall.Unset()
	repoCall1.Unset()
}

func TestListPolicies(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	id := generateULID(t)

	readPolicy := "m_read"
	writePolicy := "m_write"

	var nPolicy = uint64(10)
	var aPolicies = []clients.Policy{}
	for i := uint64(0); i < nPolicy; i++ {
		pr := clients.Policy{
			OwnerID: id,
			Actions: []string{readPolicy},
			Subject: fmt.Sprintf("thing-%d", i),
			Object:  fmt.Sprintf("client-%d", i),
		}
		if i%3 == 0 {
			pr.Actions = []string{writePolicy}
		}
		aPolicies = append(aPolicies, pr)
	}

	cases := []struct {
		desc     string
		token    string
		page     clients.Page
		response clients.PolicyPage
		err      error
	}{
		{
			desc:  "list policies with authorized token",
			token: generateValidToken(t, svc, cRepo),

			err: nil,
			response: clients.PolicyPage{
				Page: clients.Page{
					Offset: 0,
					Total:  nPolicy,
				},
				Policies: aPolicies,
			},
		},
		{
			desc:  "list policies with invalid token",
			token: inValidToken,
			err:   errors.ErrAuthentication,
			response: clients.PolicyPage{
				Page: clients.Page{
					Offset: 0,
				},
			},
		},
		{
			desc:  "list policies with offset and limit",
			token: generateValidToken(t, svc, cRepo),

			page: clients.Page{
				Offset: 6,
				Limit:  nPolicy,
			},
			response: clients.PolicyPage{
				Page: clients.Page{
					Offset: 6,
					Total:  nPolicy,
				},
				Policies: aPolicies[6:10],
			},
		},
		{
			desc:  "list policies with wrong action",
			token: generateValidToken(t, svc, cRepo),

			page: clients.Page{
				Action: "wrong",
			},
			response: clients.PolicyPage{},
			err:      apiutil.ErrMissingPolicyAct,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Retrieve", context.Background(), tc.page).Return(tc.response, tc.err)
		page, err := svc.ListPolicy(context.Background(), tc.token, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected size %v got %v\n", tc.desc, tc.response, page))
		repoCall.Unset()
	}

}

func TestUpdatePolicies(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	policy := clients.Policy{Object: "obj1", Actions: []string{"m_read"}, Subject: "sub1"}

	cases := []struct {
		desc   string
		action []string
		token  string
		err    error
	}{
		{
			desc:   "update policy actions with valid token",
			action: []string{"m_write"},
			token:  generateValidToken(t, svc, cRepo),
			err:    nil,
		},
		{
			desc:   "update policy action with invalid token",
			action: []string{"m_write"},
			token:  "non-existent",
			err:    errors.ErrAuthentication,
		},
		{
			desc:   "update policy action with wrong policy action",
			action: []string{"wrong"},
			token:  generateValidToken(t, svc, cRepo),
			err:    apiutil.ErrMissingPolicyAct,
		},
	}

	for _, tc := range cases {
		policy.Actions = tc.action
		repoCall := pRepo.On("Retrieve", context.Background(), mock.Anything).Return(clients.PolicyPage{Policies: []clients.Policy{policy}}, nil)
		repoCall1 := pRepo.On("Update", context.Background(), mock.Anything).Return(tc.err)
		err := svc.UpdatePolicy(context.Background(), tc.token, policy)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall1.Parent.AssertCalled(t, "Update", context.Background(), mock.Anything)
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestIssueToken(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	nclient := client
	nclient.Credentials.Secret = "wrongsecret"

	cases := []struct {
		desc    string
		client  clients.Client
		rClient clients.Client
		err     error
	}{
		{
			desc:    "issue token for an existing client",
			client:  client,
			rClient: client,
			err:     nil,
		},
		{
			desc:    "issue token for a non-existing client",
			client:  client,
			rClient: clients.Client{},
			err:     errors.ErrAuthentication,
		},
		{
			desc:    "issue token for a client with wrong secret",
			client:  client,
			rClient: nclient,
			err:     errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(tc.rClient, tc.err)
		token, err := svc.IssueToken(context.Background(), tc.client)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, token.AccessToken, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.AccessToken))
			assert.NotEmpty(t, token.RefreshToken, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.RefreshToken))
		}
		repoCall.Unset()
	}
}

func TestRefreshToken(t *testing.T) {
	cRepo := new(mocks.ClientRepository)
	gRepo := new(mocks.GroupRepository)
	pRepo := new(mocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret))
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idProvider)

	repoCall := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(client, nil)
	token, err := svc.IssueToken(context.Background(), client)
	assert.Nil(t, err, fmt.Sprintf("Issue token expected nil got %s\n", err))
	repoCall.Unset()

	cases := []struct {
		desc   string
		token  string
		client clients.Client
		err    error
	}{
		{
			desc:   "refresh token with refresh token for an existing client",
			token:  token.RefreshToken,
			client: client,
			err:    nil,
		},
		{
			desc:   "refresh token with refresh token for a non-existing client",
			token:  token.RefreshToken,
			client: clients.Client{},
			err:    errors.ErrAuthentication,
		},
		{
			desc:   "refresh token with access token for an existing client",
			token:  token.AccessToken,
			client: client,
			err:    errors.ErrAuthentication,
		},
		{
			desc:   "refresh token with access token for a non-existing client",
			token:  token.AccessToken,
			client: clients.Client{},
			err:    errors.ErrAuthentication,
		},
		{
			desc:   "refresh token with invalid token for an existing client",
			token:  generateValidToken(t, svc, cRepo),
			client: client,
			err:    errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall1 := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(tc.client, nil)
		repoCall2 := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.client, tc.err)
		token, err := svc.RefreshToken(context.Background(), tc.token)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, token.AccessToken, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.AccessToken))
			assert.NotEmpty(t, token.RefreshToken, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.RefreshToken))
		}
		repoCall1.Unset()
		repoCall2.Unset()
	}
}
