package mocks

import (
	"context"

	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/stretchr/testify/mock"
)

const WrongID = "wrongID"

type ClientRepository struct {
	mock.Mock
}

func (_m *ClientRepository) ChangeStatus(ctx context.Context, id string, status uint16) (clients.Client, error) {
	ret := _m.Called(ctx, id, status)

	if id == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}
	if status != clients.EnabledStatusKey && status != clients.DisabledStatusKey {
		return clients.Client{}, errors.ErrMalformedEntity
	}

	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) Memberships(ctx context.Context, clientID string, gm clients.GroupsPage) (clients.MembershipsPage, error) {
	ret := _m.Called(ctx, clientID, gm)

	if clientID == WrongID {
		return clients.MembershipsPage{}, errors.ErrNotFound
	}

	return ret.Get(0).(clients.MembershipsPage), ret.Error(1)
}

func (_m *ClientRepository) RetrieveAll(ctx context.Context, pm clients.Page) (clients.ClientsPage, error) {
	ret := _m.Called(ctx, pm)

	return ret.Get(0).(clients.ClientsPage), ret.Error(1)
}

func (_m *ClientRepository) RetrieveByID(ctx context.Context, id string) (clients.Client, error) {
	ret := _m.Called(ctx, id)

	if id == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}

	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) RetrieveByIdentity(ctx context.Context, identity string) (clients.Client, error) {
	ret := _m.Called(ctx, identity)

	if identity == "" {
		return clients.Client{}, errors.ErrMalformedEntity
	}

	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) Save(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)
	if client.Owner == WrongID {
		return clients.Client{}, errors.ErrMalformedEntity
	}
	if client.Credentials.Secret == "" {
		return clients.Client{}, errors.ErrMalformedEntity
	}

	return client, ret.Error(1)
}

func (_m *ClientRepository) Update(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if client.ID == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}
	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) UpdateIdentity(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if client.ID == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}
	if client.Credentials.Identity == "" {
		return clients.Client{}, errors.ErrMalformedEntity
	}

	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) UpdateSecret(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if client.ID == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}
	if client.Credentials.Secret == "" {
		return clients.Client{}, errors.ErrMalformedEntity
	}

	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) UpdateTags(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if client.ID == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}
	return ret.Get(0).(clients.Client), ret.Error(1)
}

func (_m *ClientRepository) UpdateOwner(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if client.ID == WrongID {
		return clients.Client{}, errors.ErrNotFound
	}
	return ret.Get(0).(clients.Client), ret.Error(1)
}

type mockConstructorTestingTNewClientRepository interface {
	mock.TestingT
	Cleanup(func())
}

func NewClientRepository(t mockConstructorTestingTNewClientRepository) *ClientRepository {
	mock := &ClientRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
