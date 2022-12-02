package mocks

import (
	"context"

	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/stretchr/testify/mock"
)

type GroupRepository struct {
	mock.Mock
}

func (_m *GroupRepository) Delete(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)
	if id == WrongID {
		return errors.ErrNotFound
	}

	return ret.Error(0)
}

func (_m *GroupRepository) Members(ctx context.Context, groupID string, pm clients.Page) (clients.MembersPage, error) {
	ret := _m.Called(ctx, groupID, pm)
	if groupID == WrongID {
		return clients.MembersPage{}, errors.ErrNotFound
	}

	return ret.Get(0).(clients.MembersPage), ret.Error(1)
}

func (_m *GroupRepository) RetrieveAll(ctx context.Context, gm clients.GroupsPage) (clients.GroupsPage, error) {
	ret := _m.Called(ctx, gm)

	return ret.Get(0).(clients.GroupsPage), ret.Error(1)
}

func (_m *GroupRepository) RetrieveByID(ctx context.Context, id string) (clients.Group, error) {
	ret := _m.Called(ctx, id)
	if id == WrongID {
		return clients.Group{}, errors.ErrNotFound
	}

	return ret.Get(0).(clients.Group), ret.Error(1)
}

func (_m *GroupRepository) Save(ctx context.Context, g clients.Group) (clients.Group, error) {
	ret := _m.Called(ctx, g)
	if g.ParentID == WrongID {
		return clients.Group{}, errors.ErrCreateEntity
	}
	if g.OwnerID == WrongID {
		return clients.Group{}, errors.ErrCreateEntity
	}

	return g, ret.Error(1)
}

func (_m *GroupRepository) Update(ctx context.Context, g clients.Group) (clients.Group, error) {
	ret := _m.Called(ctx, g)
	if g.ID == WrongID {
		return clients.Group{}, errors.ErrNotFound
	}

	return ret.Get(0).(clients.Group), ret.Error(1)
}

type mockConstructorTestingTNewGroupRepository interface {
	mock.TestingT
	Cleanup(func())
}

func NewGroupRepository(t mockConstructorTestingTNewGroupRepository) *GroupRepository {
	mock := &GroupRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
