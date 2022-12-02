package mocks

import (
	"context"

	"github.com/mainflux/mainflux/clients"
	"github.com/stretchr/testify/mock"
)

type PolicyRepository struct {
	mock.Mock
}

func (_m *PolicyRepository) Delete(ctx context.Context, p clients.Policy) error {
	ret := _m.Called(ctx, p)

	return ret.Error(0)
}

func (_m *PolicyRepository) Retrieve(ctx context.Context, pm clients.Page) (clients.PolicyPage, error) {
	ret := _m.Called(ctx, pm)

	return ret.Get(0).(clients.PolicyPage), ret.Error(1)
}

func (_m *PolicyRepository) Save(ctx context.Context, p clients.Policy) error {
	ret := _m.Called(ctx, p)

	return ret.Error(0)
}

func (_m *PolicyRepository) Update(ctx context.Context, p clients.Policy) error {
	ret := _m.Called(ctx, p)

	return ret.Error(0)
}

func (_m *PolicyRepository) Evaluate(ctx context.Context, entityType string, p clients.Policy) error {
	ret := _m.Called(ctx, entityType, p)

	return ret.Error(0)
}

type mockConstructorTestingTNewPolicyRepository interface {
	mock.TestingT
	Cleanup(func())
}

func NewPolicyRepository(t mockConstructorTestingTNewPolicyRepository) *PolicyRepository {
	mock := &PolicyRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
