package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/clients/internal/apiutil"
	"github.com/mainflux/mainflux/clients/postgres"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoliciesSave(t *testing.T) {
	t.Cleanup(func() { cleanUpPolicies(t) })
	repo := postgres.NewPolicyRepo(database)
	crepo := postgres.NewClientRepo(database)

	uid := generateULID(t)

	client := clients.Client{
		ID:   uid,
		Name: "policy-save@example.com",
		Credentials: clients.Credentials{
			Identity: "policy-save@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}

	client, err := crepo.Save(context.Background(), client)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	uid, err = idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		policy clients.Policy
		err    error
	}{
		{
			desc: "add new policy successfully",
			policy: clients.Policy{
				OwnerID: client.ID,
				Subject: client.ID,
				Object:  uid,
				Actions: []string{"c_delete"},
			},
			err: nil,
		},
		{
			desc: "add policy with duplicate subject, object and action",
			policy: clients.Policy{
				OwnerID: client.ID,
				Subject: client.ID,
				Object:  uid,
				Actions: []string{"c_delete"},
			},
			err: errors.ErrConflict,
		},
	}

	for _, tc := range cases {
		err := repo.Save(context.Background(), tc.policy)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestPoliciesEvaluate(t *testing.T) {
	t.Cleanup(func() { cleanUpPolicies(t) })
	repo := postgres.NewPolicyRepo(database)
	crepo := postgres.NewClientRepo(database)
	grepo := postgres.NewGroupRepo(database)

	client1 := clients.Client{
		ID:   generateULID(t),
		Name: "connectedclients-clientA@example.com",
		Credentials: clients.Credentials{
			Identity: "connectedclients-clientA@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}
	client2 := clients.Client{
		ID:   generateULID(t),
		Name: "connectedclients-clientB@example.com",
		Credentials: clients.Credentials{
			Identity: "connectedclients-clientB@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}
	group := clients.Group{
		ID:   generateULID(t),
		Name: "connecting-group@example.com",
	}

	client1, err := crepo.Save(context.Background(), client1)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	client2, err = crepo.Save(context.Background(), client2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	group, err = grepo.Save(context.Background(), group)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	policy1 := clients.Policy{
		OwnerID: client1.ID,
		Subject: client1.ID,
		Object:  group.ID,
		Actions: []string{"c_update", "g_update"},
	}
	policy2 := clients.Policy{
		OwnerID: client2.ID,
		Subject: client2.ID,
		Object:  group.ID,
		Actions: []string{"c_update", "g_update"},
	}
	err = repo.Save(context.Background(), policy1)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	err = repo.Save(context.Background(), policy2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := map[string]struct {
		Subject string
		Object  string
		Action  string
		Domain  string
		err     error
	}{
		"evaluate valid client update":   {client1.ID, client2.ID, "c_update", "client", nil},
		"evaluate valid group update":    {client1.ID, group.ID, "g_update", "group", nil},
		"evaluate valid client list":     {client1.ID, client2.ID, "c_list", "client", errors.ErrAuthorization},
		"evaluate valid group list":      {client1.ID, group.ID, "g_list", "group", errors.ErrAuthorization},
		"evaluate invalid client delete": {client1.ID, client2.ID, "c_delete", "client", errors.ErrAuthorization},
		"evaluate invalid group delete":  {client1.ID, group.ID, "g_delete", "group", errors.ErrAuthorization},
		"evaluate invalid client update": {"unknown", "unknown", "c_update", "client", errors.ErrAuthorization},
		"evaluate invalid group update":  {"unknown", "unknown", "c_update", "group", errors.ErrAuthorization},
	}

	for desc, tc := range cases {
		p := clients.Policy{
			Subject: tc.Subject,
			Object:  tc.Object,
			Actions: []string{tc.Action},
		}
		err := repo.Evaluate(context.Background(), tc.Domain, p)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
	}
}

func TestPoliciesRetrieve(t *testing.T) {
	t.Cleanup(func() { cleanUpPolicies(t) })
	repo := postgres.NewPolicyRepo(database)
	crepo := postgres.NewClientRepo(database)

	uid := generateULID(t)

	client := clients.Client{
		ID:   uid,
		Name: "single-policy-retrieval@example.com",
		Credentials: clients.Credentials{
			Identity: "single-policy-retrieval@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}

	client, err := crepo.Save(context.Background(), client)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	uid, err = idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	policy := clients.Policy{
		OwnerID: client.ID,
		Subject: client.ID,
		Object:  uid,
		Actions: []string{"c_delete"},
	}

	err = repo.Save(context.Background(), policy)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := map[string]struct {
		Subject string
		Object  string
		err     error
	}{
		"retrieve existing policy":     {uid, uid, nil},
		"retrieve non-existing policy": {"unknown", "unknown", nil},
	}

	for desc, tc := range cases {
		pm := clients.Page{
			Subject: tc.Subject,
			Object:  tc.Object,
		}
		_, err := repo.Retrieve(context.Background(), pm)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
	}
}

func TestPoliciesUpdate(t *testing.T) {
	t.Cleanup(func() { cleanUpPolicies(t) })
	repo := postgres.NewPolicyRepo(database)
	crepo := postgres.NewClientRepo(database)

	cid := generateULID(t)
	pid := generateULID(t)

	client := clients.Client{
		ID:   cid,
		Name: "policy-update@example.com",
		Credentials: clients.Credentials{
			Identity: "policy-update@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}

	_, err := crepo.Save(context.Background(), client)
	require.Nil(t, err, fmt.Sprintf("unexpected error during saving client: %s", err))

	policy := clients.Policy{
		OwnerID: cid,
		Subject: cid,
		Object:  pid,
		Actions: []string{"c_delete"},
	}
	err = repo.Save(context.Background(), policy)
	require.Nil(t, err, fmt.Sprintf("unexpected error during saving policy: %s", err))

	cases := []struct {
		desc   string
		policy clients.Policy
		resp   clients.Policy
		err    error
	}{
		{
			desc: "update policy successfully",
			policy: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_update"},
			},
			resp: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_update"},
			},
			err: nil,
		},
		{
			desc: "update policy with missing owner id",
			policy: clients.Policy{
				OwnerID: "",
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_delete"},
			},
			resp: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_delete"},
			},
			err: nil,
		},
		{
			desc: "update policy with missing subject",
			policy: clients.Policy{
				OwnerID: cid,
				Subject: "",
				Object:  pid,
				Actions: []string{"c_add"},
			},
			resp: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_delete"},
			},
			err: apiutil.ErrMissingPolicySub,
		},
		{
			desc: "update policy with missing object",
			policy: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  "",
				Actions: []string{"c_add"},
			},
			resp: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_delete"},
			},

			err: apiutil.ErrMissingPolicyObj,
		},
		{
			desc: "update policy with missing action",
			policy: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{""},
			},
			resp: clients.Policy{
				OwnerID: cid,
				Subject: cid,
				Object:  pid,
				Actions: []string{"c_delete"},
			},
			err: apiutil.ErrMissingPolicyAct,
		},
	}

	for _, tc := range cases {
		err := repo.Update(context.Background(), tc.policy)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		policPage, err := repo.Retrieve(context.Background(), clients.Page{
			Offset:  uint64(0),
			Limit:   uint64(10),
			Subject: tc.policy.Subject,
		})
		if err == nil {
			assert.Equal(t, tc.resp, policPage.Policies[0], fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		}
	}
}

func TestPoliciesRetrievalAll(t *testing.T) {
	t.Cleanup(func() { cleanUpPolicies(t) })
	postgres.NewDatabase(db, tracer)
	repo := postgres.NewPolicyRepo(database)
	crepo := postgres.NewClientRepo(database)

	var nPolicies = uint64(10)

	clientA := clients.Client{
		ID:   generateULID(t),
		Name: "policyA-retrievalall@example.com",
		Credentials: clients.Credentials{
			Identity: "policyA-retrievalall@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}
	clientB := clients.Client{
		ID:   generateULID(t),
		Name: "policyB-retrievalall@example.com",
		Credentials: clients.Credentials{
			Identity: "policyB-retrievalall@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}

	clientA, err := crepo.Save(context.Background(), clientA)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	clientB, err = crepo.Save(context.Background(), clientB)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	for i := uint64(0); i < nPolicies; i++ {
		obj := fmt.Sprintf("TestRetrieveAll%d@example.com", i)
		if i%2 == 0 {
			policy := clients.Policy{
				OwnerID: clientA.ID,
				Subject: clientA.ID,
				Object:  obj,
				Actions: []string{"c_delete"},
			}
			err = repo.Save(context.Background(), policy)
			require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		}
		policy := clients.Policy{
			Subject: clientB.ID,
			Object:  obj,
			Actions: []string{"c_add", "c_update"},
		}
		err = repo.Save(context.Background(), policy)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	}

	cases := map[string]struct {
		size uint64
		pm   clients.Page
	}{
		"retrieve all policies with limit and offset": {
			pm: clients.Page{
				Offset: 5,
				Limit:  nPolicies,
			},
			size: 10,
		},
		"retrieve all policies by owner id": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
			},
			size: 5,
		},
		"retrieve policies by wrong owner id": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
			},
			size: 0,
		},
		"retrieve all policies by Subject": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				Subject: clientA.ID,
			},
			size: 5,
		},
		"retrieve policies by wrong Subject": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				Subject: "wrongSubject",
			},
			size: 0,
		},

		"retrieve all policies by Object": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nPolicies,
				Total:  nPolicies,
				Object: "TestRetrieveAll1@example.com",
			},
			size: 1,
		},
		"retrieve policies by wrong Object": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nPolicies,
				Total:  nPolicies,
				Object: "TestRetrieveAll45@example.com",
			},
			size: 0,
		},
		"retrieve all policies by Action": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nPolicies,
				Total:  nPolicies,
				Action: "c_delete",
			},
			size: 5,
		},
		"retrieve policies by wrong Action": {
			pm: clients.Page{
				Offset: 0,
				Limit:  nPolicies,
				Total:  nPolicies,
				Action: "wrongAction",
			},
			size: 0,
		},
		"retrieve all policies by owner id and subject": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
				Subject: clientA.ID,
			},
			size: 5,
		},
		"retrieve policies by wrong owner id and correct subject": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
				Subject: clientA.ID,
			},
			size: 0,
		},
		"retrieve policies by correct owner id and wrong subject": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
				Subject: "wrongSubject",
			},
			size: 0,
		},
		"retrieve policies by wrong owner id and wrong subject": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
			},
			size: 0,
		},
		"retrieve all policies by owner id and object": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
				Object:  "TestRetrieveAll2@example.com",
			},
			size: 1,
		},
		"retrieve policies by wrong owner id and correct object": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
				Object:  "TestRetrieveAll1@example.com",
			},
			size: 0,
		},
		"retrieve policies by correct owner id and wrong object": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
				Object:  "TestRetrieveAll45@example.com",
			},
			size: 0,
		},
		"retrieve policies by wrong owner id and wrong object": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
				Object:  "TestRetrieveAll45@example.com",
			},
			size: 0,
		},
		"retrieve all policies by owner id and action": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
				Action:  "c_delete",
			},
			size: 5,
		},
		"retrieve policies by wrong owner id and correct action": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
				Action:  "c_delete",
			},
			size: 0,
		},
		"retrieve policies by correct owner id and wrong action": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientA.ID,
				Action:  "wrongAction",
			},
			size: 0,
		},
		"retrieve policies by wrong owner id and wrong action": {
			pm: clients.Page{
				Offset:  0,
				Limit:   nPolicies,
				Total:   nPolicies,
				OwnerID: clientB.ID,
				Action:  "wrongAction",
			},
			size: 0,
		},
	}
	for desc, tc := range cases {
		page, err := repo.Retrieve(context.Background(), tc.pm)
		size := uint64(len(page.Policies))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", desc, tc.size, size))
		assert.Nil(t, err, fmt.Sprintf("%s: expected no error got %d\n", desc, err))
	}
}

func TestPoliciesDelete(t *testing.T) {
	t.Cleanup(func() { cleanUpPolicies(t) })
	repo := postgres.NewPolicyRepo(database)
	crepo := postgres.NewClientRepo(database)

	client := clients.Client{
		ID:   generateULID(t),
		Name: "policy-delete@example.com",
		Credentials: clients.Credentials{
			Identity: "policy-delete@example.com",
			Secret:   "pass",
		},
		Status: clients.EnabledStatusKey,
	}

	subject, err := crepo.Save(context.Background(), client)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	objectID := generateULID(t)

	policy := clients.Policy{
		OwnerID: subject.ID,
		Subject: subject.ID,
		Object:  objectID,
		Actions: []string{"c_delete"},
	}

	err = repo.Save(context.Background(), policy)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := map[string]struct {
		Subject string
		Object  string
		err     error
	}{
		"delete non-existing policy":                      {"unknown", "unknown", nil},
		"delete non-existing policy with correct subject": {subject.ID, "unknown", nil},
		"delete non-existing policy with correct object":  {"unknown", objectID, nil},
		"delete existing policy":                          {subject.ID, objectID, nil},
	}

	for desc, tc := range cases {
		policy := clients.Policy{
			Subject: tc.Subject,
			Object:  tc.Object,
		}
		err := repo.Delete(context.Background(), policy)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
	}
	pm := clients.Page{
		OwnerID: subject.ID,
		Subject: subject.ID,
		Object:  objectID,
		Action:  "c_delete",
	}
	policyPage, err := repo.Retrieve(context.Background(), pm)
	assert.Equal(t, uint64(0), policyPage.Total, fmt.Sprintf("retrieve policies unexpected total %d\n", policyPage.Total))
	require.Nil(t, err, fmt.Sprintf("retrieve policies unexpected error: %s", err))
}

func cleanUpPolicies(t *testing.T) {
	_, err := db.Exec("DELETE FROM policies")
	require.Nil(t, err, fmt.Sprintf("clean policies unexpected error: %s", err))
}
