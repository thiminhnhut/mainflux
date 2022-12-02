package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/clients/postgres"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/ulid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	maxDescSize = 1024
	maxLevel    = uint64(5)
	groupName   = "group"
	description = "description"
)

var (
	validDesc   = strings.Repeat("m", 100)
	invalidDesc = strings.Repeat("m", maxDescSize+1)
	metadata    = clients.Metadata{
		"admin": "true",
	}
	ulidProvider = ulid.New()
)

func generateGroupID(t *testing.T) string {
	grpID, err := ulidProvider.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	return grpID
}

func TestGroupSave(t *testing.T) {
	t.Cleanup(func() { cleanUpGroup(t) })
	groupRepo := postgres.NewGroupRepo(database)

	usrID := generateULID(t)
	grpID := generateGroupID(t)

	cases := []struct {
		desc  string
		group clients.Group
		err   error
	}{
		{
			desc: "create new group successfully",
			group: clients.Group{
				ID:   grpID,
				Name: groupName,
			},
			err: nil,
		},
		{
			desc: "create a new group with an existing name",
			group: clients.Group{
				ID:   grpID,
				Name: groupName,
			},
			err: errors.ErrConflict,
		},
		{
			desc: "create group with an invalid name",
			group: clients.Group{
				ID:   generateGroupID(t),
				Name: invalidName,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "create a group with invalid ID",
			group: clients.Group{
				ID:          usrID,
				Name:        "withInvalidDescription",
				Description: invalidDesc,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "create group with description",
			group: clients.Group{
				ID:          generateGroupID(t),
				Name:        "withDescription",
				Description: validDesc,
			},
			err: nil,
		},
		{
			desc: "create group with invalid description",
			group: clients.Group{
				ID:          generateGroupID(t),
				Name:        "withInvalidDescription",
				Description: invalidDesc,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "create group with parent",
			group: clients.Group{
				ID:       generateGroupID(t),
				ParentID: grpID,
				Name:     "withParent",
			},
			err: nil,
		},
		{
			desc: "create a group with an invalid parent",
			group: clients.Group{
				ID:       generateGroupID(t),
				ParentID: invalidName,
				Name:     "withInvalidParent",
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "create a group with an owner",
			group: clients.Group{
				ID:      generateGroupID(t),
				OwnerID: usrID,
				Name:    "withOwner",
			},
			err: nil,
		},
		{
			desc: "create a group with an invalid owner",
			group: clients.Group{
				ID:      generateGroupID(t),
				OwnerID: invalidName,
				Name:    "withInvalidOwner",
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "create a group with metadata",
			group: clients.Group{
				ID:       generateGroupID(t),
				Name:     "withMetadata",
				Metadata: metadata,
			},
			err: nil,
		},
	}

	for _, tc := range cases {
		_, err := groupRepo.Save(context.Background(), tc.group)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}

}

func TestGroupRetrieveByID(t *testing.T) {
	t.Cleanup(func() { cleanUpGroup(t) })
	groupRepo := postgres.NewGroupRepo(database)

	uid := generateULID(t)
	group1 := clients.Group{
		ID:      generateGroupID(t),
		Name:    groupName + "TestGroupRetrieveByID1",
		OwnerID: uid,
	}

	_, err := groupRepo.Save(context.Background(), group1)
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	retrieved, err := groupRepo.RetrieveByID(context.Background(), group1.ID)
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	assert.True(t, retrieved.ID == group1.ID, fmt.Sprintf("Save group, ID: expected %s got %s\n", group1.ID, retrieved.ID))

	// Round to milliseconds as otherwise saving and retrieving from DB
	// adds rounding error.
	creationTime := time.Now().UTC().Round(time.Millisecond)
	group2 := clients.Group{
		ID:          generateGroupID(t),
		Name:        groupName + "TestGroupRetrieveByID",
		OwnerID:     uid,
		ParentID:    group1.ID,
		CreatedAt:   creationTime,
		UpdatedAt:   creationTime,
		Description: description,
		Metadata:    metadata,
	}

	_, err = groupRepo.Save(context.Background(), group2)
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	retrieved, err = groupRepo.RetrieveByID(context.Background(), group2.ID)
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	assert.True(t, retrieved.ID == group2.ID, fmt.Sprintf("Save group, ID: expected %s got %s\n", group2.ID, retrieved.ID))
	assert.True(t, retrieved.CreatedAt.Equal(creationTime), fmt.Sprintf("Save group, CreatedAt: expected %s got %s\n", creationTime, retrieved.CreatedAt))
	assert.True(t, retrieved.UpdatedAt.Equal(creationTime), fmt.Sprintf("Save group, UpdatedAt: expected %s got %s\n", creationTime, retrieved.UpdatedAt))
	assert.True(t, retrieved.Level == 2, fmt.Sprintf("Save group, Level: expected %d got %d\n", retrieved.Level, 2))
	assert.True(t, retrieved.ParentID == group1.ID, fmt.Sprintf("Save group, Level: expected %s got %s\n", group1.ID, retrieved.ParentID))
	assert.True(t, retrieved.Description == description, fmt.Sprintf("Save group, Description: expected %v got %v\n", retrieved.Description, description))
	assert.True(t, retrieved.Path == fmt.Sprintf("%s.%s", group1.ID, group2.ID), fmt.Sprintf("Save group, Path: expected %s got %s\n", fmt.Sprintf("%s.%s", group1.ID, group2.ID), retrieved.Path))

	retrieved, err = groupRepo.RetrieveByID(context.Background(), generateULID(t))
	assert.True(t, errors.Contains(err, errors.ErrNotFound), fmt.Sprintf("Retrieve group: expected %s got %s\n", errors.ErrNotFound, err))
}

func TestGroupRetrieveAll(t *testing.T) {
	t.Cleanup(func() { cleanUpGroup(t) })
	groupRepo := postgres.NewGroupRepo(database)

	uid := generateULID(t)

	n := uint64(maxLevel)
	parentID := ""
	for i := uint64(0); i < n; i++ {
		creationTime := time.Now().UTC()
		group := clients.Group{
			ID:        generateGroupID(t),
			Name:      fmt.Sprintf("%s-%d", groupName, i),
			OwnerID:   uid,
			ParentID:  parentID,
			CreatedAt: creationTime,
			UpdatedAt: creationTime,
		}
		_, err := groupRepo.Save(context.Background(), group)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
		parentID = group.ID
	}

	cases := map[string]struct {
		Size     uint64
		Metadata clients.GroupsPage
	}{
		"retrieve all groups": {
			Metadata: clients.GroupsPage{
				Page: clients.Page{
					Total: n,
					Limit: n,
				},
				Level: maxLevel,
			},
			Size: n,
		},
		"retrieve all groups with offset and limit": {
			Metadata: clients.GroupsPage{
				Page: clients.Page{
					Total:  n,
					Offset: 2,
					Limit:  n,
				},
				Level: maxLevel,
			},
			Size: 3,
		},
		"retrieve all groups with offset greater than limit": {
			Metadata: clients.GroupsPage{
				Page: clients.Page{
					Total:  n,
					Offset: 10,
					Limit:  n,
				},
				Level: maxLevel,
			},
			Size: 0,
		},
		"retrieve all groups with owner id": {
			Metadata: clients.GroupsPage{
				Page: clients.Page{
					Total:   n,
					Limit:   n,
					OwnerID: uid,
				},
				Level: maxLevel,
			},
			Size: n,
		},
	}

	for desc, tc := range cases {
		page, err := groupRepo.RetrieveAll(context.Background(), tc.Metadata)
		size := len(page.Groups)
		assert.Equal(t, tc.Size, uint64(size), fmt.Sprintf("%s: expected size %d got %d\n", desc, tc.Size, size))
		assert.Nil(t, err, fmt.Sprintf("%s: expected no error got %d\n", desc, err))
	}
}

func TestGroupUpdate(t *testing.T) {
	t.Cleanup(func() { cleanUpGroup(t) })
	groupRepo := postgres.NewGroupRepo(database)

	uid := generateULID(t)

	creationTime := time.Now().UTC()
	updateTime := time.Now().UTC()
	groupID := generateGroupID(t)

	group := clients.Group{
		ID:          groupID,
		Name:        groupName + "TestGroupUpdate",
		OwnerID:     uid,
		CreatedAt:   creationTime,
		UpdatedAt:   creationTime,
		Description: description,
		Metadata:    metadata,
	}
	updatedName := groupName + "Updated"
	updatedMetadata := clients.Metadata{"admin": "false"}
	updatedDescription := description + "updated"
	_, err := groupRepo.Save(context.Background(), group)
	require.Nil(t, err, fmt.Sprintf("group save got unexpected error: %s", err))

	retrieved, err := groupRepo.RetrieveByID(context.Background(), group.ID)
	require.Nil(t, err, fmt.Sprintf("group save got unexpected error: %s", err))

	cases := []struct {
		desc          string
		groupUpdate   clients.Group
		groupExpected clients.Group
		err           error
	}{
		{
			desc: "update group name for existing id",
			groupUpdate: clients.Group{
				ID:        groupID,
				Name:      updatedName,
				UpdatedAt: updateTime,
			},
			groupExpected: clients.Group{
				Name:        updatedName,
				Metadata:    retrieved.Metadata,
				Description: retrieved.Description,
			},
			err: nil,
		},
		{
			desc: "update group metadata for existing id",
			groupUpdate: clients.Group{
				ID:        groupID,
				UpdatedAt: updateTime,
				Metadata:  updatedMetadata,
			},
			groupExpected: clients.Group{
				Name:        updatedName,
				UpdatedAt:   updateTime,
				Metadata:    updatedMetadata,
				Description: retrieved.Description,
			},
			err: nil,
		},
		{
			desc: "update group description for existing id",
			groupUpdate: clients.Group{
				ID:          groupID,
				UpdatedAt:   updateTime,
				Description: updatedDescription,
			},
			groupExpected: clients.Group{
				Name:        updatedName,
				Description: updatedDescription,
				UpdatedAt:   updateTime,
				Metadata:    updatedMetadata,
			},
			err: nil,
		},
		{
			desc: "update group name and metadata for existing id",
			groupUpdate: clients.Group{
				ID:        groupID,
				Name:      updatedName,
				UpdatedAt: updateTime,
				Metadata:  updatedMetadata,
			},
			groupExpected: clients.Group{
				Name:        updatedName,
				UpdatedAt:   updateTime,
				Metadata:    updatedMetadata,
				Description: updatedDescription,
			},
			err: nil,
		},
		{
			desc: "update group for invalid name",
			groupUpdate: clients.Group{
				ID:   groupID,
				Name: invalidName,
			},
			err: errors.ErrMalformedEntity,
		},
		{
			desc: "update group for invalid description",
			groupUpdate: clients.Group{
				ID:          groupID,
				Description: invalidDesc,
			},
			err: errors.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		updated, err := groupRepo.Update(context.Background(), tc.groupUpdate)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.True(t, updated.Name == tc.groupExpected.Name, fmt.Sprintf("%s:Name: expected %s got %s\n", tc.desc, tc.groupExpected.Name, updated.Name))
			assert.True(t, updated.Description == tc.groupExpected.Description, fmt.Sprintf("%s:Description: expected %s got %s\n", tc.desc, tc.groupExpected.Description, updated.Description))
			assert.True(t, updated.Metadata["admin"] == tc.groupExpected.Metadata["admin"], fmt.Sprintf("%s:Metadata: expected %d got %d\n", tc.desc, tc.groupExpected.Metadata["admin"], updated.Metadata["admin"]))
		}
	}
}

func TestGroupDelete(t *testing.T) {
	t.Cleanup(func() { cleanUpGroup(t) })
	groupRepo := postgres.NewGroupRepo(database)

	uid, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	creationTime := time.Now().UTC()
	groupParent := clients.Group{
		ID:        generateGroupID(t),
		Name:      groupName + "Updated",
		OwnerID:   uid,
		CreatedAt: creationTime,
		UpdatedAt: creationTime,
	}

	_, err = groupRepo.Save(context.Background(), groupParent)
	require.Nil(t, err, fmt.Sprintf("group save got unexpected error: %s", err))

	creationTime = time.Now().UTC()
	groupChild1 := clients.Group{
		ID:        generateGroupID(t),
		ParentID:  groupParent.ID,
		Name:      groupName + "child1",
		OwnerID:   uid,
		CreatedAt: creationTime,
		UpdatedAt: creationTime,
	}

	creationTime = time.Now().UTC()
	groupChild2 := clients.Group{
		ID:        generateGroupID(t),
		ParentID:  groupParent.ID,
		Name:      groupName + "child2",
		OwnerID:   uid,
		CreatedAt: creationTime,
		UpdatedAt: creationTime,
	}

	_, err = groupRepo.Save(context.Background(), groupChild1)
	require.Nil(t, err, fmt.Sprintf("group save got unexpected error: %s", err))

	_, err = groupRepo.Save(context.Background(), groupChild2)
	require.Nil(t, err, fmt.Sprintf("group save got unexpected error: %s", err))

	err = groupRepo.Delete(context.Background(), groupParent.ID)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("delete parent with children with members: expected %v got %v\n", nil, err))

	err = groupRepo.Delete(context.Background(), groupChild1.ID)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("delete empty group: expected %v got %v\n", nil, err))

	err = groupRepo.Delete(context.Background(), groupChild2.ID)
	assert.True(t, errors.Contains(err, nil), fmt.Sprintf("delete empty group: expected %v got %v\n", nil, err))

	_, err = groupRepo.RetrieveByID(context.Background(), groupChild1.ID)
	assert.True(t, errors.Contains(err, errors.ErrNotFound), fmt.Sprintf("retrieve child after parent removed: expected %v got %v\n", nil, err))
}

func TestGroupMembers(t *testing.T) {
	t.Cleanup(func() { cleanUpClient(t) })
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
	client.Credentials.Secret = ""

	cases := map[string]struct {
		ID  string
		err error
	}{
		"retrieve members for existing group":     {group.ID, nil},
		"retrieve members for non-existing group": {wrongID, nil},
	}
	for desc, tc := range cases {
		mp, err := grepo.Members(context.Background(), tc.ID, clients.Page{Total: 10, Offset: 0, Limit: 10})
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
		if tc.ID == group.ID {
			assert.ElementsMatch(t, mp.Members, []clients.Client{client}, fmt.Sprintf("%s: expected %v got %v\n", desc, []clients.Client{client}, mp.Members))
		}
	}
}

func cleanUpGroup(t *testing.T) {
	_, err := db.Exec("DELETE FROM policies")
	require.Nil(t, err, fmt.Sprintf("clean policies unexpected error: %s", err))
	_, err = db.Exec("DELETE FROM groups")
	require.Nil(t, err, fmt.Sprintf("clean groups unexpected error: %s", err))
	_, err = db.Exec("DELETE FROM clients")
	require.Nil(t, err, fmt.Sprintf("clean clients unexpected error: %s", err))
}
