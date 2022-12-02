package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
)

var _ clients.GroupRepository = (*groupRepository)(nil)

type groupRepository struct {
	db Database
}

// NewGroupRepo instantiates a PostgreSQL implementation of group
// repository.
func NewGroupRepo(db Database) clients.GroupRepository {
	return &groupRepository{
		db: db,
	}
}

// TODO - check parent group write access.
func (repo groupRepository) Save(ctx context.Context, g clients.Group) (clients.Group, error) {
	q := `INSERT INTO groups (name, description, id, owner_id, metadata, created_at, updated_at)
		VALUES (:name, :description, :id, :owner_id, :metadata, :created_at, :updated_at)
		RETURNING id, name, description, owner_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, updated_at;`
	if g.ParentID != "" {
		q = `INSERT INTO groups (name, description, id, owner_id, parent_id, metadata, created_at, updated_at)
		VALUES (:name, :description, :id, :owner_id, :parent_id, :metadata, :created_at, :updated_at)
		RETURNING id, name, description, owner_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, updated_at;`
	}
	dbg, err := toDBGroup(g)
	if err != nil {
		return clients.Group{}, err
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbg)
	if err != nil {
		return clients.Group{}, handleError(err, errors.ErrCreateEntity)
	}

	defer row.Close()
	row.Next()
	dbg = dbGroup{}
	if err := row.StructScan(&dbg); err != nil {
		return clients.Group{}, err
	}

	return toGroup(dbg)
}

func (repo groupRepository) RetrieveByID(ctx context.Context, id string) (clients.Group, error) {
	dbu := dbGroup{
		ID: id,
	}
	q := `SELECT id, name, owner_id, COALESCE(parent_id, '') AS parent_id, description, metadata, path, nlevel(path) as level, created_at, updated_at FROM groups
	    WHERE id = $1`
	if err := repo.db.QueryRowxContext(ctx, q, id).StructScan(&dbu); err != nil {
		if err == sql.ErrNoRows {
			return clients.Group{}, errors.Wrap(errors.ErrNotFound, err)

		}
		return clients.Group{}, errors.Wrap(errors.ErrViewEntity, err)
	}
	return toGroup(dbu)
}

func (repo groupRepository) RetrieveAll(ctx context.Context, gm clients.GroupsPage) (clients.GroupsPage, error) {
	query, err := buildQuery(gm)
	if err != nil {
		return clients.GroupsPage{}, err
	}
	q := fmt.Sprintf(`SELECT id, owner_id, COALESCE(parent_id, '') AS parent_id, name, description, metadata, path, nlevel(path) as level, created_at, updated_at
					FROM groups %s ORDER BY path LIMIT :limit OFFSET :offset;`, query)
	dbPage, err := toDBGroupPage(gm)
	if err != nil {
		return clients.GroupsPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, dbPage)
	if err != nil {
		return clients.GroupsPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}
	defer rows.Close()

	items, err := repo.processRows(rows)
	if err != nil {
		return clients.GroupsPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}

	cq := "SELECT COUNT(*) FROM groups g"
	if query != "" {
		cq = fmt.Sprintf(" %s %s", cq, query)
	}

	total, err := total(ctx, repo.db, cq, dbPage)
	if err != nil {
		return clients.GroupsPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}

	page := gm
	page.Groups = items
	page.Total = total

	return page, nil
}

func (repo groupRepository) Update(ctx context.Context, g clients.Group) (clients.Group, error) {
	var query []string
	var upq string
	if g.Name != "" {
		query = append(query, "name = :name,")
	}
	if g.Description != "" {
		query = append(query, "description = :description,")
	}
	if g.Metadata != nil {
		query = append(query, "metadata = :metadata,")
	}
	if len(query) > 0 {
		upq = strings.Join(query, " ")
	}
	q := fmt.Sprintf(`UPDATE groups SET %s updated_at = :updated_at
		WHERE id = :id
		RETURNING id, name, description, owner_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, updated_at`, upq)

	dbu, err := toDBGroup(g)
	if err != nil {
		return clients.Group{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}

	row, err := repo.db.NamedQueryContext(ctx, q, dbu)
	if err != nil {
		return clients.Group{}, handleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	row.Next()
	dbu = dbGroup{}
	if err := row.StructScan(&dbu); err != nil {
		return clients.Group{}, err
	}

	return toGroup(dbu)
}

func (repo groupRepository) Delete(ctx context.Context, id string) error {
	qd := `DELETE FROM groups WHERE id = :id`
	group := clients.Group{
		ID: id,
	}
	dbg, err := toDBGroup(group)
	if err != nil {
		return errors.Wrap(errors.ErrUpdateEntity, err)
	}

	if _, err := repo.db.NamedExecContext(ctx, qd, dbg); err != nil {
		return errors.Wrap(errors.ErrRemoveEntity, err)
	}

	return nil
}

func (repo groupRepository) Members(ctx context.Context, groupID string, pm clients.Page) (clients.MembersPage, error) {
	emq, err := buildPMQuery(pm)
	if err != nil {
		return clients.MembersPage{}, err
	}

	q := fmt.Sprintf(`SELECT clients.id, clients.name, clients.tags, clients.metadata, clients.identity, clients.status, clients.created_at
		FROM clients INNER JOIN policies ON clients.id=policies.subject %s AND policies.object = :group_id
	  	ORDER BY created_at LIMIT :limit OFFSET :offset;`, emq)
	dbPage, err := toDBClientsPage(pm)
	if err != nil {
		return clients.MembersPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}
	dbPage.GroupID = groupID
	rows, err := repo.db.NamedQueryContext(ctx, q, dbPage)
	if err != nil {
		return clients.MembersPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembers, err)
	}
	defer rows.Close()

	var items []clients.Client
	for rows.Next() {
		dbc := dbClient{}
		if err := rows.StructScan(&dbc); err != nil {
			return clients.MembersPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembers, err)
		}

		c, err := toClient(dbc)
		if err != nil {
			return clients.MembersPage{}, err
		}

		items = append(items, c)
	}
	cq := fmt.Sprintf(`SELECT COUNT(*)
		FROM clients INNER JOIN policies ON clients.id=policies.subject %s AND policies.object = :group_id;`, emq)

	total, err := total(ctx, repo.db, cq, dbPage)
	if err != nil {
		return clients.MembersPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembers, err)
	}

	page := clients.MembersPage{
		Members: items,
		Page: clients.Page{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
		},
	}
	return page, nil
}

func buildQuery(pm clients.GroupsPage) (string, error) {
	queries := []string{}
	genesis := ""
	if pm.ID == "" && pm.Level != 0 {
		cmp := "<="
		if pm.Direction > 0 {
			cmp = ">="
		}
		queries = append(queries, fmt.Sprintf("nlevel(path) %s :level", cmp))
	}
	if pm.ID != "" {
		genesis = ", groups node"
		queries = append(queries, "node.id = :id")
		switch {
		case pm.Direction >= 0: // ancestors
			q := "node.path @> g.path"
			if pm.Level != 0 {
				q += " AND nlevel(g.path) - nlevel(node.path) <= :level"
			}
			queries = append(queries, q)
		case pm.Direction < 0: // descendants
			q := "g.path @> node.path"
			if pm.Level != 0 {
				q += " AND nlevel(node.path) - nlevel(g.path) <= :level"
			}
			queries = append(queries, q)
		}
	}

	if pm.Name != "" {
		queries = append(queries, "g.name = :name")
	}
	if pm.OwnerID != "" {
		queries = append(queries, fmt.Sprintf("owner_id = '%s'", pm.OwnerID))
	}
	if len(pm.Metadata) > 0 {
		queries = append(queries, "'g.metadata @> :metadata'")
	}
	if len(queries) > 0 {
		return fmt.Sprintf("%s WHERE %s", genesis, strings.Join(queries, " AND ")), nil
	}
	return "", nil
}

type dbGroup struct {
	ID          string    `db:"id"`
	ParentID    string    `db:"parent_id"`
	OwnerID     string    `db:"owner_id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	Level       int       `db:"level"`
	Path        string    `db:"path,omitempty"`
	Metadata    []byte    `db:"metadata"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

func toDBGroup(g clients.Group) (dbGroup, error) {
	data := []byte("{}")
	if len(g.Metadata) > 0 {
		b, err := json.Marshal(g.Metadata)
		if err != nil {
			return dbGroup{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}
	return dbGroup{
		ID:          g.ID,
		Name:        g.Name,
		ParentID:    g.ParentID,
		OwnerID:     g.OwnerID,
		Description: g.Description,
		Metadata:    data,
		Path:        g.Path,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}, nil
}

func toGroup(g dbGroup) (clients.Group, error) {
	var metadata clients.Metadata
	if g.Metadata != nil {
		if err := json.Unmarshal([]byte(g.Metadata), &metadata); err != nil {
			return clients.Group{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
	}
	return clients.Group{
		ID:          g.ID,
		Name:        g.Name,
		ParentID:    g.ParentID,
		OwnerID:     g.OwnerID,
		Description: g.Description,
		Metadata:    metadata,
		Level:       g.Level,
		Path:        g.Path,
		UpdatedAt:   g.UpdatedAt,
		CreatedAt:   g.CreatedAt,
	}, nil
}

func (gr groupRepository) processRows(rows *sqlx.Rows) ([]clients.Group, error) {
	var items []clients.Group
	for rows.Next() {
		dbg := dbGroup{}
		if err := rows.StructScan(&dbg); err != nil {
			return items, err
		}
		group, err := toGroup(dbg)
		if err != nil {
			return items, err
		}
		items = append(items, group)
	}
	return items, nil
}

func toDBGroupPage(pm clients.GroupsPage) (dbGroupPage, error) {
	level := clients.MaxLevel
	if pm.Level < clients.MaxLevel {
		level = pm.Level
	}
	data := []byte("{}")
	if len(pm.Metadata) > 0 {
		b, err := json.Marshal(pm.Metadata)
		if err != nil {
			return dbGroupPage{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}
	return dbGroupPage{
		ID:       pm.ID,
		Name:     pm.Name,
		Metadata: data,
		Path:     pm.Path,
		Level:    level,
		Total:    pm.Total,
		Offset:   pm.Offset,
		Limit:    pm.Limit,
		ParentID: pm.ID,
		OwnerID:  pm.OwnerID,
	}, nil
}

type dbGroupPage struct {
	ClientID string `db:"client_id"`
	ID       string `db:"id"`
	Name     string `db:"name"`
	ParentID string `db:"parent_id"`
	OwnerID  string `db:"owner_id"`
	Metadata []byte `db:"metadata"`
	Path     string `db:"path"`
	Level    uint64 `db:"level"`
	Total    uint64 `db:"total"`
	Limit    uint64 `db:"limit"`
	Offset   uint64 `db:"offset"`
}
