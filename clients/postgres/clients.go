package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgtype" // required for SQL access
	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
)

var _ clients.ClientRepository = (*clientRepo)(nil)

type clientRepo struct {
	db Database
}

// NewClientRepo instantiates a PostgreSQL
// implementation of Clients repository.
func NewClientRepo(db Database) clients.ClientRepository {
	return &clientRepo{
		db: db,
	}
}

func (repo clientRepo) Save(ctx context.Context, c clients.Client) (clients.Client, error) {
	q := `INSERT INTO clients (id, name, tags, owner, identity, secret, metadata, created_at, updated_at, status)
        VALUES (:id, :name, :tags, :owner, :identity, :secret, :metadata, :created_at, :updated_at, :status)
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`
	if c.Owner == "" {
		q = `INSERT INTO clients (id, name, tags, identity, secret, metadata, created_at, updated_at, status)
        VALUES (:id, :name, :tags, :identity, :secret, :metadata, :created_at, :updated_at, :status)
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`
	}
	dbc, err := toDBClient(c)
	if err != nil {
		return clients.Client{}, errors.Wrap(errors.ErrCreateEntity, err)
	}

	row, err := repo.db.NamedQueryContext(ctx, q, dbc)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrCreateEntity)
	}

	defer row.Close()
	row.Next()
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func (repo clientRepo) RetrieveByID(ctx context.Context, id string) (clients.Client, error) {
	q := `SELECT id, name, tags, COALESCE(owner, '') AS owner, identity, secret, metadata, created_at, updated_at, status 
        FROM clients
        WHERE id = $1`

	dbc := dbClient{
		ID: id,
	}

	if err := repo.db.QueryRowxContext(ctx, q, id).StructScan(&dbc); err != nil {
		if err == sql.ErrNoRows {
			return clients.Client{}, errors.Wrap(errors.ErrNotFound, err)

		}
		return clients.Client{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	return toClient(dbc)
}

func (repo clientRepo) RetrieveByIdentity(ctx context.Context, identity string) (clients.Client, error) {
	q := fmt.Sprintf(`SELECT id, name, tags, COALESCE(owner, '') AS owner, identity, secret, metadata, created_at, updated_at, status
        FROM clients
        WHERE identity = $1 AND status = %d`, clients.EnabledStatusKey)

	dbc := dbClient{
		Identity: identity,
	}

	if err := repo.db.QueryRowxContext(ctx, q, identity).StructScan(&dbc); err != nil {
		if err == sql.ErrNoRows {
			return clients.Client{}, errors.Wrap(errors.ErrNotFound, err)

		}
		return clients.Client{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	return toClient(dbc)
}

func (repo clientRepo) RetrieveAll(ctx context.Context, pm clients.Page) (clients.ClientsPage, error) {
	query, err := buildPMQuery(pm)
	if err != nil {
		return clients.ClientsPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	q := fmt.Sprintf(`SELECT id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at
        FROM clients %s
        ORDER BY created_at LIMIT :limit OFFSET :offset;`, query)

	dbPage, err := toDBClientsPage(pm)
	if err != nil {
		return clients.ClientsPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, dbPage)
	if err != nil {
		return clients.ClientsPage{}, errors.Wrap(clients.ErrFailedToRetrieveAll, err)
	}
	defer rows.Close()

	var items []clients.Client
	for rows.Next() {
		dbc := dbClient{}
		if err := rows.StructScan(&dbc); err != nil {
			return clients.ClientsPage{}, errors.Wrap(errors.ErrViewEntity, err)
		}

		c, err := toClient(dbc)
		if err != nil {
			return clients.ClientsPage{}, err
		}

		items = append(items, c)
	}
	cq := fmt.Sprintf(`SELECT COUNT(*) FROM clients %s;`, query)

	total, err := total(ctx, repo.db, cq, dbPage)
	if err != nil {
		return clients.ClientsPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	page := clients.ClientsPage{
		Clients: items,
		Page: clients.Page{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
		},
	}

	return page, nil
}

func (repo clientRepo) Memberships(ctx context.Context, clientID string, gm clients.GroupsPage) (clients.MembershipsPage, error) {
	query, err := buildQuery(gm)
	if err != nil {
		return clients.MembershipsPage{}, err
	}

	q := fmt.Sprintf(`SELECT groups.id, groups.owner_id, groups.name, groups.description, groups.metadata, groups.created_at
        FROM groups INNER JOIN policies ON groups.id=policies.object %s AND policies.subject = :client_id
        ORDER BY path LIMIT :limit OFFSET :offset;`, query)
	dbPage, err := toDBGroupPage(gm)
	if err != nil {
		return clients.MembershipsPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembership, err)
	}
	dbPage.ClientID = clientID
	rows, err := repo.db.NamedQueryContext(ctx, q, dbPage)
	if err != nil {
		return clients.MembershipsPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembership, err)
	}
	defer rows.Close()

	var items []clients.Group
	for rows.Next() {
		dbg := dbGroup{}
		if err := rows.StructScan(&dbg); err != nil {
			return clients.MembershipsPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembership, err)
		}
		group, err := toGroup(dbg)
		if err != nil {
			return clients.MembershipsPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembership, err)
		}
		items = append(items, group)
	}

	cq := fmt.Sprintf(`SELECT COUNT(*) FROM groups INNER JOIN policies
        ON groups.id=policies.object %s AND policies.subject = :client_id`, query)

	total, err := total(ctx, repo.db, cq, dbPage)
	if err != nil {
		return clients.MembershipsPage{}, errors.Wrap(clients.ErrFailedToRetrieveMembership, err)
	}
	page := clients.MembershipsPage{
		Memberships: items,
		Page: clients.Page{
			Total: total,
		},
	}

	return page, nil
}

func (repo clientRepo) Update(ctx context.Context, client clients.Client) (clients.Client, error) {
	var query []string
	var upq string
	if client.Name != "" {
		query = append(query, "name = :name,")
	}
	if client.Metadata != nil {
		query = append(query, "metadata = :metadata,")
	}
	if len(query) > 0 {
		upq = strings.Join(query, " ")
	}
	q := fmt.Sprintf(`UPDATE clients SET %s updated_at = :updated_at
        WHERE id = :id AND status = %d
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`,
		upq, clients.EnabledStatusKey)

	dbu, err := toDBClient(client)
	if err != nil {
		return clients.Client{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}

	row, err := repo.db.NamedQueryContext(ctx, q, dbu)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrCreateEntity)
	}

	defer row.Close()
	// False indicates that there is no next row or there is an error.
	if ok := row.Next(); !ok {
		return clients.Client{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func (repo clientRepo) UpdateTags(ctx context.Context, client clients.Client) (clients.Client, error) {
	q := fmt.Sprintf(`UPDATE clients SET tags = :tags, updated_at = :updated_at
        WHERE id = :id AND status = %d
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`,
		clients.EnabledStatusKey)

	dbu, err := toDBClient(client)
	if err != nil {
		return clients.Client{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbu)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return clients.Client{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func (repo clientRepo) UpdateIdentity(ctx context.Context, client clients.Client) (clients.Client, error) {
	q := fmt.Sprintf(`UPDATE clients SET identity = :identity, updated_at = :updated_at
        WHERE id = :id AND status = %d
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`,
		clients.EnabledStatusKey)

	dbc, err := toDBClient(client)
	if err != nil {
		return clients.Client{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbc)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return clients.Client{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func (repo clientRepo) UpdateSecret(ctx context.Context, client clients.Client) (clients.Client, error) {
	q := fmt.Sprintf(`UPDATE clients SET secret = :secret, updated_at = :updated_at
        WHERE identity = :identity AND status = %d
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`,
		clients.EnabledStatusKey)

	dbc, err := toDBClient(client)
	if err != nil {
		return clients.Client{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbc)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return clients.Client{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func (repo clientRepo) UpdateOwner(ctx context.Context, client clients.Client) (clients.Client, error) {
	q := fmt.Sprintf(`UPDATE clients SET owner = :owner, updated_at = :updated_at
        WHERE id = :id AND status = %d
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`,
		clients.EnabledStatusKey)

	dbc, err := toDBClient(client)
	if err != nil {
		return clients.Client{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbc)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return clients.Client{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func (repo clientRepo) ChangeStatus(ctx context.Context, id string, status uint16) (clients.Client, error) {
	q := fmt.Sprintf(`UPDATE clients SET status = %d WHERE id = :id
        RETURNING id, name, tags, identity, metadata, COALESCE(owner, '') AS owner, status, created_at, updated_at`, status)

	dbc := dbClient{
		ID: id,
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbc)
	if err != nil {
		return clients.Client{}, handleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return clients.Client{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	var rClient dbClient
	if err := row.StructScan(&rClient); err != nil {
		return clients.Client{}, err
	}

	return toClient(rClient)
}

func total(ctx context.Context, db Database, query string, params interface{}) (uint64, error) {
	rows, err := db.NamedQueryContext(ctx, query, params)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	total := uint64(0)
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, nil
}

type dbClient struct {
	ID        string           `db:"id"`
	Name      string           `db:"name,omitempty"`
	Tags      pgtype.TextArray `db:"tags"`
	Identity  string           `db:"identity"`
	Owner     string           `db:"owner,omitempty"` // nullable
	Secret    string           `db:"secret"`
	Metadata  []byte           `db:"metadata"`
	CreatedAt time.Time        `db:"created_at"`
	UpdatedAt time.Time        `db:"updated_at"`
	Groups    []clients.Group  `db:"groups"`
	Status    uint16           `db:"status"`
}

func toDBClient(c clients.Client) (dbClient, error) {
	data := []byte("{}")
	if len(c.Metadata) > 0 {
		b, err := json.Marshal(c.Metadata)
		if err != nil {
			return dbClient{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}
	var tags pgtype.TextArray
	if err := tags.Set(c.Tags); err != nil {
		return dbClient{}, err
	}

	return dbClient{
		ID:        c.ID,
		Name:      c.Name,
		Tags:      tags,
		Owner:     c.Owner,
		Identity:  c.Credentials.Identity,
		Secret:    c.Credentials.Secret,
		Metadata:  data,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		Status:    c.Status,
	}, nil
}

func toClient(c dbClient) (clients.Client, error) {
	var metadata clients.Metadata
	if c.Metadata != nil {
		if err := json.Unmarshal([]byte(c.Metadata), &metadata); err != nil {
			return clients.Client{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
	}
	var tags []string
	for _, e := range c.Tags.Elements {
		tags = append(tags, e.String)
	}

	return clients.Client{
		ID:    c.ID,
		Name:  c.Name,
		Tags:  tags,
		Owner: c.Owner,
		Credentials: clients.Credentials{
			Identity: c.Identity,
			Secret:   c.Secret,
		},
		Metadata:  metadata,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		Status:    c.Status,
	}, nil
}

func createMetadataQuery(entity string, um clients.Metadata) (string, []byte, error) {
	if len(um) == 0 {
		return "", nil, nil
	}

	param, err := json.Marshal(um)
	if err != nil {
		return "", nil, err
	}
	query := fmt.Sprintf("%smetadata @> :metadata", entity)

	return query, param, nil
}

func buildPMQuery(pm clients.Page) (string, error) {
	mq, _, err := createMetadataQuery("", pm.Metadata)
	if err != nil {
		return "", errors.Wrap(errors.ErrViewEntity, err)
	}
	var query []string
	var emq string
	if mq != "" {
		query = append(query, mq)
	}
	if pm.OwnerID != "" {
		query = append(query, fmt.Sprintf("owner = '%s'", pm.OwnerID))
	}
	if pm.Name != "" {
		query = append(query, fmt.Sprintf("name = '%s'", pm.Name))
	}
	if pm.Tags != "" {
		query = append(query, fmt.Sprintf("'%s' = ANY (tags)", pm.Tags))
	}
	if pm.Status != 0 {
		sq := fmt.Sprintf("status = %d", pm.Status)
		if pm.Status == clients.AllClientsStatusKey {
			sq = fmt.Sprintf("status = %d OR status = %d", clients.EnabledStatusKey, clients.DisabledStatusKey)
		}
		query = append(query, sq)
	}
	if len(query) > 0 {
		emq = fmt.Sprintf(" WHERE %s", strings.Join(query, " AND "))
	}
	return emq, nil

}

func toDBClientsPage(pm clients.Page) (dbClientsPage, error) {
	_, data, err := createMetadataQuery("", pm.Metadata)
	if err != nil {
		return dbClientsPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}
	return dbClientsPage{
		Name:     pm.Name,
		Metadata: data,
		Owner:    pm.OwnerID,
		Total:    pm.Total,
		Offset:   pm.Offset,
		Limit:    pm.Limit,
		Status:   pm.Status,
		Tag:      pm.Tags,
	}, nil
}

type dbClientsPage struct {
	GroupID  string `db:"group_id"`
	Name     string `db:"name"`
	Owner    string `db:"owner"`
	Identity string `db:"identity"`
	Metadata []byte `db:"metadata"`
	Tag      string `db:"tag"`
	Status   uint16 `db:"status"`
	Total    uint64 `db:"total"`
	Limit    uint64 `db:"limit"`
	Offset   uint64 `db:"offset"`
}
