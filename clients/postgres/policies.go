package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgtype"
	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
)

var _ clients.PolicyRepository = (*policyRepository)(nil)

var (
	// ErrInvalidEntityType indicates that the entity type is invalid.
	ErrInvalidEntityType = errors.New("invalid entity type")
)

type policyRepository struct {
	db Database
}

// NewPolicyRepo instantiates a PostgreSQL implementation of policy repository.
func NewPolicyRepo(db Database) clients.PolicyRepository {
	return &policyRepository{
		db: db,
	}
}

func (pr policyRepository) Save(ctx context.Context, policy clients.Policy) error {
	q := `INSERT INTO policies (owner_id, subject, object, actions, created_at, updated_at)
		VALUES (:owner_id, :subject, :object, :actions, :created_at, :updated_at)`

	dbp, err := toDBPolicy(policy)
	if err != nil {
		return errors.Wrap(errors.ErrCreateEntity, err)
	}

	row, err := pr.db.NamedQueryContext(ctx, q, dbp)
	if err != nil {
		return handleError(err, errors.ErrCreateEntity)
	}

	defer row.Close()

	return nil
}

func (pr policyRepository) Evaluate(ctx context.Context, entityType string, policy clients.Policy) error {
	q := ""
	switch entityType {
	case "client":
		// Evaluates if two clients are connected to the same group and the subject has the specified action
		q = fmt.Sprintf(`SELECT subject FROM policies WHERE subject = :subject AND object = (
				SELECT object FROM policies WHERE subject = :object) AND '%s'=ANY(actions)`,
			policy.Actions[0])
	case "group":
		// Evaluates if client is connected to the specified group and has the required action
		q = fmt.Sprintf(`SELECT subject FROM policies WHERE subject = :subject AND 
		object = :object AND '%s'=ANY(actions)`, policy.Actions[0])
	default:
		return ErrInvalidEntityType
	}

	dbu, err := toDBPolicy(policy)
	if err != nil {
		return errors.Wrap(errors.ErrAuthorization, err)
	}
	row, err := pr.db.NamedQueryContext(ctx, q, dbu)
	if err != nil {
		return handleError(err, errors.ErrAuthorization)
	}

	defer row.Close()

	if ok := row.Next(); !ok {
		return errors.Wrap(errors.ErrAuthorization, row.Err())
	}
	var rPolicy dbPolicy
	if err := row.StructScan(&rPolicy); err != nil {
		return err
	}
	return nil
}

func (pr policyRepository) Update(ctx context.Context, policy clients.Policy) error {
	if err := policy.Validate(); err != nil {
		return errors.Wrap(errors.ErrCreateEntity, err)
	}
	q := `UPDATE policies SET actions = :actions, updated_at = :updated_at
		WHERE subject = :subject AND object = :object`

	dbu, err := toDBPolicy(policy)
	if err != nil {
		return errors.Wrap(errors.ErrUpdateEntity, err)
	}

	if _, err := pr.db.NamedExecContext(ctx, q, dbu); err != nil {
		return errors.Wrap(errors.ErrUpdateEntity, err)
	}

	return nil
}

func (pr policyRepository) Retrieve(ctx context.Context, pm clients.Page) (clients.PolicyPage, error) {
	var query []string
	var emq string

	if pm.OwnerID != "" {
		query = append(query, fmt.Sprintf("owner_id = '%s'", pm.OwnerID))
	}
	if pm.Subject != "" {
		query = append(query, fmt.Sprintf("subject = '%s'", pm.Subject))
	}
	if pm.Object != "" {
		query = append(query, fmt.Sprintf("object = '%s'", pm.Object))
	}
	if pm.Action != "" {
		query = append(query, fmt.Sprintf("'%s' = ANY (actions)", pm.Action))
	}

	if len(query) > 0 {
		emq = fmt.Sprintf(" WHERE %s", strings.Join(query, " AND "))
	}

	q := fmt.Sprintf(`SELECT owner_id, subject, object, actions
		FROM policies %s ORDER BY updated_at LIMIT :limit OFFSET :offset;`, emq)
	params := map[string]interface{}{
		"limit":  pm.Limit,
		"offset": pm.Offset,
	}
	rows, err := pr.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return clients.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}
	defer rows.Close()

	var items []clients.Policy
	for rows.Next() {
		dbp := dbPolicy{}
		if err := rows.StructScan(&dbp); err != nil {
			return clients.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
		}

		policy, err := toPolicy(dbp)
		if err != nil {
			return clients.PolicyPage{}, err
		}

		items = append(items, policy)
	}

	cq := fmt.Sprintf(`SELECT COUNT(*) FROM policies %s;`, emq)

	total, err := total(ctx, pr.db, cq, params)
	if err != nil {
		return clients.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	page := clients.PolicyPage{
		Policies: items,
		Page: clients.Page{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
		},
	}

	return page, nil
}

func (pr policyRepository) Delete(ctx context.Context, p clients.Policy) error {
	dbp := dbPolicy{
		Subject: p.Subject,
		Object:  p.Object,
	}
	q := `DELETE FROM policies WHERE subject = :subject AND object = :object`
	if _, err := pr.db.NamedExecContext(ctx, q, dbp); err != nil {
		return errors.Wrap(errors.ErrRemoveEntity, err)
	}
	return nil
}

type dbPolicy struct {
	OwnerID   string           `db:"owner_id"`
	Subject   string           `db:"subject"`
	Object    string           `db:"object"`
	Actions   pgtype.TextArray `db:"actions"`
	CreatedAt time.Time        `db:"created_at"`
	UpdatedAt time.Time        `db:"updated_at"`
}

func toDBPolicy(p clients.Policy) (dbPolicy, error) {
	var ps pgtype.TextArray
	if err := ps.Set(p.Actions); err != nil {
		return dbPolicy{}, err
	}

	return dbPolicy{
		OwnerID:   p.OwnerID,
		Subject:   p.Subject,
		Object:    p.Object,
		Actions:   ps,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}, nil
}

func toPolicy(dbp dbPolicy) (clients.Policy, error) {
	var ps []string
	for _, e := range dbp.Actions.Elements {
		ps = append(ps, e.String)
	}

	return clients.Policy{
		OwnerID:   dbp.OwnerID,
		Subject:   dbp.Subject,
		Object:    dbp.Object,
		Actions:   ps,
		CreatedAt: dbp.CreatedAt,
		UpdatedAt: dbp.UpdatedAt,
	}, nil
}
