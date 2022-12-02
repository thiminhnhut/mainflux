package clients

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/clients/internal/apiutil"
	"github.com/mainflux/mainflux/pkg/errors"
)

const (
	// 1 for enabled, 2 for disabled and 3 for all as 0 is usually null
	EnabledStatusKey    = 1
	DisabledStatusKey   = 2
	AllClientsStatusKey = 3
	RefreshToken        = "refresh"
	AccessToken         = "access"
)

var (
	// ErrInvalidStatus indicates invalid status
	ErrInvalidStatus = errors.New("invalid client status")

	// ErrEnableClient indicates error in enabling client
	ErrEnableClient = errors.New("failed to enable client")

	// ErrDisableClient indicates error in disabling client
	ErrDisableClient = errors.New("failed to disable client")

	ErrStatusAlreadyAssigned = errors.New("status already assigned")
)

// Service unites Clients and Group services.
type Service interface {
	ClientService
	GroupService
	PolicyService
	TokenService
}

type service struct {
	clients    ClientRepository
	groups     GroupRepository
	policies   PolicyRepository
	idProvider mainflux.IDProvider
	tokens     TokenRepository
}

// NewService returns a new Clients service implementation.
func NewService(c ClientRepository, g GroupRepository, p PolicyRepository, t TokenRepository, idp mainflux.IDProvider) Service {
	return service{
		clients:    c,
		groups:     g,
		policies:   p,
		tokens:     t,
		idProvider: idp,
	}
}

func (svc service) RegisterClient(ctx context.Context, token string, cli Client) (Client, error) {
	id, err := svc.idProvider.ID()
	if err != nil {
		return Client{}, err
	}
	// We don't check the error currently since we can register client with empty token
	iClientID, _ := svc.identify(ctx, token)
	if iClientID != "" && cli.Owner == "" {
		cli.Owner = iClientID
	}
	if cli.Credentials.Identity == "" {
		return Client{}, errors.ErrMalformedEntity
	}
	if cli.Status == 0 {
		cli.Status = 1
	}
	if cli.Status != 1 && cli.Status != 2 {
		return Client{}, apiutil.ErrInvalidStatus
	}
	cli.ID = id
	cli.CreatedAt = time.Now()
	cli.UpdatedAt = cli.CreatedAt
	return svc.clients.Save(ctx, cli)
}

func (svc service) IssueToken(ctx context.Context, cli Client) (Token, error) {
	dbUser, err := svc.clients.RetrieveByIdentity(ctx, cli.Credentials.Identity)
	if err != nil {
		return Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if dbUser.Credentials.Secret != cli.Credentials.Secret {
		return Token{}, errors.ErrAuthentication
	}
	claims := Claims{
		ClientID: dbUser.ID,
	}
	return svc.tokens.Issue(ctx, claims)
}

func (svc service) RefreshToken(ctx context.Context, accessToken string) (Token, error) {
	claims, err := svc.tokens.Parse(ctx, accessToken)
	if err != nil {
		return Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if claims.Type != RefreshToken {
		return Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if _, err := svc.clients.RetrieveByID(ctx, claims.ClientID); err != nil {
		return Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	return svc.tokens.Issue(ctx, claims)
}

func (svc service) ViewClient(ctx context.Context, token string, id string) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", id, "c_list"); err != nil {
		return Client{}, err
	}
	return svc.clients.RetrieveByID(ctx, id)
}

func (svc service) ListClients(ctx context.Context, token string, pm Page) (ClientsPage, error) {
	if err := svc.checkAuthz(ctx, token, "group", "*", "c_list"); err != nil {
		return ClientsPage{}, err
	}
	return svc.clients.RetrieveAll(ctx, pm)
}

func (svc service) ListMemberships(ctx context.Context, token, clientID string, gm GroupsPage) (MembershipsPage, error) {
	if err := svc.checkAuthz(ctx, token, "group", "*", "c_list"); err != nil {
		return MembershipsPage{}, err
	}
	return svc.clients.Memberships(ctx, clientID, gm)
}

func (svc service) UpdateClient(ctx context.Context, token string, cli Client) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", cli.ID, "c_update"); err != nil {
		return Client{}, err
	}
	client := Client{
		ID:        cli.ID,
		Name:      cli.Name,
		Metadata:  cli.Metadata,
		UpdatedAt: time.Now(),
	}
	return svc.clients.Update(ctx, client)
}

func (svc service) UpdateClientTags(ctx context.Context, token string, cli Client) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", cli.ID, "c_update"); err != nil {
		return Client{}, err
	}
	client := Client{
		ID:        cli.ID,
		Tags:      cli.Tags,
		UpdatedAt: time.Now(),
	}
	return svc.clients.UpdateTags(ctx, client)
}

func (svc service) UpdateClientIdentity(ctx context.Context, token, id, identity string) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", id, "c_update"); err != nil {
		return Client{}, err
	}
	cli := Client{
		ID: id,
		Credentials: Credentials{
			Identity: identity,
		},
	}
	return svc.clients.UpdateIdentity(ctx, cli)
}

func (svc service) UpdateClientSecret(ctx context.Context, token, oldSecret, newSecret string) (Client, error) {
	iClientID, err := svc.identify(ctx, token)
	if err != nil {
		return Client{}, err
	}
	cli, err := svc.clients.RetrieveByID(ctx, iClientID)
	if err != nil {
		return Client{}, err
	}
	if cli.Credentials.Secret != oldSecret {
		return Client{}, err
	}
	cli.Credentials.Secret = newSecret
	return svc.clients.UpdateSecret(ctx, cli)
}

func (svc service) UpdateClientOwner(ctx context.Context, token string, cli Client) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", cli.ID, "c_update"); err != nil {
		return Client{}, err
	}
	client := Client{
		ID:        cli.ID,
		Owner:     cli.Owner,
		UpdatedAt: time.Now(),
	}
	return svc.clients.UpdateOwner(ctx, client)
}

func (svc service) EnableClient(ctx context.Context, token, id string) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", id, "c_delete"); err != nil {
		return Client{}, err
	}
	client, err := svc.changeStatus(ctx, id, EnabledStatusKey)
	if err != nil {
		return Client{}, errors.Wrap(ErrEnableClient, err)
	}
	return client, nil
}

func (svc service) DisableClient(ctx context.Context, token, id string) (Client, error) {
	if err := svc.checkAuthz(ctx, token, "client", id, "c_delete"); err != nil {
		return Client{}, err
	}
	client, err := svc.changeStatus(ctx, id, DisabledStatusKey)
	if err != nil {
		return Client{}, errors.Wrap(ErrDisableClient, err)
	}
	return client, nil
}

func (svc service) changeStatus(ctx context.Context, id string, status uint16) (Client, error) {
	dbClient, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return Client{}, err
	}
	if dbClient.Status == status {
		return Client{}, ErrStatusAlreadyAssigned
	}

	return svc.clients.ChangeStatus(ctx, id, status)
}
func (svc service) CreateGroup(ctx context.Context, token string, g Group) (Group, error) {
	iClientID, err := svc.identify(ctx, token)
	if err != nil {
		return Group{}, err
	}
	id, err := svc.idProvider.ID()
	if err != nil {
		return Group{}, err
	}
	if g.OwnerID == "" {
		g.OwnerID = iClientID
	}
	g.ID = id
	g.CreatedAt = time.Now()
	g.UpdatedAt = g.CreatedAt
	return svc.groups.Save(ctx, g)
}

func (svc service) ViewGroup(ctx context.Context, token string, id string) (Group, error) {
	if err := svc.checkAuthz(ctx, token, "group", id, "g_list"); err != nil {
		return Group{}, err
	}
	return svc.groups.RetrieveByID(ctx, id)
}

func (svc service) ListGroups(ctx context.Context, token string, gm GroupsPage) (GroupsPage, error) {
	if err := svc.checkAuthz(ctx, token, "group", "*", "g_list"); err != nil {
		return GroupsPage{}, err
	}
	return svc.groups.RetrieveAll(ctx, gm)
}

func (svc service) ListMembers(ctx context.Context, token, groupID string, pm Page) (MembersPage, error) {
	if err := svc.checkAuthz(ctx, token, "group", groupID, "g_list"); err != nil {
		return MembersPage{}, err
	}
	return svc.groups.Members(ctx, groupID, pm)
}

func (svc service) UpdateGroup(ctx context.Context, token string, g Group) (Group, error) {
	if err := svc.checkAuthz(ctx, token, "group", g.ID, "g_update"); err != nil {
		return Group{}, err
	}
	g.UpdatedAt = time.Now()
	return svc.groups.Update(ctx, g)
}

func (svc service) RemoveGroup(ctx context.Context, token, id string) error {
	if err := svc.checkAuthz(ctx, token, "group", id, "g_delete"); err != nil {
		return err
	}
	return svc.groups.Delete(ctx, id)
}

func (svc service) Authorize(ctx context.Context, entityType string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return svc.policies.Evaluate(ctx, entityType, p)
}
func (svc service) UpdatePolicy(ctx context.Context, token string, p Policy) error {
	iClientID, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.checkActionRank(ctx, iClientID, p); err != nil {
		return err
	}
	p.UpdatedAt = time.Now()
	return svc.policies.Update(ctx, p)
}

func (svc service) AddPolicy(ctx context.Context, token string, p Policy) error {
	iClientID, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	page, err := svc.policies.Retrieve(ctx, Page{Subject: p.Subject, Object: p.Object})
	if err != nil {
		return err
	}
	if len(page.Policies) != 0 {
		return svc.policies.Update(ctx, p)
	}
	if err := svc.checkActionRank(ctx, iClientID, p); err != nil {
		return err
	}
	p.OwnerID = iClientID
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	return svc.policies.Save(ctx, p)
}

func (svc service) DeletePolicy(ctx context.Context, token string, p Policy) error {
	iClientID, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.checkActionRank(ctx, iClientID, p); err != nil {
		return err
	}
	return svc.policies.Delete(ctx, p)
}

func (svc service) ListPolicy(ctx context.Context, token string, pm Page) (PolicyPage, error) {
	if _, err := svc.identify(ctx, token); err != nil {
		return PolicyPage{}, err
	}
	if err := pm.Validate(); err != nil {
		return PolicyPage{}, err
	}
	page, err := svc.policies.Retrieve(ctx, pm)
	if err != nil {
		return PolicyPage{}, err
	}
	return page, err
}

// checkActionRank check if an action is in the provide list of actions
func (svc service) checkActionRank(ctx context.Context, clientID string, p Policy) error {
	page, err := svc.policies.Retrieve(ctx, Page{Subject: clientID, Object: p.Object})
	if err != nil {
		return err
	}
	if len(page.Policies) != 0 {
		for _, a := range p.Actions {
			var found = false
			for _, v := range page.Policies[0].Actions {
				if v == a {
					found = true
					break
				}
			}
			if !found {
				return apiutil.ErrHigherPolicyRank
			}
		}
	}
	return nil

}

func (svc service) identify(ctx context.Context, tkn string) (string, error) {
	claims, err := svc.tokens.Parse(ctx, tkn)
	if err != nil {
		return "", errors.Wrap(errors.ErrAuthentication, err)
	}
	if claims.Type != AccessToken {
		return "", errors.ErrAuthentication
	}
	return claims.ClientID, nil
}

func (svc service) checkAuthz(ctx context.Context, token, entityType, object, action string) error {
	clientID, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	return svc.Authorize(ctx, entityType, Policy{Subject: clientID, Object: object, Actions: []string{action}})
}
