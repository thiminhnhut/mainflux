package jwt

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
)

const issuerName = "clients.auth"

var _ clients.TokenRepository = (*tokenRepo)(nil)

var (
	accessDuration  time.Duration = time.Minute * 15
	refreshDuration time.Duration = time.Hour * 24
)

type tokenRepo struct {
	secret []byte
}

// NewTokenRepo instantiates an implementation of Token repository.
func NewTokenRepo(secret []byte) clients.TokenRepository {
	return &tokenRepo{
		secret: secret,
	}
}

func (repo tokenRepo) Issue(ctx context.Context, claim clients.Claims) (clients.Token, error) {
	aexpiry := time.Now().Add(accessDuration)
	accessToken, err := jwt.NewBuilder().
		Issuer(issuerName).
		IssuedAt(time.Now()).
		Subject(claim.ClientID).
		Claim("type", clients.AccessToken).
		Claim("role", claim.Role).
		Claim("tag", claim.Tag).
		Expiration(aexpiry).
		Build()
	if err != nil {
		return clients.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	signedAccessToken, err := jwt.Sign(accessToken, jwt.WithKey(jwa.HS512, repo.secret))
	if err != nil {
		return clients.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	refreshToken, err := jwt.NewBuilder().
		Issuer(issuerName).
		IssuedAt(time.Now()).
		Subject(claim.ClientID).
		Claim("type", clients.RefreshToken).
		Claim("role", claim.Role).
		Claim("tag", claim.Tag).
		Expiration(time.Now().Add(refreshDuration)).
		Build()
	if err != nil {
		return clients.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	signedRefreshToken, err := jwt.Sign(refreshToken, jwt.WithKey(jwa.HS512, repo.secret))
	if err != nil {
		return clients.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	return clients.Token{
		AccessToken:  string(signedAccessToken[:]),
		RefreshToken: string(signedRefreshToken[:]),
		AccessType:   "Bearer",
	}, nil
}

func (repo tokenRepo) Parse(ctx context.Context, accessToken string) (clients.Claims, error) {
	token, err := jwt.Parse(
		[]byte(accessToken),
		jwt.WithValidate(true),
		jwt.WithKey(jwa.HS512, repo.secret),
	)
	if err != nil {
		return clients.Claims{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	tType, ok := token.Get("type")
	if !ok {
		return clients.Claims{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	role, ok := token.Get("role")
	if !ok {
		return clients.Claims{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	tag, ok := token.Get("tag")
	if !ok {
		return clients.Claims{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	claim := clients.Claims{
		ClientID: token.Subject(),
		Role:     role.(string),
		Tag:      tag.(string),
		Type:     tType.(string),
	}
	return claim, nil
}
