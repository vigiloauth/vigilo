package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenIssuer = (*tokenIssuer)(nil)

type tokenIssuer struct {
	creator token.TokenCreator
	logger  *config.Logger
	module  string
}

func NewTokenIssuer(creator token.TokenCreator) token.TokenIssuer {
	return &tokenIssuer{
		creator: creator,
		logger:  config.GetServerConfig().Logger(),
		module:  "Token Creator",
	}
}

func (t *tokenIssuer) IssueTokenPair(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
	requestedClaims *claims.ClaimsRequest,
) (string, string, error) {
	requestID := utils.GetRequestID(ctx)

	accessToken, err := t.creator.CreateAccessTokenWithClaims(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
		requestedClaims,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[IssueTokenPair]: Failed to issue access token: %v", err)
		return "", "", errors.Wrap(err, "", "failed to issue access token")
	}

	refreshToken, err := t.creator.CreateRefreshToken(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[IssueTokenPair]: Failed to issue refresh token: %v", err)
		return "", "", errors.Wrap(err, "", "failed to issue refresh token")
	}

	return accessToken, refreshToken, nil
}

func (t *tokenIssuer) IssueIDToken(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	nonce string,
	authTime time.Time,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	IDToken, err := t.creator.CreateIDToken(
		ctx,
		subject,
		audience,
		scopes,
		nonce,
		authTime,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[IssueTokenPair]: Failed to issue ID token: %v", err)
		return "", errors.Wrap(err, "", "failed to issue ID token")
	}

	return IDToken, nil
}

func (t *tokenIssuer) IssueAccessToken(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	accessToken, err := t.creator.CreateAccessToken(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[IssueAccessToken]: Failed to issue access token: %v", err)
		return "", errors.Wrap(err, "", "failed to issue access token")
	}

	return accessToken, nil
}
