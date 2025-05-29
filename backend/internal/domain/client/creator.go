package domain

import "context"

type ClientCreator interface {
	Register(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error)
}
