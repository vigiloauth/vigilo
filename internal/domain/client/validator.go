package domain

type ClientValidator interface {
	ValidateRegistrationRequest(req *ClientRegistrationRequest) error
	ValidateUpdateRequest(req *ClientUpdateRequest) error
	ValidateAuthorizationRequest(req *ClientAuthorizationRequest) error
}
