package web

import (
	"fmt"
	"net/url"

	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
)

func ValidateClientAuthorizationParameters(query url.Values) string {
	state := ""
	if stateReq := query.Get(constants.StateReqField); stateReq != "" {
		state = stateReq
	}

	redirectURI := query.Get(constants.RedirectURIReqField)

	if clientID := query.Get(constants.ClientIDReqField); clientID == "" {
		return buildErrorURL(redirectURI, errors.ErrCodeInvalidRequest, "client_id", state)
	} else if responseType := query.Get(constants.ResponseTypeReqField); responseType == "" {
		return buildErrorURL(redirectURI, errors.ErrCodeInvalidRequest, "response_type", state)
	}

	return ""
}

func buildErrorURL(redirectURI, errCode, parameter, state string) string {
	description := fmt.Sprintf("the request is missing the required '%s' parameter", parameter)

	queryParams := url.Values{}
	queryParams.Add("error", errCode)
	queryParams.Add("error_description", description)
	if state != "" {
		queryParams.Add(constants.StateReqField, state)
	}

	return redirectURI + "?" + queryParams.Encode()
}
