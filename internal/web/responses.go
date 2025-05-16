package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
)

// WriteJSON writes the provided data as JSON to the HTTP response writer.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	if data != nil {
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			panic(err)
		}
	}
}

// WriteError writes an error as JSON response with appropriate HTTP status code
func WriteError(w http.ResponseWriter, err error) {
	if e, ok := err.(*errors.ErrorCollection); ok {
		err := errors.VigiloAuthError{
			ErrorCode:        errors.ErrCodeValidationError,
			ErrorDescription: "One or more validation errors occurred",
			Errors:           e.Errors(),
		}
		WriteJSON(w, http.StatusBadRequest, err)
	} else {
		WriteJSON(w, errors.HTTPStatusCodeMap[errors.Code(err)], err)
	}
}

func RenderErrorPage(w http.ResponseWriter, r *http.Request, errorCode string, invalidURI string) {
	errorURL := "/error?type=" + errors.SystemErrorCodeMap[errorCode]
	if invalidURI != "" {
		errorURL += "&uri=" + url.QueryEscape(invalidURI)
	}

	http.Redirect(w, r, errorURL, http.StatusFound)
}

func BuildErrorURL(errCode, errDescription, state, redirectURI string) string {
	params := url.Values{}
	params.Add("error", errCode)
	params.Add("error_description", errDescription)
	params.Add(constants.StateReqField, state)

	return redirectURI + "?" + params.Encode()
}

func BuildRedirectURL(clientID, redirectURI, scope, responseType, state, nonce, prompt, display, endpoint string) string {
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, clientID)
	queryParams.Add(constants.RedirectURIReqField, redirectURI)
	queryParams.Add(constants.ScopeReqField, scope)
	queryParams.Add(constants.ResponseTypeReqField, responseType)

	if state != "" {
		queryParams.Add(constants.StateReqField, state)
	}
	if nonce != "" {
		queryParams.Add(constants.NonceReqField, nonce)
	}
	if prompt != "" {
		queryParams.Add(constants.PromptReqField, prompt)
	}

	if display != "" && constants.ValidAuthenticationDisplays[display] {
		queryParams.Add(constants.DisplayReqField, display)
	} else {
		queryParams.Add(constants.DisplayReqField, constants.DisplayPage)
	}

	return fmt.Sprintf("/%s?%s", endpoint, queryParams.Encode())
}
