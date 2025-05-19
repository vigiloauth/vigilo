package domain

import (
	"encoding/json"
	"net/url"
)

type ClaimsRequest struct {
	UserInfo *ClaimSet `json:"userinfo,omitempty"`
}

type ClaimSet map[string]*ClaimSpec

type ClaimSpec struct {
	Essential bool   `json:"essential,omitempty"`
	Value     string `json:"value,omitempty"`
}

func ParseClaimsParameter(claimsParam string) (*ClaimsRequest, error) {
	decodedClaims, _ := url.QueryUnescape(claimsParam)
	var claimsRequest ClaimsRequest
	_ = json.Unmarshal([]byte(decodedClaims), &claimsRequest)
	return &claimsRequest, nil
}
