package constants

const (
	CodeResponseType    string = "code"
	TokenResponseType   string = "token"
	IDTokenResponseType string = "id_token"
)

var ValidResponseTypes = map[string]bool{
	CodeResponseType:    true,
	TokenResponseType:   true,
	IDTokenResponseType: true,
}
