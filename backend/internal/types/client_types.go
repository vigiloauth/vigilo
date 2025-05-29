package types

type ClientType string

const (
	ConfidentialClient ClientType = "confidential"
	PublicClient       ClientType = "public"
)

var SupportedClientTypes = map[ClientType]bool{
	ConfidentialClient: true,
	PublicClient:       true,
}

func (c ClientType) String() string {
	return string(c)
}
