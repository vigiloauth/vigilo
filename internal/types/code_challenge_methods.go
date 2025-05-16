package types

type CodeChallengeMethod string

const (
	PlainCodeChallengeMethod  CodeChallengeMethod = "plain"
	SHA256CodeChallengeMethod CodeChallengeMethod = "SHA-256"
)

var SupportedCodeChallengeMethods = map[CodeChallengeMethod]bool{
	PlainCodeChallengeMethod:  true,
	SHA256CodeChallengeMethod: true,
}

func (c CodeChallengeMethod) String() string {
	return string(c)
}
