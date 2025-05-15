package constants

const (
	PromptLogin   string = "login"
	PromptNone    string = "none"
	PromptConsent string = "consent"
)

var ValidPrompts = map[string]bool{
	PromptLogin:   true,
	PromptNone:    true,
	PromptConsent: true,
}
