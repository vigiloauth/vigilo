package constants

const (
	PromptLogin string = "login"
	PromptNone  string = "none"
)

var ValidPrompts = map[string]bool{
	PromptLogin: true,
	PromptNone:  true,
}
