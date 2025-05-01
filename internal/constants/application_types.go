package constants

// Predefined client application types.
const (
	WebApplicationType    string = "web"
	NativeApplicationType string = "native"
)

var ValidApplicationTypes = map[string]bool{
	WebApplicationType:    true,
	NativeApplicationType: true,
}
