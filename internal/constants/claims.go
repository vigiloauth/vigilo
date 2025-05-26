package constants

const (
	SubClaim                 string = "sub"
	NameClaim                string = "name"
	GivenNameClaim           string = "given_name"
	FamilyNameClaim          string = "family_name"
	MiddleNameClaim          string = "middle_name"
	NicknameClaim            string = "nickname"
	PreferredUsernameClaim   string = "preferred_username"
	ProfileClaim             string = "profile"
	PictureClaim             string = "picture"
	WebsiteClaim             string = "website"
	GenderClaim              string = "gender"
	BirthdateClaim           string = "birthdate"
	ZoneinfoClaim            string = "zoneinfo"
	LocaleClaim              string = "locale"
	EmailClaim               string = "email"
	EmailVerifiedClaim       string = "email_verified"
	PhoneNumberClaim         string = "phone_number"
	PhoneNumberVerifiedClaim string = "phone_number_verified"
	UpdatedAtClaim           string = "updated_at"
	AddressClaim             string = "address"
)

var SupportedClaims = map[string]bool{
	SubClaim:                 true,
	NameClaim:                true,
	GivenNameClaim:           true,
	FamilyNameClaim:          true,
	MiddleNameClaim:          true,
	NicknameClaim:            true,
	PreferredUsernameClaim:   true,
	ProfileClaim:             true,
	PictureClaim:             true,
	WebsiteClaim:             true,
	GenderClaim:              true,
	BirthdateClaim:           true,
	ZoneinfoClaim:            true,
	LocaleClaim:              true,
	EmailClaim:               true,
	EmailVerifiedClaim:       true,
	PhoneNumberClaim:         true,
	PhoneNumberVerifiedClaim: true,
	UpdatedAtClaim:           true,
	AddressClaim:             true,
}
