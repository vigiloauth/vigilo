package domain

import (
	"fmt"
	"slices"
	"time"
)

// User represents a user in the system.
type User struct {
	ID                string
	PreferredUsername string
	Name              string
	GivenName         string
	MiddleName        string
	FamilyName        string
	Nickname          string
	Profile           string // URL to user’s profile
	Picture           string // URL to user’s picture
	Website           string // Personal website URL
	Email             string
	PhoneNumber       string
	Password          string

	Gender    string
	Birthdate string
	Zoneinfo  string // e.g., "America/New_York"
	Locale    string // e.g., "en-US"

	Address *UserAddress

	Roles []string

	LastFailedLogin time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time

	AccountLocked       bool
	EmailVerified       bool
	PhoneNumberVerified bool
}

type UserAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

// UserRegistrationRequest represents the registration request payload.
type UserRegistrationRequest struct {
	Username    string      `json:"username,omitempty"`
	Nickname    string      `json:"nickname,omitempty"`
	FirstName   string      `json:"first_name"`
	MiddleName  string      `json:"middle_name,omitempty"`
	FamilyName  string      `json:"family_name"`
	Birthdate   string      `json:"birthdate,omitempty"`
	Email       string      `json:"email"`
	Profile     string      `json:"profile,omitempty"` // URL to the user's profile page
	Picture     string      `json:"picture,omitempty"` // URL to the user's picture/avatar
	Website     string      `json:"website,omitempty"` // URL to the user's personal website
	Gender      string      `json:"gender,omitempty"`
	PhoneNumber string      `json:"phone_number,omitempty"`
	Password    string      `json:"password"`
	Address     UserAddress `json:"address,omitempty"`
	Scopes      []string    `json:"scope,omitempty"`
	Roles       []string    `json:"roles,omitempty"`
}

// UserInfoResponse represents the payload for the user info request.
type UserInfoResponse struct {
	Sub                 string       `json:"sub"`
	Name                string       `json:"name,omitempty"`
	GivenName           string       `json:"given_name,omitempty"`
	FamilyName          string       `json:"family_name,omitempty"`
	MiddleName          string       `json:"middle_name,omitempty"`
	Nickname            string       `json:"nickname,omitempty"`
	PreferredUsername   string       `json:"preferred_username,omitempty"`
	Profile             string       `json:"profile,omitempty"`
	Picture             string       `json:"picture,omitempty"`
	Website             string       `json:"website,omitempty"`
	Gender              string       `json:"gender,omitempty"`
	Birthdate           string       `json:"birthdate,omitempty"`
	Zoneinfo            string       `json:"zoneinfo,omitempty"`
	Locale              string       `json:"locale,omitempty"`
	Email               string       `json:"email,omitempty"`
	EmailVerified       *bool        `json:"email_verified,omitempty"`
	PhoneNumber         string       `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool        `json:"phone_number_verified,omitempty"`
	UpdatedAt           int64        `json:"updated_at,omitempty"`
	Address             *UserAddress `json:"address,omitempty"`
}

// UserRegistrationResponse represents the registration response payload.
type UserRegistrationResponse struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	Gender      string `json:"gender"`
	Birthdate   string `json:"birthdate"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Address     string `json:"address"`
	JWTToken    string `json:"token"`
}

// UserLoginRequest represents the login request payload.
type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`

	ClientID    string
	RedirectURI string
}

// UserLoginResponse represents the login response payload.
type UserLoginResponse struct {
	UserID           string    `json:"-"`
	Username         string    `json:"username"`
	Email            string    `json:"email"`
	AccessToken      string    `json:"access_token,omitempty"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	OAuthRedirectURL string    `json:"oauth_redirect_url,omitempty"`
	LastFailedLogin  time.Time `json:"last_failed_login"`
	Scopes           []string  `json:"scopes,omitempty"`
	Roles            []string  `json:"roles,omitempty"`
}

// UserPasswordResetRequest represents the password reset request payload.
type UserPasswordResetRequest struct {
	Email       string `json:"email"`
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}

// UserPasswordResetResponse represents the password reset response payload.
type UserPasswordResetResponse struct {
	Message string `json:"message"`
}

// UserLoginAttempt represents a user's login attempt.
type UserLoginAttempt struct {
	UserID          string
	IPAddress       string
	Username        string
	Password        string
	ForwardedFor    string
	Timestamp       time.Time
	RequestMetadata string
	Details         string
	UserAgent       string
	FailedAttempts  int
}

// NewUser creates a new User instance.
//
// Parameters:
//   - username string: The user's username.
//   - email string: The user's email address.
//   - password string: The user's password (hashed).
//
// Returns:
//   - *User: A new User instance.
func NewUser(username, email, password string) *User {
	return &User{
		PreferredUsername: username,
		Email:             email,
		Password:          password,
		LastFailedLogin:   time.Time{},
		AccountLocked:     false,
		EmailVerified:     false,
	}
}

// NewUserFromRegistrationRequest create a new user instance from a registration request.
//
// Parameters:
//   - req *UserRegistrationRequest: The request.
//
// Returns:
//   - *User: A new user instance.
func NewUserFromRegistrationRequest(req *UserRegistrationRequest) *User {
	name := fmt.Sprintf("%s %s %s", req.FirstName, req.MiddleName, req.FamilyName)
	return &User{
		PreferredUsername: req.Username,
		Password:          req.Password,
		Name:              name,
		GivenName:         req.FirstName,
		MiddleName:        req.MiddleName,
		FamilyName:        req.FamilyName,
		Gender:            req.Gender,
		Birthdate:         req.Birthdate,
		Email:             req.Email,
		PhoneNumber:       req.PhoneNumber,
		Zoneinfo:          time.UTC.String(),
		Roles:             req.Roles,
		Locale:            req.Address.Locality,
		Website:           req.Website,
		Profile:           req.Profile,
		Picture:           req.Picture,
		Nickname:          req.Nickname,
		Address: NewUserAddress(
			req.Address.StreetAddress,
			req.Address.Locality,
			req.Address.Region,
			req.Address.PostalCode,
			req.Address.Country,
		),
		LastFailedLogin:     time.Time{},
		AccountLocked:       false,
		EmailVerified:       false,
		PhoneNumberVerified: false,
	}
}

// NewUserRegistrationRequest creates a new UserRegistrationRequest instance.
//
// Parameters:
//   - username string: The username for the registration request.
//   - email string: The email for the registration request.
//   - password string: The password for the registration request.
//
// Returns:
//   - *UserRegistrationRequest: A new UserRegistrationRequest instance.
func NewUserRegistrationRequest(username, email, password string) *UserRegistrationRequest {
	return &UserRegistrationRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
}

// NewUserRegistrationResponse creates a new UserRegistrationResponse instance.
//
// Parameters:
//   - user *User: The created User object.
//   - jwtToken string: The JWT token for the registered user.
//
// Returns:
//   - *UserRegistrationResponse: A new UserRegistrationResponse instance.
func NewUserRegistrationResponse(user *User, jwtToken string) *UserRegistrationResponse {
	return &UserRegistrationResponse{
		Username:    user.PreferredUsername,
		Name:        user.Name,
		Gender:      user.Gender,
		Birthdate:   user.Birthdate,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		Address:     user.Address.Formatted,
		JWTToken:    jwtToken,
	}
}

// NewUserAddress created a new UserAddress instance.
//
// Parameters:
//   - streetAddress string: The street address component, which may include house number, street name, and post office box.
//   - locality string: City or locality component.
//   - region string: State, province, prefecture or region component.
//   - postalCode string: Zip code or postal code component.
//   - country string: Country name component.
//
// Returns:
//   - *UserAddress: A new UserAddress instance.
func NewUserAddress(streetAddress, locality, region, postalCode, country string) *UserAddress {
	formattedAddress := formatAddress(streetAddress, locality, region, postalCode, country)
	return &UserAddress{
		Formatted:     formattedAddress,
		StreetAddress: streetAddress,
		Locality:      locality,
		Region:        region,
		PostalCode:    postalCode,
		Country:       country,
	}
}

// NewUserLoginRequest creates a new UserLoginRequest instance.
//
// Parameters:
//   - username string: The username for the login request.
//   - password string: The password for the login request.
//
// Returns:
//   - *UserLoginRequest: A new UserLoginRequest instance.
func NewUserLoginRequest(username, password string) *UserLoginRequest {
	return &UserLoginRequest{
		Username: username,
		Password: password,
	}
}

// NewUserLoginResponse creates a new UserLoginResponse instance.
//
// Parameters:
//   - user *User: The authenticated User object.
//   - accessToken string: The access token for the authenticated user.
//   - refreshToken string: The refresh token for the authenticated user.
//
// Returns:
//   - *UserLoginResponse: A new UserLoginResponse instance.
func NewUserLoginResponse(
	user *User,
	accessToken string,
	refreshToken string,
) *UserLoginResponse {
	return &UserLoginResponse{
		UserID:       user.ID,
		Username:     user.PreferredUsername,
		Email:        user.Email,
		Roles:        user.Roles,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,

		LastFailedLogin: user.LastFailedLogin,
	}
}

// NewUserLoginAttempt creates a new UserLoginAttempt instance.
//
// Parameters:
//   - ipAddress string: The IP address of the login attempt.
//   - requestMetadata string: Additional request metadata.
//   - details string: Details about the login attempt.
//   - userAgent string: The user agent of the login attempt.
//
// Returns:
//   - *LoginAttempt: A new UserLoginAttempt instance.
func NewUserLoginAttempt(ipAddress, userAgent string) *UserLoginAttempt {
	return &UserLoginAttempt{
		IPAddress:      ipAddress,
		Timestamp:      time.Now(),
		UserAgent:      userAgent,
		FailedAttempts: 0,
	}
}

func (u *User) HasRole(role string) bool {
	return slices.Contains(u.Roles, role)
}

func formatAddress(streetAddress, locality, region, postalCode, country string) string {
	return fmt.Sprintf("%s\n%s, %s %s\n%s",
		streetAddress,
		locality, region, postalCode,
		country,
	)
}
