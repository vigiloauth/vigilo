module github.com/vigiloauth/vigilo

go 1.23

require (
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.29.0
	github.com/vigiloauth/vigilo/identity v0.1.0-alpha.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-chi/chi/v5 v5.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// For local development only
// replace (
	// github.com/vigiloauth/vigilo/identity => ./identity
// )
