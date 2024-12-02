module github.com/vigiloauth/vigilo/identity

go 1.23

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/vigiloauth/vigilo v0.0.0
)

require golang.org/x/crypto v0.29.0 // indirect

replace (
	github.com/vigiloauth/vigilo => ../
	github.com/vigiloauth/vigilo/identity => ./
)
