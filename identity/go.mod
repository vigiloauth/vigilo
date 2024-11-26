module github.com/vigiloauth/vigilo/identity

go 1.22

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/vigiloauth/vigilo v0.0.0
)

replace (
	github.com/vigiloauth/vigilo => ../
	github.com/vigiloauth/vigilo/identity => ./
)
