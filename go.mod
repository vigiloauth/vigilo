module github.com/vigiloauth/vigilo

go 1.22

require (
	github.com/stretchr/testify v1.10.0
	github.com/vigiloauth/vigilo/identity v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.29.0
)

replace (
	github.com/vigiloauth/vigilo => ./
	github.com/vigiloauth/vigilo/identity => ./identity
)
