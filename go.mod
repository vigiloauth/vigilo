module github.com/vigiloauth/vigilo

go 1.23.3

require (
    github.com/vigiloauth/vigilo/authentication v0.0.0
    github.com/vigiloauth/vigilo/authorization v0.0.0
)

replace github.com/vigiloauth/vigilo/authentication => ./authentication
replace github.com/vigiloauth/vigilo/authorization => ./authorization