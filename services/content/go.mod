module github.com/fyberflix/fyberflix/services/content

go 1.24

require (
	github.com/fyberflix/fyberflix/libs/authz v0.0.0
	github.com/jackc/pgx/v5 v5.7.2
)

replace github.com/fyberflix/fyberflix/libs/authz => ../../libs/authz
