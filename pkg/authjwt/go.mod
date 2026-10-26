module github.com/highflame-ai/zeroid/pkg/authjwt

go 1.27.0

require (
	github.com/highflame-ai/zeroid/pkg/jwks v1.23.1
	github.com/lestrrat-go/jwx/v4 v4.4.0
	github.com/rs/zerolog v1.35.1
	github.com/stretchr/testify v1.12.0
)

require (
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/highflame-ai/zeroid/pkg/jwks => ../jwks
