# fasthttp-auth

[![Go Version](https://img.shields.io/github/go-mod/go-version/casbin/fasthttp-auth)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/fasthttp-auth)](https://goreportcard.com/report/github.com/casbin/fasthttp-auth)
[![License](https://img.shields.io/github/license/casbin/fasthttp-auth)](https://github.com/casbin/fasthttp-auth/blob/master/LICENSE)
[![Casbin](https://img.shields.io/badge/Casbin-v2.120.0-blue.svg)](https://github.com/casbin/casbin)
[![fasthttp](https://img.shields.io/badge/fasthttp-v1.65.0-green.svg)](https://github.com/valyala/fasthttp)

Authorization middleware for [fasthttp](https://github.com/valyala/fasthttp) using [Casbin](https://github.com/casbin/casbin).

## Installation

```bash
go get github.com/casbin/fasthttp-auth
```

## Quick Start

### 1. Configuration Files

**`authz_model.conf`**:
```conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

**`authz_policy.csv`**:
```csv
p, alice, /, GET
p, alice, /data1, GET
p, bob, /data2, POST
```

### 2. Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/valyala/fasthttp"
    authz "github.com/casbin/fasthttp-auth"
)

func main() {
    a, err := authz.NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv")
    if err != nil {
        log.Fatal(err)
    }

    handler := func(ctx *fasthttp.RequestCtx) {
        fmt.Fprintf(ctx, "Welcome!")
    }

    protected := a.Middleware(handler)
    fasthttp.ListenAndServe(":8081", protected)
}
```

### 3. Test

```bash
# Alice can access / and /data1
curl -H 'X-User: alice' http://localhost:8081/

# Bob can only POST to /data2  
curl -H 'X-User: bob' http://localhost:8081/data2 -X POST

# Anonymous users get 403
curl http://localhost:8081/
```

## How It Works

Authorization is based on `{subject, object, action}`:
- **Subject**: User from `X-User` header (defaults to `anonymous`)
- **Object**: URL path being accessed
- **Action**: HTTP method (GET, POST, etc.)

## Examples

See `example/main.go` for a complete example.

```bash
go run ./example
```

## License

Apache-2.0, see [LICENSE](LICENSE) file




