# fasthttp-auth

Authorization middleware for `fasthttp` based on [Casbin](https://github.com/casbin/casbin).

References: [fasthttp](https://github.com/valyala/fasthttp), [Casbin Middlewares](https://casbin.org/docs/middlewares)

## Installation

```bash
go get github.com/casbin/fasthttp-auth
```

## Quick Start

### 1. Create Configuration Files

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

### 2. Run Your Application

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

## How to Control the Access

The authorization determines a request based on `{subject, object, action}`, which means what `subject` can perform what `action` on what `object`. In this middleware, the meanings are:

1. **subject**: the logged-on user name (extracted from `X-User` header, defaults to `anonymous`)
2. **object**: the URL path for the web resource like "dataset1/item1"
3. **action**: HTTP method like GET, POST, PUT, DELETE, or the high-level actions you defined like "read-file", "write-blog"

For how to write authorization policy and other details, please refer to the [Casbin's documentation](https://casbin.org/docs/get-started).


## Casbin Model and Policy

- `authz_model.conf`: Basic ACL model (r=sub,obj,act; p=sub,obj,act)
- `authz_policy.csv`: Example policy file

## Examples

See `example/main.go` for a complete working example.

### Running the Example

```bash
# Clone the repository
git clone https://github.com/casbin/fasthttp-auth.git
cd fasthttp-auth

# Run the example (includes built-in permission tests)
go run ./example

# Or specify a custom port
PORT=8082 go run ./example
```

The example will:
1. Run permission tests automatically
2. Start an HTTP server on port 8081 (or custom port)
3. Auto-close after 30 seconds


## License

Apache-2.0, see `LICENSE` file.

