// Copyright 2025 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"testing"

	"github.com/valyala/fasthttp"
)

// helper to execute middleware once and report whether next() ran
func runOnce(a *Authorizer, user, path, method string) (allowed bool, status int, body []byte) {
	allowed = false
	h := a.Middleware(func(ctx *fasthttp.RequestCtx) {
		allowed = true
	})
	var ctx fasthttp.RequestCtx
	if user != "" {
		ctx.Request.Header.Set("X-User", user)
	}
	ctx.Request.SetRequestURI(path)
	ctx.Request.Header.SetMethod(method)
	h(&ctx)
	status = ctx.Response.StatusCode()
	body = ctx.Response.Body()
	return
}

func TestMiddleware_Allow(t *testing.T) {
	a, err := NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	allowed, status, _ := runOnce(a, "alice", "/", "GET")
	if !allowed {
		t.Fatalf("expected request to be allowed, but it was denied")
	}
	// default fasthttp status is 200 if handler runs
	if status != 200 {
		t.Fatalf("expected status 200 when allowed, got %d", status)
	}
}

func TestMiddleware_Deny(t *testing.T) {
	a, err := NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	allowed, status, body := runOnce(a, "bob", "/", "GET")
	if allowed {
		t.Fatalf("expected request to be denied, but it was allowed")
	}
	if status != fasthttp.StatusForbidden {
		t.Fatalf("expected status %d when denied, got %d", fasthttp.StatusForbidden, status)
	}
	if string(body) == "" {
		t.Fatalf("expected forbidden body to be written")
	}
}

func TestMiddleware_AnonymousDenied(t *testing.T) {
	a, err := NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	allowed, status, _ := runOnce(a, "", "/", "GET")
	if allowed {
		t.Fatalf("expected anonymous request to be denied")
	}
	if status != fasthttp.StatusForbidden {
		t.Fatalf("expected status %d for anonymous denied, got %d", fasthttp.StatusForbidden, status)
	}
}

func TestMiddleware_CustomForbiddenHandler(t *testing.T) {
	a, err := NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv",
		WithForbiddenHandler(func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(418)
			_, _ = ctx.WriteString("nope")
		}),
	)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	allowed, status, body := runOnce(a, "bob", "/", "GET")
	if allowed {
		t.Fatalf("expected request to be denied with custom handler")
	}
	if status != 418 {
		t.Fatalf("expected custom status 418, got %d", status)
	}
	if string(body) != "nope" {
		t.Fatalf("expected custom body 'nope', got %q", string(body))
	}
}

func TestMiddleware_CustomGetters(t *testing.T) {
	a, err := NewAuthorizerFromFiles(
		"authz_model.conf",
		"authz_policy.csv",
		WithSubjectGetter(func(ctx *fasthttp.RequestCtx) string {
			return string(ctx.QueryArgs().Peek("u"))
		}),
		WithObjectGetter(func(ctx *fasthttp.RequestCtx) string { return "/data1" }),
		WithActionGetter(func(ctx *fasthttp.RequestCtx) string { return "GET" }),
	)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	// despite POST and different path, custom getters force (alice, /data1, GET)
	allowed, status, _ := runOnce(a, "", "/ignored?u=alice", "POST")
	if !allowed {
		t.Fatalf("expected request to be allowed by custom getters")
	}
	if status != 200 {
		t.Fatalf("expected 200 when allowed with custom getters, got %d", status)
	}
}

func TestAuthorizerMiddleware_Helper(t *testing.T) {
	// construct enforcer then build middleware via helper
	a, err := NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	mwFactory := AuthorizerMiddleware(a.enforcer)
	allowed := false
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.Set("X-User", "alice")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetMethod("GET")
	handler := mwFactory(func(ctx *fasthttp.RequestCtx) { allowed = true })
	handler(&ctx)
	if !allowed {
		t.Fatalf("expected request to be allowed via AuthorizerMiddleware helper")
	}
}
