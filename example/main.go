// Copyright 2024 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/valyala/fasthttp"

	authz "github.com/casbin/fasthttp-auth"
)

// Test case structure
type testCase struct {
	user     string
	path     string
	method   string
	expected bool
	desc     string
}

func main() {
	// Create authorizer (loads model and policy from files)
	a, err := authz.NewAuthorizerFromFiles("authz_model.conf", "authz_policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	// Run permission tests first
	runPermissionTests(a)

	// Define your handler with different routes
	handler := func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())
		user := string(ctx.Request.Header.Peek("X-User"))
		if user == "" {
			user = "anonymous"
		}

		switch path {
		case "/":
			fmt.Fprintf(ctx, "Welcome to the home page! User: %s", user)
		case "/data1":
			fmt.Fprintf(ctx, "Data1 page - User: %s", user)
		case "/data2":
			fmt.Fprintf(ctx, "Data2 page - User: %s, Method: %s", user, ctx.Method())
		case "/api/users":
			fmt.Fprintf(ctx, "Users API - User: %s", user)
		default:
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			fmt.Fprintf(ctx, "Page not found: %s", path)
		}
	}

	// Wrap with authorization middleware
	protected := a.Middleware(handler)

	// Start server
	log.Println("\n=== Starting HTTP Server ===")
	log.Println("Server starting on :8081")
	log.Println("The server will auto-close in 30 seconds for testing...")

	// Start server in goroutine
	go func() {
		if err := fasthttp.ListenAndServe(":8081", protected); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Auto-close after 30 seconds
	time.Sleep(30 * time.Second)
	log.Println("Testing completed, server shutting down")
}

// Run permission tests
func runPermissionTests(a *authz.Authorizer) {
	log.Println("=== Running Permission Tests ===")

	// Define test cases based on our policy
	testCases := []testCase{
		// Alice's permissions
		{"alice", "/", "GET", true, "alice can access root path"},
		{"alice", "/data1", "GET", true, "alice can access /data1"},
		{"alice", "/data2", "GET", false, "alice cannot access /data2"},
		{"alice", "/", "POST", false, "alice cannot POST to root path"},

		// Bob's permissions
		{"bob", "/", "GET", false, "bob cannot access root path"},
		{"bob", "/data1", "GET", false, "bob cannot access /data1"},
		{"bob", "/data2", "POST", true, "bob can POST to /data2"},
		{"bob", "/data2", "GET", false, "bob cannot GET /data2"},

		// Anonymous user tests
		{"", "/", "GET", false, "anonymous user cannot access any path"},
		{"anonymous", "/", "GET", false, "anonymous user cannot access any path"},

		// Non-existent path tests
		{"alice", "/nonexistent", "GET", false, "alice cannot access non-existent path"},
		{"bob", "/api/users", "GET", false, "bob cannot access unauthorized API path"},
	}

	// Run tests
	passed := 0
	total := len(testCases)

	for i, tc := range testCases {
		result := testPermission(a, tc)
		if result == tc.expected {
			passed++
			log.Printf("✅ Test %d: %s", i+1, tc.desc)
		} else {
			log.Printf("❌ Test %d: %s (Expected: %v, Actual: %v)", i+1, tc.desc, tc.expected, result)
		}
	}

	log.Printf("=== Test Results: %d/%d Passed ===", passed, total)
}

// Test single permission
func testPermission(a *authz.Authorizer, tc testCase) bool {
	// Create test request context
	ctx := &fasthttp.RequestCtx{}

	// Set user
	if tc.user != "" {
		ctx.Request.Header.Set("X-User", tc.user)
	}

	// Set path and method
	ctx.Request.SetRequestURI(tc.path)
	ctx.Request.Header.SetMethod(tc.method)

	// Mark if allowed
	allowed := false

	// Create test handler
	next := func(ctx *fasthttp.RequestCtx) {
		allowed = true
	}

	// Execute permission check
	handler := a.Middleware(next)
	handler(ctx)

	return allowed
}
