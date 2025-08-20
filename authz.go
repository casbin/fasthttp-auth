package authz

import (
	"github.com/casbin/casbin/v2"
	"github.com/valyala/fasthttp"
)

// SubjectGetter extracts the subject (user) from the request context.
type SubjectGetter func(ctx *fasthttp.RequestCtx) string

// ObjectGetter extracts the object (resource) from the request context.
type ObjectGetter func(ctx *fasthttp.RequestCtx) string

// ActionGetter extracts the action (operation) from the request context.
type ActionGetter func(ctx *fasthttp.RequestCtx) string

// Option configures Authorizer.
type Option func(a *Authorizer)

// Authorizer is a fasthttp middleware that authorizes requests using Casbin.
type Authorizer struct {
	enforcer         *casbin.Enforcer
	getSubject       SubjectGetter
	getObject        ObjectGetter
	getAction        ActionGetter
	forbiddenHandler fasthttp.RequestHandler
}

// NewAuthorizer creates an Authorizer with the provided Casbin enforcer.
func NewAuthorizer(enforcer *casbin.Enforcer, opts ...Option) *Authorizer {
	a := &Authorizer{
		enforcer: enforcer,
		getSubject: func(ctx *fasthttp.RequestCtx) string {
			// Default: read subject from header "X-User"; fall back to "anonymous"
			subject := string(ctx.Request.Header.Peek("X-User"))
			if subject == "" {
				subject = "anonymous"
			}
			return subject
		},
		getObject: func(ctx *fasthttp.RequestCtx) string {
			return string(ctx.Path())
		},
		getAction: func(ctx *fasthttp.RequestCtx) string {
			return string(ctx.Method())
		},
		forbiddenHandler: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetContentType("text/plain; charset=utf-8")
			_, _ = ctx.WriteString("Forbidden")
		},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// NewAuthorizerFromFiles creates an Authorizer by loading model and policy from files.
func NewAuthorizerFromFiles(modelPath, policyPath string, opts ...Option) (*Authorizer, error) {
	e, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, err
	}
	return NewAuthorizer(e, opts...), nil
}

// Middleware returns a fasthttp.RequestHandler that enforces authorization before calling next.
func (a *Authorizer) Middleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		subject := a.getSubject(ctx)
		object := a.getObject(ctx)
		action := a.getAction(ctx)

		ok, err := a.enforcer.Enforce(subject, object, action)
		if err != nil {
			// On error, fail closed by default
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetContentType("text/plain; charset=utf-8")
			_, _ = ctx.WriteString("Authorization error")
			return
		}
		if !ok {
			a.forbiddenHandler(ctx)
			return
		}
		next(ctx)
	}
}

// WithSubjectGetter customizes how to extract subject from request.
func WithSubjectGetter(getter SubjectGetter) Option {
	return func(a *Authorizer) { a.getSubject = getter }
}

// WithObjectGetter customizes how to extract object from request.
func WithObjectGetter(getter ObjectGetter) Option {
	return func(a *Authorizer) { a.getObject = getter }
}

// WithActionGetter customizes how to extract action from request.
func WithActionGetter(getter ActionGetter) Option {
	return func(a *Authorizer) { a.getAction = getter }
}

// WithForbiddenHandler customizes the 403 response.
func WithForbiddenHandler(handler fasthttp.RequestHandler) Option {
	return func(a *Authorizer) { a.forbiddenHandler = handler }
}

// AuthorizerMiddleware is a convenience helper to construct middleware from an enforcer directly.
func AuthorizerMiddleware(enforcer *casbin.Enforcer, opts ...Option) func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	a := NewAuthorizer(enforcer, opts...)
	return a.Middleware
}
