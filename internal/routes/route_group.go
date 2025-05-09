package routes

import "net/http"

type RouteGroup struct {
	Name       string
	Middleware []func(http.Handler) http.Handler
	Routes     []Route
}

type Route struct {
	Methods     []string
	Pattern     string
	Handler     http.HandlerFunc
	Middleware  []func(http.Handler) http.Handler
	Description string
}

type RouteBuilder struct {
	route Route
}

func NewRoute() *RouteBuilder {
	return &RouteBuilder{
		route: Route{
			Middleware: make([]func(http.Handler) http.Handler, 0),
		},
	}
}

func (rb *RouteBuilder) SetMethods(methods ...string) *RouteBuilder {
	rb.route.Methods = methods
	return rb
}

func (rb *RouteBuilder) SetPattern(pattern string) *RouteBuilder {
	rb.route.Pattern = pattern
	return rb
}

func (rb *RouteBuilder) SetHandler(handler http.HandlerFunc) *RouteBuilder {
	rb.route.Handler = handler
	return rb
}

func (rb *RouteBuilder) SetMiddleware(middleware ...func(http.Handler) http.Handler) *RouteBuilder {
	rb.route.Middleware = append(rb.route.Middleware, middleware...)
	return rb
}

func (rb *RouteBuilder) SetDescription(description string) *RouteBuilder {
	rb.route.Description = description
	return rb
}

func (rb *RouteBuilder) Build() Route {
	return rb.route
}

func (r Route) getHTTPMethods() []string {
	if len(r.Methods) > 0 {
		return r.Methods
	}

	return []string{http.MethodGet} // Default to GET if no method is provided
}
