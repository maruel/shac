// Copyright 2016 The LUCI Authors.
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

package prpc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"go.chromium.org/luci/common/logging"
	"go.chromium.org/luci/server/router"
)

var (
	// Describes the default permitted headers for cross-origin requests.
	//
	// It explicitly includes a subset of the default CORS-safelisted request
	// headers that are relevant to RPCs, as well as "Authorization" header.
	//
	// Custom AccessControl implementations may allow more headers.
	//
	// See https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header
	allowHeaders = strings.Join([]string{"Origin", "Content-Type", "Accept", "Authorization"}, ", ")
	allowMethods = strings.Join([]string{"OPTIONS", "POST"}, ", ")

	// allowPreflightCacheAgeSecs is the amount of time to enable the browser to
	// cache the preflight access control response, in seconds.
	//
	// 600 seconds is 10 minutes.
	allowPreflightCacheAgeSecs = "600"

	// exposeHeaders lists the non-standard response headers that are exposed to
	// client that make cross-origin calls.
	exposeHeaders = strings.Join([]string{HeaderGRPCCode}, ", ")
)

// AccessControlDecision describes how to handle a cross-origin request.
//
// It is returned by AccessControl server callback based on the origin of the
// call and defines what CORS policy headers to add to responses to preflight
// requests and actual cross-origin requests.
//
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS for the general
// overview of CORS policies.
type AccessControlDecision struct {
	// AllowCrossOriginRequests defines if CORS policies should be enabled at all.
	//
	// If false, the server will not send any CORS policy headers and the browser
	// will use the default "same-origin" policy. All fields below will be
	// ignored.
	//
	// See https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
	AllowCrossOriginRequests bool

	// AllowCredentials defines if a cross-origin request is allowed to use
	// credentials associated with the pRPC server's domain.
	//
	// This setting controls if the client can use `credentials: include` option
	// in Fetch init parameters or `withCredentials = true` in XMLHttpRequest.
	//
	// Credentials, as defined by Web APIs, are cookies, HTTP authentication
	// entries, and TLS client certificates.
	//
	// See
	//   https://developer.mozilla.org/en-US/docs/Web/API/fetch#parameters
	//   https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/withCredentials
	//   https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
	AllowCredentials bool

	// AllowHeaders is a list of request headers that a cross-origin request is
	// allowed to have.
	//
	// Extends the default list of allowed headers, which is: "Accept",
	// "Authorization", "Content-Type", Origin".
	//
	// Use this option if the authentication interceptor checks some custom
	// headers.
	AllowHeaders []string
}

// AllowOriginAll is a CORS policy that allows any origin to send cross-origin
// requests that can use credentials (e.g. cookies) and "Authorization" header.
//
// Other non-standard headers are forbidden. Use a custom AccessControl callback
// to allow them.
func AllowOriginAll(ctx context.Context, origin string) AccessControlDecision {
	return AccessControlDecision{
		AllowCrossOriginRequests: true,
		AllowCredentials:         true,
	}
}

// Override is a pRPC method-specific override which may optionally handle the
// entire pRPC method call. If it returns true, the override is assumed to
// have fully handled the pRPC method call and processing of the request does
// not continue. In this case it's the override's responsibility to adhere to
// all pRPC semantics. However if it returns false, processing continues as
// normal, allowing the override to act as a preprocessor. In this case it's
// the override's responsibility to ensure it hasn't done anything that will
// be incompatible with pRPC semantics (such as writing garbage to the response
// writer in the router context).
type Override func(*router.Context) bool

// Server is a pRPC server to serve RPC requests.
// Zero value is valid.
type Server struct {
	// AccessControl, if not nil, is a callback that is invoked per request to
	// determine what CORS access control headers, if any, should be added to
	// the response.
	//
	// It controls what cross-origin RPC calls are allowed from a browser and what
	// responses cross-origin clients may see. Does not effect calls made by
	// non-browser RPC clients.
	//
	// This callback is invoked for each CORS pre-flight request as well as for
	// actual RPC requests. It can make its decision based on the origin of
	// the request.
	//
	// If nil, the server will not send any CORS headers and the browser will
	// use the default "same-origin" policy.
	//
	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS for the general
	// overview of CORS policies.
	AccessControl func(ctx context.Context, origin string) AccessControlDecision

	// HackFixFieldMasksForJSON indicates whether to attempt a workaround for
	// https://github.com/golang/protobuf/issues/745 when the request has
	// Content-Type: application/json. This hack is scheduled for removal.
	// TODO(crbug/1082369): Remove this workaround once field masks can be decoded.
	HackFixFieldMasksForJSON bool

	// UnaryServerInterceptor provides a hook to intercept the execution of
	// a unary RPC on the server. It is the responsibility of the interceptor to
	// invoke handler to complete the RPC.
	UnaryServerInterceptor grpc.UnaryServerInterceptor

	// EnableResponseCompression allows the server to compress responses if they
	// are larger than a certain threshold.
	//
	// If false (default), responses are never compressed.
	//
	// If true and the client sends "Accept-Encoding: gzip" (default for all Go
	// clients), responses larger than a certain threshold will be compressed.
	//
	// The request compression is configured independently on the client. The
	// server always accepts compressed requests.
	EnableResponseCompression bool

	mu        sync.RWMutex
	services  map[string]*service
	overrides map[string]map[string]Override
}

type service struct {
	methods map[string]grpc.MethodDesc
	impl    any
}

// RegisterService registers a service implementation.
// Called from the generated code.
//
// desc must contain description of the service, its message types
// and all transitive dependencies.
//
// Panics if a service of the same name is already registered.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl any) {
	serv := &service{
		impl:    impl,
		methods: make(map[string]grpc.MethodDesc, len(desc.Methods)),
	}
	for _, m := range desc.Methods {
		serv.methods[m.MethodName] = m
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.services == nil {
		s.services = map[string]*service{}
	} else if _, ok := s.services[desc.ServiceName]; ok {
		panic(fmt.Errorf("service %q is already registered", desc.ServiceName))
	}

	s.services[desc.ServiceName] = serv
}

// RegisterOverride registers an overriding function.
//
// Panics if an override for the given service method is already registered.
func (s *Server) RegisterOverride(serviceName, methodName string, fn Override) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.overrides == nil {
		s.overrides = map[string]map[string]Override{}
	}
	if _, ok := s.overrides[serviceName]; !ok {
		s.overrides[serviceName] = map[string]Override{}
	}
	if _, ok := s.overrides[serviceName][methodName]; ok {
		panic(fmt.Errorf("method %q of service %q is already overridden", methodName, serviceName))
	}

	s.overrides[serviceName][methodName] = fn
}

// InstallHandlers installs HTTP handlers at /prpc/:service/:method.
//
// See https://godoc.org/go.chromium.org/luci/grpc/prpc#hdr-Protocol
// for pRPC protocol.
//
// Assumes incoming requests are not authenticated yet. Authentication should be
// performed by an interceptor (just like when using a gRPC server).
func (s *Server) InstallHandlers(r *router.Router, base router.MiddlewareChain) {
	r.POST("/prpc/:service/:method", base, s.handlePOST)
	r.OPTIONS("/prpc/:service/:method", base, s.handleOPTIONS)
}

// handle handles RPCs.
// See https://godoc.org/go.chromium.org/luci/grpc/prpc#hdr-Protocol
// for pRPC protocol.
func (s *Server) handlePOST(c *router.Context) {
	serviceName := c.Params.ByName("service")
	methodName := c.Params.ByName("method")

	override, service, method, methodFound := s.lookup(serviceName, methodName)
	// Override takes precedence over notImplementedErr.
	if override != nil && override(c) {
		return
	}

	s.setAccessControlHeaders(c, false)
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header()["Date"] = nil // omit, not part of the protocol

	res := response{}
	switch {
	case service == nil:
		res.err = status.Errorf(
			codes.Unimplemented,
			"service %q is not implemented",
			serviceName)
	case !methodFound:
		res.err = status.Errorf(
			codes.Unimplemented,
			"method %q in service %q is not implemented",
			methodName, serviceName)
	default:
		s.call(c, service, method, &res)
	}

	if res.err != nil {
		writeError(c.Context, c.Writer, res.err, res.fmt)
		return
	}

	writeMessage(c.Context, c.Writer, res.out, res.fmt, s.EnableResponseCompression && res.acceptsGZip)
}

func (s *Server) handleOPTIONS(c *router.Context) {
	s.setAccessControlHeaders(c, true)
	c.Writer.WriteHeader(http.StatusOK)
}

var requestContextKey = "context key with *requestContext"

type requestContext struct {
	// additional headers that will be sent in the response
	header http.Header
}

// SetHeader sets the header metadata.
// When called multiple times, all the provided metadata will be merged.
//
// If ctx is not a pRPC server context, then SetHeader calls grpc.SetHeader
// such that calling prpc.SetHeader works for both pRPC and gRPC.
func SetHeader(ctx context.Context, md metadata.MD) error {
	if rctx, ok := ctx.Value(&requestContextKey).(*requestContext); ok {
		if err := metaIntoHeaders(md, rctx.header); err != nil {
			return err
		}
		return nil
	}
	return grpc.SetHeader(ctx, md)
}

type response struct {
	out         proto.Message
	fmt         Format
	acceptsGZip bool
	err         error
}

func (s *Server) lookup(serviceName, methodName string) (override Override, service *service, method grpc.MethodDesc, methodFound bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if methods, ok := s.overrides[serviceName]; ok {
		override = methods[methodName]
	}
	service = s.services[serviceName]
	if service == nil {
		return
	}
	method, methodFound = service.methods[methodName]
	return
}

func (s *Server) call(c *router.Context, service *service, method grpc.MethodDesc, r *response) {
	var perr *protocolError
	r.fmt, perr = responseFormat(c.Request.Header.Get(headerAccept))
	if perr != nil {
		r.err = perr
		return
	}

	methodCtx, cancelFunc, err := parseHeader(c.Context, c.Request.Header, c.Request.Host)
	if err != nil {
		r.err = protocolErr(codes.InvalidArgument, http.StatusBadRequest, "bad request headers: %s", err)
		return
	}
	defer cancelFunc()

	if r.acceptsGZip, err = acceptsGZipResponse(c.Request.Header); err != nil {
		r.err = protocolErr(codes.InvalidArgument, http.StatusBadRequest, "bad Accept headers: %s", err)
		return
	}

	methodCtx = context.WithValue(methodCtx, &requestContextKey, &requestContext{header: c.Writer.Header()})

	// Populate peer.Peer if we can manage to parse the address. This may fail
	// if the server is exposed via a Unix socket, for example.
	if addr, err := netip.ParseAddrPort(c.Request.RemoteAddr); err == nil {
		methodCtx = peer.NewContext(methodCtx, &peer.Peer{
			Addr: net.TCPAddrFromAddrPort(addr),
		})
	}

	out, err := method.Handler(service.impl, methodCtx, func(in any) error {
		if in == nil {
			return status.Errorf(codes.Internal, "input message is nil")
		}
		// Do not collapse it to one line. There is implicit err type conversion.
		if perr := readMessage(c.Request, in.(proto.Message), s.HackFixFieldMasksForJSON); perr != nil {
			return perr
		}
		return nil
	}, s.UnaryServerInterceptor)

	switch {
	case err != nil:
		r.err = err
	case out == nil:
		r.err = status.Error(codes.Internal, "service returned nil message")
	default:
		r.out = out.(proto.Message)
	}
	return
}

func (s *Server) setAccessControlHeaders(c *router.Context, preflight bool) {
	// Don't write out access control headers if the origin is unspecified.
	const originHeader = "Origin"
	origin := c.Request.Header.Get(originHeader)
	if origin == "" || s.AccessControl == nil {
		return
	}
	accessControl := s.AccessControl(c.Context, origin)
	if !accessControl.AllowCrossOriginRequests {
		if accessControl.AllowCredentials {
			logging.Warningf(c.Context, "pRPC AccessControl: ignoring AllowCredentials since AllowCrossOriginRequests is false")
		}
		if len(accessControl.AllowHeaders) != 0 {
			logging.Warningf(c.Context, "pRPC AccessControl: ignoring AllowHeaders since AllowCrossOriginRequests is false")
		}
		return
	}

	h := c.Writer.Header()
	h.Add("Access-Control-Allow-Origin", origin)
	h.Add("Vary", originHeader) // indicate the response depends on Origin header
	if accessControl.AllowCredentials {
		h.Add("Access-Control-Allow-Credentials", "true")
	}

	if preflight {
		if len(accessControl.AllowHeaders) == 0 {
			h.Add("Access-Control-Allow-Headers", allowHeaders)
		} else {
			h.Add("Access-Control-Allow-Headers",
				strings.Join(accessControl.AllowHeaders, ", ")+", "+allowHeaders)
		}
		h.Add("Access-Control-Allow-Methods", allowMethods)
		h.Add("Access-Control-Max-Age", allowPreflightCacheAgeSecs)
	} else {
		h.Add("Access-Control-Expose-Headers", exposeHeaders)
	}
}

// ServiceNames returns a sorted list of full names of all registered services.
func (s *Server) ServiceNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.services))
	for name := range s.services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
