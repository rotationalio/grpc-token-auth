package grpcauth

import (
	"context"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

//===========================================================================
// Client Credentials
//===========================================================================

// TokenCredentials implements per-RPC credentials to be provided by the client as a
// dial or call option to authenticate the user via the Authorization: Bearer header in
// the request.
type TokenCredentials struct {
	Token string
}

// GetRequestMetadata implements credentials.PerRPCCredentials to set the token header.
func (c TokenCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": "Bearer " + c.Token,
	}, nil
}

// RequireTransportSecurity should be True for this authentication mechanism, since
// anyone with the access token will be authorized. However, for the purposes of this
// demo, it's set to False for testing and development.
func (c TokenCredentials) RequireTransportSecurity() bool {
	return false
}

//===========================================================================
// Server Interceptor
//===========================================================================

// Server interceptor performs token authorization for every request unless the request
// is to the Login method; if the request is not authorized an Unauthenticated error is
// returned to the user before the handler is called. The interceptor also does some
// lightweight logging with request latencies.
//
// NOTE: the interceptor must be a server method so that it can access the server secret
// key to validate JWT authentication tokens.
func (s *Server) serverInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// Track how long the method takes to execute.
	start := time.Now()

	// Authorize the request unless the request is a Login RPC.
	if info.FullMethod != "/grpcauth.api.Authenticator/Login" {
		var user string
		if user, err = s.authorize(ctx); err != nil {
			return nil, err
		}

		// Add the user to the context for downstream handlers (e.g. logout)
		ctx = context.WithValue(ctx, tokenCtxKey, user)
	}

	// Call the handler to finalize the request and get the response.
	h, err := handler(ctx, req)

	// Log with zerolog - checkout grpclog.LoggerV2 for default logging.
	log.Info().Str("method", info.FullMethod).Str("latency", time.Since(start).String()).Err(err)
	return h, err
}

// Authorize fetches the Authorization: Bearer header from the request, parses the JWT
// token it contains and validates and verifies the token using the server secret key.
func (s *Server) authorize(ctx context.Context) (user string, err error) {
	// Fetch the bearer token (either the access or the refresh token) from the
	// Authorization: Bearer header of the incoming request.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.InvalidArgument, "could not retrieve metadata")
	}

	bearer, ok := md["authorization"]
	if !ok || len(bearer) == 0 {
		return "", status.Error(codes.Unauthenticated, "no Bearer token in Authorization header")
	}

	// Parse the JWT token from the header
	var (
		token  *jwt.Token
		claims *jwt.StandardClaims
	)
	if len(bearer) == 1 {
		parts := strings.Split(bearer[0], "Bearer ")
		if len(parts) == 2 {
			claims = &jwt.StandardClaims{}
			if token, err = jwt.ParseWithClaims(strings.TrimSpace(parts[1]), claims, s.jwtKey); err != nil {
				return "", status.Error(codes.Unauthenticated, err.Error())
			}
		}
	}

	if token == nil {
		return "", status.Error(codes.Unauthenticated, "could not parse authorization token")
	}

	// Verify the token is still logged in by checking if it is in the list of tokens.
	if _, ok := tokens[claims.Id]; !ok {
		return "", status.Error(codes.Unauthenticated, "token no longer valid")
	}

	// Verify the token audience is correct.
	if !claims.VerifyAudience(jwtAudience, true) {
		return "", status.Error(codes.Unauthenticated, "wrong audience for token")
	}

	// All checks complete, the token is authorized! Return the claims ID to identify
	// the user in downstream request handlers.
	return claims.Id, nil
}

// The jwtKeyFunc is required to validate tokens, returning the server secret. This
// function can be used to return a per-token secret or perform database lookups if
// required.
func (s *Server) jwtKey(token *jwt.Token) (interface{}, error) {
	return s.secret, nil
}

// Context handlers for storing and fetching the token ID from the context.
// See: https://www.calhoun.io/pitfalls-of-context-values-and-how-to-avoid-or-mitigate-them/
type tokenCtxKeyType string

const tokenCtxKey tokenCtxKeyType = "token"

func getToken(ctx context.Context) string {
	token, ok := ctx.Value(tokenCtxKey).(string)
	if !ok {
		return ""
	}
	return token
}
