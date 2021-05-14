package grpcauth

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "github.com/rotationalio/grpc-token-auth/proto"
)

func init() {
	// Set the random seed
	rand.Seed(time.Now().UnixNano())

	// Initialize zerolog with GCP logging requirements
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"})
}

var (
	jwtAudience      = "localhost:8318/grpcauth.Authenticator"
	jwtSigningMethod = jwt.SigningMethodHS256
	tokens           = make(map[string]struct{})
	userdb           = map[string]string{
		"secretagent": "$argon2id$v=19$m=65536,t=1,p=2$louqMxp83FdMTlvDlAkSDQ==$7LThPmUTO3TFu3BP/nwADwJg9jNsGtCt52RG45RRIeM=",
	}
)

type Server struct {
	api.UnimplementedAuthenticatorServer
	srv    *grpc.Server
	errc   chan error
	secret []byte
}

func New() (_ *Server, err error) {
	// Generate a random secret for the server to authenticate JWT tokens
	// The secret will be different every time the server is running, invalidating any
	// login tokens before server reboot.
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return nil, fmt.Errorf("could not generate random secret: %s", err)
	}

	// Create the server instance.
	s := &Server{
		errc:   make(chan error, 1),
		secret: secret,
	}

	// Create the gRPC server with the custom interceptor and register the service.
	s.srv = grpc.NewServer(grpc.UnaryInterceptor(s.serverInterceptor))
	api.RegisterAuthenticatorServer(s.srv, s)
	return s, nil
}

func (s *Server) Serve(addr string) (err error) {
	// Listen for CTRL+C and call shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		s.errc <- s.Shutdown()
	}()

	// Listen on the address (ipaddr:port)
	var sock net.Listener
	if sock, err = net.Listen("tcp", addr); err != nil {
		return fmt.Errorf("could not listen on %q: %s", addr, err)
	}
	defer sock.Close()

	// Handle gRPC methods in a go routine
	go func() {
		log.Info().Str("listen", addr).Msg("server started")
		if err := s.srv.Serve(sock); err != nil {
			s.errc <- err
		}
	}()

	// Wait for server error or shutdown
	if err = <-s.errc; err != nil {
		return err
	}
	return nil
}

func (s *Server) Shutdown() (err error) {
	// Shutdown the gRPC server
	s.srv.GracefulStop()
	return nil
}

// Login the user with the specified username and password. Login uses argon2 derived
// key comparisons to verify the user without storing the password in plain text. It
// returns JWT access and refresh tokens that can be used to access the secure endpoint.
func (s *Server) Login(ctx context.Context, in *api.LoginRequest) (out *api.LoginReply, err error) {
	if in.Username == "" || in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password required")
	}

	dk, ok := userdb[in.Username]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no user %q in the database", in.Username)
	}

	var authenticated bool
	if authenticated, err = VerifyDerivedKey(dk, in.Password); err != nil {
		log.Error().Err(err).Msg("could not verify derived key")
		return nil, status.Errorf(codes.FailedPrecondition, "could not verify derived key: %s", err)
	}

	if !authenticated {
		return nil, status.Error(codes.Unauthenticated, "incorrect username and password")
	}

	// Create JWT token for downstream access
	claims := &jwt.StandardClaims{
		Id:        uuid.New().String(),
		Audience:  jwtAudience,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}

	out = &api.LoginReply{}
	at := jwt.NewWithClaims(jwtSigningMethod, claims)
	if out.Token, err = at.SignedString(s.secret); err != nil {
		log.Error().Err(err).Msg("could not generate access token")
		return nil, fmt.Errorf("could not generate access token: %s", err)
	}

	// Store the ID in the tokens database as a valid logged-in token.
	tokens[claims.Id] = struct{}{}

	log.Info().Str("username", in.Username).Msg("login")
	return out, nil
}

// Logout removes the authorization token from the list of logged-in tokens, which means
// that it cannot be used again as a login-token.
func (s *Server) Logout(ctx context.Context, in *api.Empty) (out *api.LogoutReply, err error) {
	out = &api.LogoutReply{Success: false}

	// Fetch the token ID from the context
	token := getToken(ctx)
	if token == "" {
		return out, nil
	}

	// Locate the token in the tokens map and delete it. If the token is not in the
	// tokens map, then success will be false, but no error is returned.
	if _, out.Success = tokens[token]; out.Success {
		delete(tokens, token)
	}
	return out, nil
}

// Secure should only return a message if the user is authenticated.
func (s *Server) Secure(ctx context.Context, in *api.Empty) (out *api.SecureReply, err error) {
	return &api.SecureReply{Message: "this is the super secret message!"}, nil
}
