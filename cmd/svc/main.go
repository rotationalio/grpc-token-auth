package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	grpcauth "github.com/rotationalio/grpc-token-auth"
	api "github.com/rotationalio/grpc-token-auth/proto"
	cli "github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

func main() {
	app := cli.NewApp()
	app.Name = "grpcauth"
	app.Usage = "experimenting with authentication in gRPC"
	app.Version = "beta"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "endpoint",
			Aliases: []string{"e"},
			Usage:   "endpoint to connect to the server on (client commands)",
			Value:   "localhost:8318",
		},
		&cli.StringFlag{
			Name:    "token-file",
			Aliases: []string{"t"},
			Usage:   "file with authenticated token writen to it",
			Value:   "token.txt",
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:     "serve",
			Usage:    "run the grpc-auth server",
			Category: "server",
			Action:   serve,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "addr",
					Aliases: []string{"a"},
					Usage:   "listen address to bind to",
					Value:   ":8318",
				},
			},
		},
		{
			Name:     "mkpasswd",
			Usage:    "create and print out a derived key password",
			Category: "server",
			Action:   mkpasswd,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "password",
					Aliases: []string{"p"},
					Usage:   "the password to create a derived key from",
				},
			},
		},
		{
			Name:     "login",
			Usage:    "send a login request to the grpc-auth server",
			Category: "client",
			Action:   login,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "username",
					Aliases: []string{"u"},
					Usage:   "username to login with",
				},
				&cli.StringFlag{
					Name:    "password",
					Aliases: []string{"p"},
					Usage:   "password to login with",
				},
			},
		},
		{
			Name:     "logout",
			Usage:    "logout ensures the token cannot be used again",
			Category: "client",
			Action:   logout,
			Flags:    []cli.Flag{},
		},
		{
			Name:     "secure",
			Usage:    "send a secure request to the grpc-auth server",
			Category: "client",
			Action:   secure,
			Flags:    []cli.Flag{},
		},
	}

	app.Run(os.Args)
}

func serve(c *cli.Context) (err error) {
	var server *grpcauth.Server
	if server, err = grpcauth.New(); err != nil {
		return cli.Exit(err, 1)
	}

	if err = server.Serve(c.String("addr")); err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}

func mkpasswd(c *cli.Context) (err error) {
	password := c.String("password")
	if password == "" {
		return cli.Exit("specify a password (randomly generated passwords implemented later)", 1)
	}

	if password, err = grpcauth.CreateDerivedKey(c.String("password")); err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Println(password)
	return nil
}

func login(c *cli.Context) (err error) {
	var cc *grpc.ClientConn
	if cc, err = grpc.Dial(c.String("endpoint"), grpc.WithInsecure()); err != nil {
		return cli.Exit(err, 1)
	}
	defer cc.Close()

	req := &api.LoginRequest{
		Username: c.String("username"),
		Password: c.String("password"),
	}

	client := api.NewAuthenticatorClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rep *api.LoginReply
	if rep, err = client.Login(ctx, req); err != nil {
		return cli.Exit(err, 1)
	}

	// Save/overwrite the token file to disk
	if err = ioutil.WriteFile(c.String("token-file"), []byte(rep.Token), 0600); err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Printf("token written to %s\n", c.String("token-file"))
	return nil
}

func logout(c *cli.Context) (err error) {
	var cc *grpc.ClientConn
	if cc, err = grpc.Dial(c.String("endpoint"), grpc.WithInsecure()); err != nil {
		return cli.Exit(err, 1)
	}
	defer cc.Close()

	// Read the token from the token file
	var token []byte
	if token, err = ioutil.ReadFile(c.String("token-file")); err != nil {
		fmt.Printf("warning could not read %s: %s\n", c.String("token-file"), err)
	}

	// Create the Per-RPC Credentials
	creds := grpcauth.TokenCredentials{Token: string(token)}

	client := api.NewAuthenticatorClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Add the per-rpc credentials to the request not the dialer.
	var rep *api.LogoutReply
	if rep, err = client.Logout(ctx, &api.Empty{}, grpc.PerRPCCredentials(creds)); err != nil {
		return cli.Exit(err, 1)
	}
	fmt.Println(rep)
	return nil
}

func secure(c *cli.Context) (err error) {
	var cc *grpc.ClientConn
	if cc, err = grpc.Dial(c.String("endpoint"), grpc.WithInsecure()); err != nil {
		return cli.Exit(err, 1)
	}
	defer cc.Close()

	// Read the token from the token file
	var token []byte
	if token, err = ioutil.ReadFile(c.String("token-file")); err != nil {
		fmt.Printf("warning could not read %s: %s\n", c.String("token-file"), err)
	}

	// Create the Per-RPC Credentials
	creds := grpcauth.TokenCredentials{Token: string(token)}

	client := api.NewAuthenticatorClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Add the per-rpc credentials to the request not the dialer.
	var rep *api.SecureReply
	if rep, err = client.Secure(ctx, &api.Empty{}, grpc.PerRPCCredentials(creds)); err != nil {
		return cli.Exit(err, 1)
	}
	fmt.Println(rep)
	return nil
}
