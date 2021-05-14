# gRPC Token Authentication

**Code for gRPC token authentication blog posts**

## Quick Start

Open two terminal windows, in the first one, run the server:

    $ go run ./cmd/svc serve

In the second one, run client commands. First attempt to get the secure message without logging in as follows:

    $ go run ./cmd/svc secure

You should see an error message! Now login:

    $ go run ./cmd/svc login -u secretagent -p supersecret

This will write a file called "token.txt" to your current working directory; you should now be able to get the secure message:

    $ go run ./cmd/svc secure

If you wait 10 minutes the token will expire and you'll automatically be logged out; however you can also use the logout command directly:

    $ go run ./cmd/svc logout

Note this will not delete the "token.txt" file; go ahead and try to get the secure message again:

    $ go run ./cmd/svc secure