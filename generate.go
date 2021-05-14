package grpcauth

//go:generate protoc -I=./proto --go_out=. --go_opt=module=github.com/rotationalio/grpc-token-auth --go-grpc_out=. --go-grpc_opt=module=github.com/rotationalio/grpc-token-auth api.proto
