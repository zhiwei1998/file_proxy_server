
go mod init flie-proxy-server
go mod tidy

CGO_ENABLED=0 go build -ldflags="-s -w" -o file-proxy-serve
