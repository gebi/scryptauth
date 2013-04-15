all:
	go test

format:
	gofmt -s -w=true *.go
