all:
	go test

format:
	gofmt -s -w=true *.go

bench:
	go test -run=Scrypt -bench=.
