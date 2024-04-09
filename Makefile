keygen: keygen.go go.mod go.sum
	go build -ldflags="-s -w" -trimpath -o $@

.PHONY: short
short: keygen
	./keygen 10s

.PHONY: long
long: keygen
	./keygen 10m
