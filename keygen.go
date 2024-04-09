// Generate ssh keys in a loop and check their uniqueness.
//
// Guard against a repeat of DSA-1571-1
// <https://security-tracker.debian.org/tracker/DSA-1571-1>
//
// Since author uses only ed25519 other key algorithms are not tested.
//
// Copyright 2024 Vitaly Potyarkin
// Licensed under Apache License, Version 2.0

package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

func main() {
	var rc int
	defer func(rc *int) { os.Exit(*rc) }(&rc)

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s 10m\n", os.Args[0])
		rc = 101
		return
	}

	runtime, err := time.ParseDuration(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		rc = 102
		return
	}

	tests := []struct {
		keygen func() (sshkey, error)
		limit  time.Duration
	}{
		{keygen: osSshKeygen, limit: runtime * 2 / 3},
		{keygen: goSshKeygen, limit: runtime * 1 / 3},
	}
	for _, t := range tests {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(t.limit))
		err = test(ctx, t.keygen)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
		}
		fmt.Printf("%d duplicates out of %d generated keys\n", len(dups), len(seen))
		cancel()
	}
}

func test(ctx context.Context, keygen func() (sshkey, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var errors = make(chan error)
	var goroutines = runtime.NumCPU() + 3
	for g := 0; g < goroutines; g++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				key, err := keygen()
				if err != nil {
					select {
					case errors <- err:
					default:
					}
					return
				}
				seenMu.Lock()
				_, exist := seen[key]
				if exist {
					dups = append(dups, key)
				}
				seen[key] = struct{}{}
				seenMu.Unlock()
			}
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errors:
		return err
	}
}

// Unique key identifier.
//
// For ed25519 the cheapest identifier is the key seed (first 32 bytes of private key).
type sshkey [ed25519.SeedSize]byte

func (k sshkey) String() string {
	return fmt.Sprintf("[ed25519 seed=%#x]", k)
}

// Keep track of which keys we have already seen
var (
	seen   = make(map[sshkey]struct{})
	seenMu sync.Mutex
	dups   = make([]sshkey, 0)
)

// OS provided ssh-keygen tool
func osSshKeygen() (sshkey, error) {
	return sshkey{}, fmt.Errorf("OS ssh-keygen not implemented")
}

// Generate ssh keys with golang x/crypto
func goSshKeygen() (sshkey, error) {
	return sshkey{}, fmt.Errorf("Golang ssh keygen not implemented")
}
