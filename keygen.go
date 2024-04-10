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
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
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
		fmt.Fprintf(os.Stderr, "bad argument value: %v\n", err)
		rc = 102
		return
	}

	tests := []struct {
		name   string
		keygen func(path string) (sshkey, error)
		limit  time.Duration
	}{
		{name: "ssh-keygen", keygen: osSshKeygen, limit: runtime * 2 / 3},
		{name: "stdlib", keygen: goSshKeygen, limit: runtime * 1 / 3},
	}
	for _, t := range tests {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(t.limit))
		err = test(ctx, t.keygen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", t.name, err)
			rc = 1
		}
		fmt.Printf("%20s: %d duplicates out of %d keys\n", t.name, len(dups), len(seen))
		cancel()
	}
	if len(dups) > 0 {
		rc = 2
		fmt.Println("DUPLICATES")
		for _, d := range dups {
			fmt.Println(d)
		}
	}
}

func test(ctx context.Context, keygen func(path string) (sshkey, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	temp, err := os.MkdirTemp(os.Getenv("TEMP"), "ssh-keygen-*")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(temp) }()

	var errors = make(chan error)
	var goroutines = runtime.NumCPU() + 3
	for g := 0; g < goroutines; g++ {
		fifo := filepath.Join(temp, fmt.Sprintf("key-%03d", g))
		err = syscall.Mkfifo(fifo, 0600)
		if err != nil {
			return fmt.Errorf("mkfifo: %w", err)
		}
		err = os.Symlink("/dev/null", fifo+".pub")
		if err != nil {
			return fmt.Errorf("symlink: %w", err)
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				key, err := keygen(fifo)
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
//
// ssh-keygen -t ed25519 -C "your_email@example.com"
func osSshKeygen(path string) (key sshkey, err error) {
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-P", "", "-C", "your_email@example.com", "-f", path)
	cmd.Stdin = yes{} // ssh-keygen asks before overwriting existing key file
	err = cmd.Start()
	if err != nil {
		return key, fmt.Errorf("start ssh-keygen: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return key, fmt.Errorf("reading generated key: %w", err)
	}
	err = cmd.Wait()
	if err != nil {
		return key, fmt.Errorf("generating key: %w", err)
	}
	private, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return key, fmt.Errorf("invalid generated key: %w", err)
	}
	edkey, ok := private.(*ed25519.PrivateKey)
	if !ok {
		return key, fmt.Errorf("not an ed25519 key: %T", private)
	}
	copy(key[:], (*edkey)[:])
	return key, nil
}

// Generate ssh keys with Go standard library
func goSshKeygen(path string) (key sshkey, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return key, fmt.Errorf("generating key: %w", err)
	}
	copy(key[:], priv[:])
	return key, nil
}

type yes struct{}

func (y yes) Read(p []byte) (n int, err error) {
	var YES = [...]byte{'y', '\n'}
	n = copy(p, YES[:])
	if n != 2 {
		return n, fmt.Errorf("incomplete yes")
	}
	return n, nil
}
