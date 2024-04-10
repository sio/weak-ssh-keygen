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

	temp, err = os.MkdirTemp(os.Getenv("TEMP"), "ssh-keygen-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temporary directory: %v\n", err)
		rc = 103
		return
	}
	defer func() { _ = os.RemoveAll(temp) }()

	tests := []struct {
		name   string
		keygen func() (sshkey, error)
		limit  time.Duration
	}{
		{name: "ssh-keygen", keygen: osSshKeygen, limit: runtime * 9 / 10},
		{name: "stdlib", keygen: goSshKeygen, limit: runtime * 1 / 10},
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

func test(ctx context.Context, keygen func() (sshkey, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var errors = make(chan error)
	var goroutines = runtime.NumCPU()
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

// Temporary directory. Preferably on tmpfs or other fast storage
var temp string

// OS provided ssh-keygen tool
//
// ssh-keygen -t ed25519 -C "your_email@example.com"
func osSshKeygen() (key sshkey, err error) {
	var suf [2]byte
	_, _ = rand.Read(suf[:])
	filename := filepath.Join(temp, fmt.Sprintf("key-%x-%x-%x", len(seen), time.Now().UnixNano(), suf))
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-P", "", "-C", "your_email@example.com", "-f", filename)
	err = cmd.Run()
	if err != nil {
		return key, fmt.Errorf("generating key: %w", err)
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		return key, fmt.Errorf("reading generated key: %w", err)
	}
	go func() {
		_ = os.RemoveAll(filename)
		_ = os.RemoveAll(filename + ".pub")
	}()
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
func goSshKeygen() (key sshkey, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return key, fmt.Errorf("generating key: %w", err)
	}
	copy(key[:], priv[:])
	return key, nil
}
