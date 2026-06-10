package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:req REQ-CLI-SIGN001
func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa sign [flags] <file>\n\n")
		fmt.Fprintf(stderr, "Sign or verify a file using HMAC-SHA256.\n\n")
		fmt.Fprintf(stderr, "  gofusa sign --key keyfile artifact.zip           # creates artifact.zip.sig\n")
		fmt.Fprintf(stderr, "  gofusa sign --verify --key keyfile artifact.zip  # verifies artifact.zip.sig\n")
		fmt.Fprintf(stderr, "  gofusa sign --keygen keyfile                     # generate a new key\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		keyFile = fs.String("key", "", "path to HMAC key file (32-byte hex)")
		verify  = fs.Bool("verify", false, "verify an existing signature instead of creating one")
		keygen  = fs.String("keygen", "", "generate a new random key and write to this path")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	if *keygen != "" {
		return signKeygen(*keygen, stdout, stderr)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return fusa.ExitRuntime
	}
	target := fs.Arg(0)

	if *keyFile == "" {
		fmt.Fprintf(stderr, "gofusa sign: --key is required\n")
		return fusa.ExitUsage
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sign: load key: %v\n", err)
		return fusa.ExitRuntime
	}

	if *verify {
		return signVerify(target, key, stdout, stderr)
	}
	return signCreate(target, key, stdout, stderr)
}

func signKeygen(path string, stdout, stderr io.Writer) int {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(stderr, "gofusa sign: generate key: %v\n", err)
		return fusa.ExitRuntime
	}
	encoded := hex.EncodeToString(key) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		fmt.Fprintf(stderr, "gofusa sign: write key: %v\n", err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "Key written to %s (keep this secret)\n", path)
	return fusa.ExitOK
}

func signCreate(target string, key []byte, stdout, stderr io.Writer) int {
	sig, err := hmacFile(target, key)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sign: %v\n", err)
		return fusa.ExitRuntime
	}
	sigPath := target + ".sig"
	if err := os.WriteFile(sigPath, []byte(hex.EncodeToString(sig)+"\n"), 0o640); err != nil {
		fmt.Fprintf(stderr, "gofusa sign: write signature: %v\n", err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "Signature written to %s\n", sigPath)
	return fusa.ExitOK
}

func signVerify(target string, key []byte, stdout, stderr io.Writer) int {
	sigPath := target + ".sig"
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sign: read signature: %v\n", err)
		return fusa.ExitRuntime
	}
	want, err := hex.DecodeString(string(sigData[:len(sigData)-1]))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sign: decode signature: %v\n", err)
		return fusa.ExitRuntime
	}
	got, err := hmacFile(target, key)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sign: %v\n", err)
		return fusa.ExitRuntime
	}
	if !hmac.Equal(got, want) {
		fmt.Fprintf(stderr, "gofusa sign: signature INVALID for %s\n", target)
		return fusa.ExitUsage
	}
	fmt.Fprintf(stdout, "Signature OK for %s\n", target)
	return fusa.ExitOK
}

func hmacFile(path string, key []byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := hmac.New(sha256.New, key)
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hash %s: %w", path, err)
	}
	return h.Sum(nil), nil
}

func loadKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Strip trailing newline/whitespace.
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	key, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode key hex: %w", err)
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("key too short: %d bytes (minimum 16)", len(key))
	}
	return key, nil
}
