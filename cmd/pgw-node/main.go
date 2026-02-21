// cmd/pgw-node/main.go — pgw-node sync daemon entry point.
// Runs on remote VPS nodes to sync assignments and report heartbeat to master.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Chinsusu/pgw-node/internal/config"
	"github.com/Chinsusu/pgw-node/internal/keypair"
	"github.com/Chinsusu/pgw-node/internal/sync"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			handleInit()
			return
		case "pubkey":
			handlePubkey()
			return
		case "version":
			fmt.Println("pgw-node", version)
			return
		}
	}

	flag.Parse()
	cfg := config.Load()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	kp, err := keypair.Load(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading keypair from %s: %v\n", cfg.KeyPath, err)
		fmt.Fprintf(os.Stderr, "Run 'pgw-node init' to generate a new keypair.\n")
		os.Exit(1)
	}

	fmt.Printf("pgw-node %s starting\n", version)
	fmt.Printf("  Server: %s\n", cfg.ServerURL)
	fmt.Printf("  Node ID: %s\n", cfg.NodeID)
	fmt.Printf("  Poll interval: %s\n", cfg.PollInterval)

	syncer := sync.New(cfg, kp, version)
	syncer.Run(ctx)

	fmt.Println("pgw-node stopped.")
}

func handleInit() {
	cfg := config.Load()
	kp, err := keypair.Generate(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated Ed25519 keypair at: %s\n", cfg.KeyPath)
	fmt.Printf("Public key (hex): %s\n", kp.PublicKeyHex())
	fmt.Printf("\nRegister this public key with the master server:\n")
	fmt.Printf("  PUT /v1/nodes/{id} with {\"public_key\": \"%s\"}\n", kp.PublicKeyHex())
}

func handlePubkey() {
	cfg := config.Load()
	kp, err := keypair.Load(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No keypair found at %s. Run 'pgw-node init' first.\n", cfg.KeyPath)
		os.Exit(1)
	}
	fmt.Print(kp.PublicKeyHex())
}
