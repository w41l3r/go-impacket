package dcerpc

import (
	"fmt"
	"math"
	"time"

	"github.com/jfjallid/go-smb/smb"
	libdcerpc "github.com/jfjallid/go-smb/smb/dcerpc"
)

type ServiceController struct {
	bind *libdcerpc.ServiceBind
	conn *smb.Connection
	pipe *smb.File
}

func AttachSCMR(conn *smb.Connection) (*ServiceController, error) {
	if err := conn.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$ tree connect: %w", err)
	}

	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskGenericRead | smb.FAccMaskGenericWrite
	opts.ShareAccess = smb.FileShareRead | smb.FileShareWrite
	opts.CreateDisp = smb.FileOpen

	pipe, err := conn.OpenFileExt("IPC$", libdcerpc.MSRPCSvcCtlPipe, opts)
	if err != nil {
		return nil, fmt.Errorf("open svcctl pipe: %w", err)
	}

	bind, err := libdcerpc.Bind(pipe,
		libdcerpc.MSRPCUuidSvcCtl,
		libdcerpc.MSRPCSvcCtlMajorVersion,
		libdcerpc.MSRPCSvcCtlMinorVersion,
		NdrTransferSyntax,
	)
	if err != nil {
		pipe.CloseFile()
		return nil, fmt.Errorf("bind SCMR: %w", err)
	}

	return &ServiceController{bind: bind, conn: conn, pipe: pipe}, nil
}

func (sc *ServiceController) Close() {
	if sc.pipe != nil {
		sc.pipe.CloseFile()
	}
	sc.conn.TreeDisconnect("IPC$")
}

func (sc *ServiceController) Ignite(name, binPath string) error {
	err := sc.bind.CreateService(
		name,
		libdcerpc.ServiceWin32OwnProcess,
		libdcerpc.ServiceDemandStart,
		libdcerpc.ServiceErrorNormal,
		binPath,
		"", "", name,
		false,
	)
	if err != nil {
		return fmt.Errorf("create service %q: %w", name, err)
	}

	if err := sc.bind.StartService(name, nil); err != nil {
		_ = sc.bind.DeleteService(name)
		return fmt.Errorf("start service %q: %w", name, err)
	}

	return nil
}

func (sc *ServiceController) Erase(name string) error {
	_ = sc.bind.ControlService(name, libdcerpc.ServiceControlStop)
	return sc.bind.DeleteService(name)
}

// IgniteAndErase creates, starts, and immediately deletes a transient service.
// This is the core pattern used by scorch: fire-and-forget with automatic cleanup.
func (sc *ServiceController) IgniteAndErase(name, binPath string) error {
	if err := sc.bind.CreateService(
		name,
		libdcerpc.ServiceWin32OwnProcess,
		libdcerpc.ServiceDemandStart,
		libdcerpc.ServiceErrorNormal,
		binPath,
		"", "", name,
		false,
	); err != nil {
		return fmt.Errorf("create service: %w", err)
	}

	startErr := sc.bind.StartService(name, nil)
	_ = sc.bind.DeleteService(name)
	if startErr != nil {
		return fmt.Errorf("start service: %w", startErr)
	}
	return nil
}

// WaitReady retries AttachSCMR with exponential backoff — useful after a fresh
// service manager restart.
func WaitReady(conn *smb.Connection, maxWait time.Duration) (*ServiceController, error) {
	deadline := time.Now().Add(maxWait)
	delay := 500 * time.Millisecond

	for {
		sc, err := AttachSCMR(conn)
		if err == nil {
			return sc, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("SCMR not ready after %v: %w", maxWait, err)
		}
		time.Sleep(delay)
		delay = time.Duration(math.Min(float64(delay*2), float64(8*time.Second)))
	}
}
