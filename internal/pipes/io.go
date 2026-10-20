package pipes

import (
	"fmt"

	"github.com/jfjallid/go-smb/smb"
)

type NamedPipe struct {
	f    *smb.File
	conn *smb.Connection
}

func Open(conn *smb.Connection, pipePath string) (*NamedPipe, error) {
	if err := conn.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$ connect: %w", err)
	}

	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskGenericRead | smb.FAccMaskGenericWrite | smb.FAccMaskSynchronize
	opts.ShareAccess = smb.FileShareRead | smb.FileShareWrite
	opts.CreateDisp = smb.FileOpen

	f, err := conn.OpenFileExt("IPC$", pipePath, opts)
	if err != nil {
		return nil, fmt.Errorf("open pipe %q: %w", pipePath, err)
	}

	return &NamedPipe{f: f, conn: conn}, nil
}

func (p *NamedPipe) Write(data []byte) (int, error) {
	n, err := p.f.WriteFile(data, 0)
	if err != nil {
		return n, fmt.Errorf("pipe write: %w", err)
	}
	return n, nil
}

func (p *NamedPipe) Read(buf []byte) (int, error) {
	n, err := p.f.ReadFile(buf, 0)
	if err != nil {
		return n, fmt.Errorf("pipe read: %w", err)
	}
	return n, nil
}

func (p *NamedPipe) Close() {
	if p.f != nil {
		p.f.CloseFile()
	}
}
