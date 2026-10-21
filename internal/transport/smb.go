package transport

import (
	"fmt"
	"net/url"
	"time"

	"github.com/go-impacket/kit/internal/cred"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"golang.org/x/net/proxy"
)

type Endpoint struct {
	conn *smb.Connection
}

// ProxyDialer builds a proxy.Dialer from a URL string (socks5://host:port).
// Returns nil when proxyURL is empty, which disables proxying.
func ProxyDialer(proxyURL string) (proxy.Dialer, error) {
	if proxyURL == "" {
		return nil, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("build proxy dialer: %w", err)
	}
	return d, nil
}

func Dial(host string, port int, bundle *cred.Bundle) (*Endpoint, error) {
	initiator, err := buildInitiator(bundle)
	if err != nil {
		return nil, err
	}

	opts := smb.Options{
		Host:        host,
		Port:        port,
		Initiator:   initiator,
		DialTimeout: 10 * time.Second,
	}

	if bundle.ProxyURL != "" {
		d, err := ProxyDialer(bundle.ProxyURL)
		if err != nil {
			return nil, err
		}
		opts.ProxyDialer = d
	}

	conn, err := smb.NewConnection(opts)
	if err != nil {
		return nil, fmt.Errorf("SMB connect to %s:%d: %w", host, port, err)
	}

	if err = conn.NegotiateProtocol(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("negotiate: %w", err)
	}

	if err = conn.SessionSetup(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("session setup: %w", err)
	}

	return &Endpoint{conn: conn}, nil
}

func (e *Endpoint) Raw() *smb.Connection {
	return e.conn
}

func (e *Endpoint) Close() {
	if e.conn != nil {
		e.conn.Logoff()
		e.conn.Close()
	}
}

func buildInitiator(b *cred.Bundle) (initiator *spnego.NTLMInitiator, err error) {
	initiator = &spnego.NTLMInitiator{
		User:   b.Username,
		Domain: b.Domain,
	}

	switch {
	case b.IsPassTheHash():
		initiator.Hash = b.NTHash
	case b.Password != "":
		initiator.Password = b.Password
	default:
		initiator.NullSession = true
	}

	return initiator, nil
}
