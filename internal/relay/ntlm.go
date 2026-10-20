package relay

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"
)

// Session holds state for one in-flight NTLM relay exchange.
type Session struct {
	ID          string
	Target      *url.URL
	Protocol    string
	Username    string
	Domain      string
	AdminStatus bool
	Opened      time.Time

	// Raw NTLM blobs forwarded between victim and target.
	negotiateMsg    []byte
	challengeMsg    []byte
	authenticateMsg []byte

	// SMB2 session tracking for the relay state machine.
	victimSessionID uint64
	targetSessionID uint64
	targetConn      net.Conn
}

// Vault holds all active relay sessions.
type Vault struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewVault() *Vault {
	return &Vault{sessions: make(map[string]*Session)}
}

func (v *Vault) Add(s *Session) {
	v.mu.Lock()
	v.sessions[s.ID] = s
	v.mu.Unlock()
}

func (v *Vault) Remove(id string) {
	v.mu.Lock()
	delete(v.sessions, id)
	v.mu.Unlock()
}

func (v *Vault) List() []*Session {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*Session, 0, len(v.sessions))
	for _, s := range v.sessions {
		out = append(out, s)
	}
	return out
}

// ParseNTLMMessageType reads the message type field from an NTLM blob.
// Type 1 = Negotiate, Type 2 = Challenge, Type 3 = Authenticate.
func ParseNTLMMessageType(blob []byte) (uint32, error) {
	if len(blob) < 12 {
		return 0, fmt.Errorf("NTLM blob too short")
	}
	sig := string(blob[:8])
	if sig != "NTLMSSP\x00" {
		return 0, fmt.Errorf("not an NTLM message")
	}
	return binary.LittleEndian.Uint32(blob[8:12]), nil
}

// ExtractNTLMCreds extracts username and domain from a Type 3 (Authenticate) message.
func ExtractNTLMCreds(blob []byte) (user, domain string) {
	if len(blob) < 72 {
		return
	}
	domainLen := int(binary.LittleEndian.Uint16(blob[28:30]))
	domainOff := int(binary.LittleEndian.Uint32(blob[32:36]))
	userLen := int(binary.LittleEndian.Uint16(blob[36:38]))
	userOff := int(binary.LittleEndian.Uint32(blob[40:44]))

	if domainOff+domainLen <= len(blob) && domainLen > 0 {
		domain = decodeUTF16LE(blob[domainOff : domainOff+domainLen])
	}
	if userOff+userLen <= len(blob) && userLen > 0 {
		user = decodeUTF16LE(blob[userOff : userOff+userLen])
	}
	return
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	return string(runes)
}
