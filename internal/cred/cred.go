package cred

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type Bundle struct {
	Username    string
	Password    string
	Domain      string
	LMHash      []byte
	NTHash      []byte
	AESKey      string
	UseKerberos bool
	KDCHost     string
}

func (b *Bundle) IsPassTheHash() bool {
	return len(b.NTHash) > 0
}

func (b *Bundle) HasCreds() bool {
	return b.Username != "" && (b.Password != "" || b.IsPassTheHash() || b.UseKerberos)
}

// ParseTarget parses [[domain/]user[:pass]@]host
func ParseTarget(s string) (domain, user, pass, host string, err error) {
	atIdx := strings.LastIndex(s, "@")
	if atIdx < 0 {
		host = s
		return
	}
	host = s[atIdx+1:]
	creds := s[:atIdx]

	slashIdx := strings.Index(creds, "/")
	if slashIdx >= 0 {
		domain = creds[:slashIdx]
		creds = creds[slashIdx+1:]
	}

	colonIdx := strings.Index(creds, ":")
	if colonIdx >= 0 {
		user = creds[:colonIdx]
		pass = creds[colonIdx+1:]
	} else {
		user = creds
	}

	if host == "" {
		err = fmt.Errorf("missing host in target string")
	}
	return
}

// FromHashes splits "LMHASH:NTHASH" into separate byte slices.
// Either side may be empty or "aad3b435b51404eeaad3b435b51404ee" (empty LM).
func FromHashes(combined string) (lm, nt []byte, err error) {
	parts := strings.SplitN(combined, ":", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("hashes must be in LMHASH:NTHASH format")
		return
	}
	if parts[0] != "" && parts[0] != "aad3b435b51404eeaad3b435b51404ee" {
		lm, err = hex.DecodeString(parts[0])
		if err != nil {
			err = fmt.Errorf("invalid LM hash: %w", err)
			return
		}
	}
	if parts[1] != "" {
		nt, err = hex.DecodeString(parts[1])
		if err != nil {
			err = fmt.Errorf("invalid NT hash: %w", err)
			return
		}
	}
	return
}
