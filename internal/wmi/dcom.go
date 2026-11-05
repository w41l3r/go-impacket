package wmi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-impacket/kit/internal/cred"
	"github.com/go-impacket/kit/internal/dcerpc"
	"github.com/go-impacket/kit/internal/transport"
	"github.com/go-impacket/kit/pkg/randname"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"golang.org/x/net/proxy"
)

type Executor struct {
	ep          *transport.Endpoint
	conn        *smb.Connection
	share       string
	noOutput    bool
	FallbackSCM bool
	host        string
	bundle      *cred.Bundle
	proxyDialer proxy.Dialer
}

func Connect(host string, port int, bundle *cred.Bundle, share string, noOutput bool) (*Executor, error) {
	ep, err := transport.Dial(host, port, bundle)
	if err != nil {
		return nil, err
	}
	pd, _ := transport.ProxyDialer(bundle.ProxyURL)
	return &Executor{
		ep:          ep,
		conn:        ep.Raw(),
		share:       share,
		noOutput:    noOutput,
		FallbackSCM: true,
		host:        host,
		bundle:      bundle,
		proxyDialer: pd,
	}, nil
}

// ConnectDCOM creates an Executor that skips the SMB leg and goes straight to
// DCOM/WMI on port 135. Use when SMB (port 445) is blocked but RPC is reachable.
func ConnectDCOM(host string, bundle *cred.Bundle) (*Executor, error) {
	pd, err := transport.ProxyDialer(bundle.ProxyURL)
	if err != nil {
		return nil, err
	}
	return &Executor{
		FallbackSCM: false,
		host:        host,
		bundle:      bundle,
		proxyDialer: pd,
	}, nil
}

func (x *Executor) Invoke(cmd string, timeout time.Duration) (string, int, error) {
	if x.FallbackSCM {
		return x.invokeViaSCM(cmd, timeout)
	}
	return x.invokeViaDCOM(cmd, timeout)
}

func (x *Executor) Close() {
	x.ep.Close()
}

func (x *Executor) invokeViaSCM(cmd string, timeout time.Duration) (string, int, error) {
	sc, err := dcerpc.AttachSCMR(x.conn)
	if err != nil {
		return "", 1, fmt.Errorf("SCM attach: %w", err)
	}
	defer sc.Close()

	outFile := "__wmi_" + randname.Alnum(8)
	svcName := randname.Alpha(8)
	batName := randname.Alpha(8) + ".bat"

	outputPath := fmt.Sprintf("\\\\%%COMPUTERNAME%%\\%s\\%s", x.share, outFile)
	shell := "%COMSPEC% /Q /c "
	batPath := "%SYSTEMROOT%\\" + batName

	wrapped := fmt.Sprintf(
		`%secho %s ^> %s 2^>^&1 > %s & %s%s & del %s`,
		shell, cmd, outputPath, batPath,
		shell, batPath,
		batPath,
	)

	if err := sc.IgniteAndErase(svcName, wrapped); err != nil {
		return "", 1, err
	}

	if x.noOutput {
		return "", 0, nil
	}

	deadline := time.Now().Add(timeout)
	var output []byte
	for time.Now().Before(deadline) {
		var buf []byte
		err = x.conn.RetrieveFile(x.share, outFile, 0, func(data []byte) (int, error) {
			buf = append(buf, data...)
			return len(data), nil
		})
		if err == nil {
			output = buf
			_ = x.conn.DeleteFile(x.share, outFile)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if time.Now().After(deadline) && len(output) == 0 {
		return "", 1, fmt.Errorf("timeout waiting for output file")
	}

	return string(output), 0, nil
}

// ─── DCOM/WMI native implementation ──────────────────────────────────────────
//
// Protocol flow:
//   1. TCP:135 → DCE-RPC BIND to EPM → ept_map → resolve dynamic DCOM port
//   2. TCP:<dcom_port> → DCE-RPC BIND with NTLM auth → IWbemLevel1Login
//   3. NTLMLogin("//./root/cimv2") → IWbemServices handle (IPID)
//   4. Win32_Process.Create via IWbemServices ExecMethod

const (
	dceTypRequest      = 0x00
	dceTypResponse     = 0x02
	dceTypBind         = 0x0b
	dceTypBindAck      = 0x0c
	dceTypBindNak      = 0x0d
	dceTypAuth3        = 0x10
	dceFlagFirst       = 0x01
	dceFlagLast        = 0x02
	dceAuthNTLM        = uint8(0x0a)
	dceAuthConnect     = uint8(0x02)
	dceAuthPktIntegrity = uint8(0x05)
	dceMaxFrag         = uint16(4280)
)

// UUIDs in MS-RPCE wire format (first 3 fields LE, last 10 bytes as-is).
var (
	uuidEPM          = msUUID("6BFFD098-A112-3610-9833-46C3F87E345A")
	uuidNDR          = msUUID("8A885D04-1CEB-11C9-9FE8-08002B104860")
	uuidWbemLogin    = msUUID("F309AD18-D86A-11D0-A075-00C04FB68820")
	uuidWbemServices = msUUID("9556DC99-828C-11CF-A37E-00AA003240C7")
	uuidIActivation  = msUUID("4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57")
)

// CLSID_WbemLevel1Login {8BC3F05E-D86B-11D0-A075-00C04FB68820} in LE wire format.
// Used in IActivation.RemoteActivation to activate the WMI service.
var clsidWbemLevel1Login = [16]byte{
	0x5E, 0xF0, 0xC3, 0x8B, 0x6B, 0xD8, 0xD0, 0x11,
	0xA0, 0x75, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20,
}

// msUUID converts a UUID string to the 16-byte MS-RPCE wire encoding.
// The first three hyphen-delimited fields are stored little-endian; the rest big-endian.
func msUUID(s string) [16]byte {
	clean := strings.ReplaceAll(s, "-", "")
	b, _ := hex.DecodeString(clean)
	var u [16]byte
	copy(u[:], b)
	// swap bytes for LE fields
	u[0], u[3] = u[3], u[0]
	u[1], u[2] = u[2], u[1]
	u[4], u[5] = u[5], u[4]
	u[6], u[7] = u[7], u[6]
	return u
}

type rpcSession struct {
	conn   net.Conn
	callID uint32
}

func openRPC(host string, port int, timeout time.Duration, d proxy.Dialer) (*rpcSession, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	var c net.Conn
	var err error
	if d != nil {
		c, err = d.Dial("tcp", addr)
	} else {
		c, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil, err
	}
	return &rpcSession{conn: c, callID: 1}, nil
}

func (s *rpcSession) Close() { s.conn.Close() }

func (s *rpcSession) nextID() uint32 {
	id := s.callID
	s.callID++
	return id
}

func (s *rpcSession) send(pkt []byte) error {
	_, err := s.conn.Write(pkt)
	return err
}

func (s *rpcSession) recv() ([]byte, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return nil, fmt.Errorf("DCE-RPC recv header: %w", err)
	}
	fragLen := int(binary.LittleEndian.Uint16(hdr[8:]))
	if fragLen < 16 {
		return nil, fmt.Errorf("DCE-RPC bad fragLen: %d", fragLen)
	}
	rest := make([]byte, fragLen-16)
	if _, err := io.ReadFull(s.conn, rest); err != nil {
		return nil, fmt.Errorf("DCE-RPC recv body: %w", err)
	}
	return append(hdr, rest...), nil
}

func (s *rpcSession) sendRecv(pkt []byte) ([]byte, error) {
	if err := s.send(pkt); err != nil {
		return nil, err
	}
	return s.recv()
}

func pktType(p []byte) byte {
	if len(p) < 3 {
		return 0xff
	}
	return p[2]
}

func authLen(p []byte) int {
	if len(p) < 12 {
		return 0
	}
	return int(binary.LittleEndian.Uint16(p[10:]))
}

// authValue returns the auth_value bytes from the verifier trailer (skips 8-byte header).
func authValue(p []byte) []byte {
	al := authLen(p)
	if al <= 8 || al > len(p) {
		return nil
	}
	return p[len(p)-al+8:]
}

// buildHdr writes a 16-byte DCE-RPC common header.
func buildHdr(pType, flags byte, fragLen, authL uint16, callID uint32) []byte {
	b := make([]byte, 16)
	b[0], b[1] = 5, 0
	b[2], b[3] = pType, flags
	b[4] = 0x10 // little-endian, ASCII chars, IEEE floats
	binary.LittleEndian.PutUint16(b[8:], fragLen)
	binary.LittleEndian.PutUint16(b[10:], authL)
	binary.LittleEndian.PutUint32(b[12:], callID)
	return b
}

// encodeSyntax encodes a p_syntax_id_t: uuid(16) + major(2) + minor(2).
func encodeSyntax(u [16]byte, major, minor uint16) []byte {
	b := make([]byte, 20)
	copy(b, u[:])
	binary.LittleEndian.PutUint16(b[16:], major)
	binary.LittleEndian.PutUint16(b[18:], minor)
	return b
}

func buildAuthTrailer(authType, authLevel byte, val []byte) []byte {
	return buildAuthTrailerPad(authType, authLevel, 0, val)
}

// buildAuthTrailerPad builds the 8-byte auth verifier header followed by val.
// padLen is auth_pad_length: how many padding bytes precede this trailer.
func buildAuthTrailerPad(authType, authLevel, padLen byte, val []byte) []byte {
	b := make([]byte, 8+len(val))
	b[0] = authType
	b[1] = authLevel
	b[2] = padLen // auth_pad_length
	// b[3] = auth_reserved = 0
	// b[4:8] = auth_context_id = 0
	copy(b[8:], val)
	return b
}

// buildBind creates a DCE-RPC BIND packet (with optional NTLM verifier).
//
// When NTLM is present the body must be padded to a 4-byte boundary before the
// auth trailer; auth_pad_length in the trailer reports how many bytes were added.
func buildBind(callID uint32, ctxID uint16, ifUUID [16]byte, ifMaj, ifMin uint16, ntlmNeg []byte, authLevel byte) []byte {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, dceMaxFrag)   // max_xmit_frag
	binary.Write(body, binary.LittleEndian, dceMaxFrag)   // max_recv_frag
	binary.Write(body, binary.LittleEndian, uint32(0))    // assoc_group_id
	binary.Write(body, binary.LittleEndian, uint16(1))    // n_context_items
	binary.Write(body, binary.LittleEndian, uint16(0))    // reserved
	binary.Write(body, binary.LittleEndian, ctxID)
	binary.Write(body, binary.LittleEndian, uint16(1))    // n_transfer_syn
	binary.Write(body, binary.LittleEndian, uint16(0))    // reserved
	body.Write(encodeSyntax(ifUUID, ifMaj, ifMin))
	body.Write(encodeSyntax(uuidNDR, 2, 0))

	var trailer []byte
	var authL uint16
	if len(ntlmNeg) > 0 {
		// Pad body to 4-byte alignment; auth_pad_length reports padding added.
		padLen := (4 - (body.Len() % 4)) % 4
		body.Write(make([]byte, padLen))
		trailer = buildAuthTrailerPad(dceAuthNTLM, authLevel, byte(padLen), ntlmNeg)
		// auth_length = length of auth_value ONLY (not the 8-byte verifier header).
		authL = uint16(len(ntlmNeg))
	}

	fragLen := uint16(16 + body.Len() + len(trailer))
	hdr := buildHdr(dceTypBind, dceFlagFirst|dceFlagLast, fragLen, authL, callID)

	out := new(bytes.Buffer)
	out.Write(hdr)
	out.Write(body.Bytes())
	if len(trailer) > 0 {
		out.Write(trailer)
	}
	return out.Bytes()
}

// buildAuth3 creates the AUTH3 packet (NTLM authenticate response to BIND_ACK challenge).
func buildAuth3(callID uint32, ntlmAuth []byte, authLevel byte) []byte {
	trailer := buildAuthTrailer(dceAuthNTLM, authLevel, ntlmAuth)
	// auth_length = length of auth_value ONLY (not the 8-byte verifier header).
	authL := uint16(len(ntlmAuth))
	fragLen := uint16(16 + 4 + len(trailer)) // hdr + 4 pad
	hdr := buildHdr(dceTypAuth3, dceFlagFirst|dceFlagLast, fragLen, authL, callID)
	out := new(bytes.Buffer)
	out.Write(hdr)
	binary.Write(out, binary.LittleEndian, uint32(0)) // padding
	out.Write(trailer)
	return out.Bytes()
}

// buildRequest creates a DCE-RPC REQUEST packet.
func buildRequest(callID uint32, ctxID, opnum uint16, stub []byte) []byte {
	fragLen := uint16(16 + 8 + len(stub))
	hdr := buildHdr(dceTypRequest, dceFlagFirst|dceFlagLast, fragLen, 0, callID)
	out := new(bytes.Buffer)
	out.Write(hdr)
	binary.Write(out, binary.LittleEndian, uint32(len(stub))) // alloc_hint
	binary.Write(out, binary.LittleEndian, ctxID)
	binary.Write(out, binary.LittleEndian, opnum)
	out.Write(stub)
	return out.Bytes()
}

// bindNTLM performs the 3-message NTLM handshake inside DCE-RPC:
// BIND (type1) → BIND_ACK (type2 challenge) → AUTH3 (type3 authenticate).
// Returns the ntlmssp.Client so the caller can use it for packet signing when
// authLevel=dceAuthPktIntegrity (5) is used.
func bindNTLM(s *rpcSession, ctxID uint16, ifUUID [16]byte, ifMaj, ifMin uint16, b *cred.Bundle, authLevel byte) (*ntlmssp.Client, error) {
	nc := &ntlmssp.Client{
		User:     b.Username,
		Domain:   b.Domain,
		Password: b.Password,
	}
	if b.IsPassTheHash() {
		nc.Hash = b.NTHash // already raw bytes from cred.FromHashes
	}

	neg, err := nc.Negotiate()
	if err != nil {
		return nil, fmt.Errorf("NTLM Negotiate: %w", err)
	}

	callID := s.nextID()
	pkt := buildBind(callID, ctxID, ifUUID, ifMaj, ifMin, neg, authLevel)
	resp, err := s.sendRecv(pkt)
	if err != nil {
		return nil, fmt.Errorf("BIND send/recv: %w", err)
	}
	switch pktType(resp) {
	case dceTypBindNak:
		return nil, fmt.Errorf("BIND_NAK — interface not supported on this port")
	case dceTypBindAck:
		// ok
	default:
		return nil, fmt.Errorf("unexpected DCE-RPC response to BIND: 0x%02x", pktType(resp))
	}

	challenge := authValue(resp)
	if len(challenge) == 0 {
		// Server accepted without challenge (null session)
		return nc, nil
	}

	auth, err := nc.Authenticate(challenge)
	if err != nil {
		return nil, fmt.Errorf("NTLM Authenticate: %w", err)
	}

	auth3 := buildAuth3(callID, auth, authLevel)
	// AUTH3 has no server response
	return nc, s.send(auth3)
}

// buildSignedRequest creates a DCE-RPC REQUEST packet with an NTLM signature
// verifier appended (required for auth_level=5 PKT_INTEGRITY connections).
//
// Per MS-RPCE §3.3.4.1.1, the signed data covers: PDU header + stub + padding
// + auth verifier header (8 bytes, auth_value zeroed). The 16-byte NTLM MAC
// is then placed in the auth_value field.
func buildSignedRequest(nc *ntlmssp.Client, callID uint32, ctxID, opnum uint16, stub []byte, seqNum uint32) ([]byte, uint32, error) {
	session := nc.Session()
	if session == nil {
		return nil, 0, fmt.Errorf("NTLM session not established (Authenticate not called)")
	}

	// Build request body (without signing)
	reqBody := new(bytes.Buffer)
	binary.Write(reqBody, binary.LittleEndian, uint32(len(stub))) // alloc_hint
	binary.Write(reqBody, binary.LittleEndian, ctxID)
	binary.Write(reqBody, binary.LittleEndian, opnum)
	reqBody.Write(stub)

	// Pad to 4-byte boundary before auth trailer
	padLen := byte((4 - (reqBody.Len() % 4)) % 4)
	reqBody.Write(make([]byte, padLen))

	// Auth verifier header (8 bytes) with zeroed 16-byte auth_value placeholder
	authHdr := buildAuthTrailerPad(dceAuthNTLM, dceAuthPktIntegrity, padLen, make([]byte, 16))

	// fragLen covers header(16) + body(with padding) + auth verifier(8 hdr + 16 sig).
	// auth_length = length of auth_value ONLY (not the 8-byte verifier header).
	fragLen := uint16(16 + reqBody.Len() + len(authHdr))
	authL := uint16(16) // length of NTLM signature (auth_value only)

	hdr := buildHdr(dceTypRequest, dceFlagFirst|dceFlagLast, fragLen, authL, callID)

	// Signed content = hdr + body(with padding) + auth verifier header (NOT auth_value)
	toSign := make([]byte, 0, 16+reqBody.Len()+8)
	toSign = append(toSign, hdr...)
	toSign = append(toSign, reqBody.Bytes()...)
	toSign = append(toSign, authHdr[:8]...) // only the 8-byte header, not the sig placeholder

	sig, newSeqNum := session.Sum(toSign, seqNum)

	// Final auth trailer with real signature
	realAuth := buildAuthTrailerPad(dceAuthNTLM, dceAuthPktIntegrity, padLen, sig)

	out := new(bytes.Buffer)
	out.Write(hdr)
	out.Write(reqBody.Bytes())
	out.Write(realAuth)

	return out.Bytes(), newSeqNum, nil
}

// resolveWMIPort uses IActivation.RemoteActivation on port 135 to discover the
// dynamic TCP port hosting IWbemLevel1Login.
//
// IWbemLevel1Login is NOT registered in the EPM — ept_map returns
// ept_s_not_registered. The correct approach is DCOM activation via
// IActivation (UUID: 4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57, opnum=0).
func resolveWMIPort(host string, bundle *cred.Bundle, d proxy.Dialer) (int, error) {
	s, err := openRPC(host, 135, 10*time.Second, d)
	if err != nil {
		return 0, fmt.Errorf("connect port 135: %w", err)
	}
	defer s.Close()

	// IActivation on port 135 requires PKT_INTEGRITY (auth_level=5) — level 2
	// returns BIND_NAK and level 2 returns rpc_s_access_denied on RemoteActivation.
	nc, err := bindNTLM(s, 0, uuidIActivation, 0, 0, bundle, dceAuthPktIntegrity)
	if err != nil {
		return 0, fmt.Errorf("BIND IActivation: %w", err)
	}

	// RemoteActivation (opnum 0) — must be signed at auth_level=5
	stub := buildRemoteActivationStub()
	reqPkt, _, err := buildSignedRequest(nc, s.nextID(), 0, 0, stub, 0)
	if err != nil {
		return 0, fmt.Errorf("build signed RemoteActivation: %w", err)
	}
	resp, err := s.sendRecv(reqPkt)
	if err != nil {
		return 0, fmt.Errorf("RemoteActivation RPC: %w", err)
	}
	if pktType(resp) != dceTypResponse {
		return 0, fmt.Errorf("RemoteActivation unexpected type 0x%02x", pktType(resp))
	}

	// Parse stub (skip DCE hdr(16) + response hdr(8) = 24 bytes)
	port, err := parseActivationPort(resp[24:])
	if err != nil {
		return 0, fmt.Errorf("parse RemoteActivation response: %w", err)
	}
	return port, nil
}

// buildRemoteActivationStub encodes the NDR parameters for
// IActivation::RemoteActivation(opnum=0):
//
//	ORPCthis, CLSID, pwszObjectName=NULL, pObjectStorage=NULL,
//	ClientImpLevel=2, Mode=0, Interfaces=1, pIIDs=[IWbemLevel1Login],
//	cRequestedProtseqs=1, aRequestedProtseqs=[7(ncacn_ip_tcp)]
//
// Stub layout captured from impacket (102 bytes total):
// [0:32]  ORPCthis   [32:48] CLSID   [48:52] NULL   [52:56] NULL
// [56:60] ImpLevel=2 [60:64] Mode=0  [64:68] nIf=1
// [68:72] pIIDs-ref  [72:76] max=1   [76:92] IID
// [92:94] nProto=1   [94:96] pad     [96:100] max=1  [100:102] 7
func buildRemoteActivationStub() []byte {
	b := new(bytes.Buffer)

	// ORPCthis: version 5.7, flags=1 (ORPCF_LOCAL), CID, extensions=NULL
	orpc := buildORPCTHIS()
	orpc[4] = 1 // flags = 1
	b.Write(orpc)

	// CLSID_WbemLevel1Login
	b.Write(clsidWbemLevel1Login[:])

	// pwszObjectName: NULL unique pointer
	binary.Write(b, binary.LittleEndian, uint32(0))

	// pObjectStorage: NULL unique pointer
	binary.Write(b, binary.LittleEndian, uint32(0))

	// ClientImpLevel: 2 (impersonate)
	binary.Write(b, binary.LittleEndian, uint32(2))

	// Mode: 0
	binary.Write(b, binary.LittleEndian, uint32(0))

	// Interfaces: 1
	binary.Write(b, binary.LittleEndian, uint32(1))

	// pIIDs: non-null referent + max_count + IWbemLevel1Login IID (inline)
	binary.Write(b, binary.LittleEndian, uint32(0x00007494)) // referent
	binary.Write(b, binary.LittleEndian, uint32(1))          // max_count
	b.Write(uuidWbemLogin[:])                                 // IID (16 bytes)

	// cRequestedProtseqs: 1
	binary.Write(b, binary.LittleEndian, uint16(1))

	// 2-byte alignment padding
	binary.Write(b, binary.LittleEndian, uint16(0))

	// aRequestedProtseqs: max_count=1, [7 = ncacn_ip_tcp]
	binary.Write(b, binary.LittleEndian, uint32(1))
	binary.Write(b, binary.LittleEndian, uint16(7))

	return b.Bytes()
}

// parseActivationPort extracts the TCP port from a RemoteActivation response stub.
//
// Wire layout of the stub (before IPID, MInterfacePointer, etc.):
//
//	ORPCthat (8) + OXID (8) + PDUALSTRINGARRAY referent (4)
//	+ max_count (4) + wNumEntries (2) + wSecurityOffset (2) + aStringArray
//
// aStringArray contains STRINGBINDING entries: wTowerId(2) + null-terminated
// UTF-16LE network address. Tower 7 = ncacn_ip_tcp; address = "host[port]".
func parseActivationPort(stub []byte) (int, error) {
	// offset 0..7:  ORPCthat (flags=4, extensions=4)
	// offset 8..15: OXID (uint64)
	// offset 16..19: PDUALSTRINGARRAY referent
	// offset 20..23: max_count (conformant dim of aStringArray)
	// offset 24..25: wNumEntries
	// offset 26..27: wSecurityOffset
	// offset 28+: aStringArray
	if len(stub) < 28 {
		return 0, fmt.Errorf("stub too short (%d bytes)", len(stub))
	}

	referent := binary.LittleEndian.Uint32(stub[16:20])
	if referent == 0 {
		return 0, fmt.Errorf("PDUALSTRINGARRAY is null")
	}

	wNumEntries := int(binary.LittleEndian.Uint16(stub[24:26]))
	if wNumEntries == 0 {
		return 0, fmt.Errorf("DUALSTRINGARRAY is empty")
	}

	// aStringArray: wNumEntries uint16 elements, each 2 bytes
	arrayEnd := 28 + wNumEntries*2
	if arrayEnd > len(stub) {
		arrayEnd = len(stub)
	}
	pos := 28

	for pos+2 <= arrayEnd {
		towerId := binary.LittleEndian.Uint16(stub[pos : pos+2])
		pos += 2
		if towerId == 0 {
			break // null STRINGBINDING = terminator
		}
		// Scan for null-terminated UTF-16LE address
		addrStart := pos
		for pos+1 < len(stub) {
			if stub[pos] == 0 && stub[pos+1] == 0 {
				break
			}
			pos += 2
		}
		addrEnd := pos
		pos += 2 // skip null terminator

		if towerId != 7 { // skip non-TCP bindings
			continue
		}

		// Decode UTF-16LE → string
		addrBytes := stub[addrStart:addrEnd]
		addrRunes := make([]uint16, len(addrBytes)/2)
		for i := range addrRunes {
			addrRunes[i] = binary.LittleEndian.Uint16(addrBytes[i*2:])
		}
		addr := string(utf16.Decode(addrRunes))

		// Extract port from "host[port]"
		if lb := strings.LastIndex(addr, "["); lb >= 0 {
			if rb := strings.LastIndex(addr, "]"); rb > lb {
				portStr := addr[lb+1 : rb]
				port, err := strconv.Atoi(portStr)
				if err == nil && port > 1024 && port < 65535 {
					return port, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no ncacn_ip_tcp binding in DUALSTRINGARRAY")
}

// buildEptMapStub builds the NDR stub data for ept_map(opnum=3).
// Asks for the TCP endpoint of IWbemLevel1Login.
func buildEptMapStub() []byte {
	tower := buildProtocolTower()

	b := new(bytes.Buffer)
	// obj: null unique pointer to UUID
	binary.Write(b, binary.LittleEndian, uint32(0))

	// map_tower: non-null unique pointer to twr_t
	binary.Write(b, binary.LittleEndian, uint32(0x00020000)) // referent ID

	// twr_t conformant array: max_count then tower_length then data
	// (conformant array max_count is hoisted before the struct in NDR)
	tlen := uint32(len(tower))
	binary.Write(b, binary.LittleEndian, tlen) // max_count (hoisted)
	binary.Write(b, binary.LittleEndian, tlen) // tower_length field
	b.Write(tower)
	// align to 4 bytes
	if pad := (4 - (int(tlen) % 4)) % 4; pad > 0 {
		b.Write(make([]byte, pad))
	}

	// entry_handle: null (4 bytes type + 16 bytes uuid = 20 bytes)
	b.Write(make([]byte, 20))

	// max_towers
	binary.Write(b, binary.LittleEndian, uint32(4))

	return b.Bytes()
}

// buildProtocolTower encodes a 5-floor protocol tower for IWbemLevel1Login over TCP/IP.
//
// MS-RPCE §2.1.2.3.3 defines the standard TCP/IP tower as:
//   Floor 0: UUID (0x0d) — target interface
//   Floor 1: UUID (0x0d) — NDR transfer syntax
//   Floor 2: 0x0b — connection-oriented RPC (no port data, rhs_length=0)
//   Floor 3: 0x07 — TCP transport (port, big-endian, rhs_length=2)
//   Floor 4: 0x09 — IP address (rhs_length=4)
func buildProtocolTower() []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, uint16(5)) // floor_count

	// Floor 0: IWbemLevel1Login UUID (protocol identifier 0x0d)
	// lhs_length = 1 (proto_id) + 16 (UUID) + 2 (major) = 19
	binary.Write(b, binary.LittleEndian, uint16(19))
	b.WriteByte(0x0d)
	b.Write(uuidWbemLogin[:])
	binary.Write(b, binary.LittleEndian, uint16(0)) // major version
	binary.Write(b, binary.LittleEndian, uint16(2)) // rhs_length
	binary.Write(b, binary.LittleEndian, uint16(0)) // minor version

	// Floor 1: NDR transfer syntax
	binary.Write(b, binary.LittleEndian, uint16(19))
	b.WriteByte(0x0d)
	b.Write(uuidNDR[:])
	binary.Write(b, binary.LittleEndian, uint16(2)) // major version
	binary.Write(b, binary.LittleEndian, uint16(2)) // rhs_length
	binary.Write(b, binary.LittleEndian, uint16(0)) // minor version

	// Floor 2: connection-oriented RPC (0x0b) — no port data
	binary.Write(b, binary.LittleEndian, uint16(1)) // lhs_length
	b.WriteByte(0x0b)
	binary.Write(b, binary.LittleEndian, uint16(0)) // rhs_length = 0

	// Floor 3: TCP transport (0x07), port = 0 when querying
	binary.Write(b, binary.LittleEndian, uint16(1)) // lhs_length
	b.WriteByte(0x07)
	binary.Write(b, binary.LittleEndian, uint16(2)) // rhs_length
	binary.Write(b, binary.BigEndian, uint16(0))    // port (big-endian)

	// Floor 4: IP address (0x09)
	binary.Write(b, binary.LittleEndian, uint16(1)) // lhs_length
	b.WriteByte(0x09)
	binary.Write(b, binary.LittleEndian, uint16(4)) // rhs_length
	b.Write([]byte{0, 0, 0, 0})

	return b.Bytes()
}

// scanForTCPPort scans the EPM response stub for a TCP floor and extracts the port.
func scanForTCPPort(stub []byte) int {
	// TCP floor pattern: lhs_len=0x01 0x00, proto=0x07, rhs_len=0x02 0x00, port(2 BE)
	for i := 0; i+6 < len(stub); i++ {
		if stub[i] == 0x01 && stub[i+1] == 0x00 && stub[i+2] == 0x07 &&
			stub[i+3] == 0x02 && stub[i+4] == 0x00 {
			port := int(binary.BigEndian.Uint16(stub[i+5:]))
			if port > 1024 && port < 65535 {
				return port
			}
		}
	}
	return 0
}

// ─── ORPC helpers ─────────────────────────────────────────────────────────────

// buildORPCTHIS returns the 32-byte ORPCTHIS header prepended to every DCOM method call.
//
//	COMVERSION(2+2) + flags(4) + reserved(4) + CID(16) + extensions_ptr(4) = 32 bytes
func buildORPCTHIS() []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint16(b[0:], 5) // MajorVersion
	binary.LittleEndian.PutUint16(b[2:], 7) // MinorVersion
	// flags=0, reserved=0 → zero
	// CID: random-looking but fixed for the session
	for i := 8; i < 24; i++ {
		b[i] = byte(i * 7) // deterministic non-zero fill
	}
	// extensions = NULL pointer (4 bytes, already zero)
	return b
}

// buildExecMethodStub encodes the NDR parameters for IWbemServices::ExecMethod
// (opnum 24) with strObjectPath="Win32_Process", strMethodName="Create",
// pInParams containing commandLine.
func buildExecMethodStub(commandLine string) []byte {
	buf := new(bytes.Buffer)

	// ORPCTHIS (32 bytes)
	buf.Write(buildORPCTHIS())

	// strObjectPath: conformant LPWSTR "Win32_Process"
	encodeWStr(buf, "Win32_Process")

	// strMethodName: conformant LPWSTR "Create"
	encodeWStr(buf, "Create")

	// lFlags: int32 = 0
	binary.Write(buf, binary.LittleEndian, int32(0))

	// pCtx: null unique pointer (IWbemContext*)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pInParams: MInterfacePointer (non-null unique pointer + data)
	mip := BuildWin32ProcessCreateInParams(commandLine)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // referent (non-null)
	buf.Write(mip)

	// ppOutParams: null
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ppCallResult: null
	binary.Write(buf, binary.LittleEndian, uint32(0))

	return buf.Bytes()
}

// wmiNTLMLogin calls IWbemLevel1Login::NTLMLogin (opnum 6) and returns the stub response.
func wmiNTLMLogin(s *rpcSession, ctxID uint16) ([]byte, error) {
	stub := buildNTLMLoginStub("//./root/cimv2")
	pkt := buildRequest(s.nextID(), ctxID, 6, stub)
	resp, err := s.sendRecv(pkt)
	if err != nil {
		return nil, fmt.Errorf("NTLMLogin RPC: %w", err)
	}
	if pktType(resp) != dceTypResponse {
		return nil, fmt.Errorf("NTLMLogin unexpected packet type: 0x%02x", pktType(resp))
	}
	// Strip DCE hdr(16) + response hdr(8) = 24 bytes
	if len(resp) < 24 {
		return nil, fmt.Errorf("NTLMLogin response too short")
	}
	return resp[24:], nil
}

// buildNTLMLoginStub encodes the NDR input for NTLMLogin.
// Signature: NTLMLogin(wszNetworkResource, wszPreferredLocale, lFlags, ppCtx**)
func buildNTLMLoginStub(netResource string) []byte {
	b := new(bytes.Buffer)

	// wszNetworkResource: unique ptr (non-null) + conformant wstring
	encodeWStr(b, netResource)

	// wszPreferredLocale: null unique ptr
	binary.Write(b, binary.LittleEndian, uint32(0))

	// lFlags: LONG = 0
	binary.Write(b, binary.LittleEndian, int32(0))

	// ppCtx: null unique ptr ([in,out] IWbemContext**)
	binary.Write(b, binary.LittleEndian, uint32(0))

	return b.Bytes()
}

// encodeWStr encodes an LPWSTR as NDR unique-pointer + conformant string.
func encodeWStr(b *bytes.Buffer, s string) {
	binary.Write(b, binary.LittleEndian, uint32(0x00020000)) // non-null referent

	r16 := utf16.Encode([]rune(s))
	r16 = append(r16, 0) // null terminator
	n := uint32(len(r16))

	binary.Write(b, binary.LittleEndian, n) // max_count
	binary.Write(b, binary.LittleEndian, uint32(0)) // offset
	binary.Write(b, binary.LittleEndian, n) // actual_count

	for _, w := range r16 {
		binary.Write(b, binary.LittleEndian, w)
	}
	// 4-byte align
	byteLen := int(n) * 2
	if pad := (4 - byteLen%4) % 4; pad > 0 {
		b.Write(make([]byte, pad))
	}
}

// extractIPID scans the NTLMLogin response stub for an OBJREF (MEOW signature)
// and returns the IPID of the IWbemServices interface pointer.
func extractIPID(stub []byte) ([16]byte, error) {
	var ipid [16]byte
	if len(stub) < 4 {
		return ipid, fmt.Errorf("NTLMLogin stub too short")
	}

	hresult := int32(binary.LittleEndian.Uint32(stub[len(stub)-4:]))
	if hresult != 0 {
		return ipid, fmt.Errorf("NTLMLogin HRESULT=0x%08X", uint32(hresult))
	}

	// OBJREF is identified by "MEOW" signature (0x4D 0x45 0x4F 0x57)
	meow := []byte{0x4D, 0x45, 0x4F, 0x57}
	idx := bytes.Index(stub, meow)
	if idx < 0 {
		return ipid, fmt.Errorf(
			"IWbemServices OBJREF not found in NTLMLogin response — " +
				"WMI call reached server; COM object marshaling parse not implemented")
	}
	// OBJREF_STANDARD layout after MEOW:
	// flags(4) + iid(16) + STDOBJREF: flags(4)+cRefs(4)+OXID(8)+OID(8)+IPID(16)
	off := idx + 4 + 4 + 16 + 4 + 4 + 8 + 8
	if off+16 > len(stub) {
		return ipid, fmt.Errorf("OBJREF too short for IPID at offset %d", off)
	}
	copy(ipid[:], stub[off:off+16])
	return ipid, nil
}

// invokeViaDCOM is the native DCOM/WMI execution path.
// Steps: EPM port lookup → DCE-RPC bind with NTLM → NTLMLogin → Win32_Process.Create
func (x *Executor) invokeViaDCOM(cmd string, timeout time.Duration) (string, int, error) {
	// Step 1: IActivation.RemoteActivation → dynamic WMI port
	wmiPort, err := resolveWMIPort(x.host, x.bundle, x.proxyDialer)
	if err != nil {
		return "", 1, fmt.Errorf("[step 1/4 EPM] %w", err)
	}

	// Step 2: DCE-RPC connect + NTLM bind to IWbemLevel1Login
	s, err := openRPC(x.host, wmiPort, 10*time.Second, x.proxyDialer)
	if err != nil {
		return "", 1, fmt.Errorf("[step 2/4 DCOM-connect port=%d] %w", wmiPort, err)
	}
	defer s.Close()

	if _, err := bindNTLM(s, 0, uuidWbemLogin, 0, 0, x.bundle, dceAuthConnect); err != nil {
		return "", 1, fmt.Errorf("[step 2/4 NTLM-bind IWbemLevel1Login] %w", err)
	}

	// Step 3: NTLMLogin → IWbemServices IPID
	loginStub, err := wmiNTLMLogin(s, 0)
	if err != nil {
		return "", 1, fmt.Errorf("[step 3/4 NTLMLogin] %w", err)
	}

	ipid, err := extractIPID(loginStub)
	if err != nil {
		return "", 1, fmt.Errorf("[step 3/4 OBJREF-parse] %w", err)
	}

	// Step 4: Bind IWbemServices (ctxID=1) on the same connection, then call
	// ExecMethod("Win32_Process", "Create", pInParams) with ORPC headers.
	_ = ipid

	bindPkt := buildBind(s.nextID(), 1, uuidWbemServices, 0, 0, nil, dceAuthConnect)
	bindResp, err := s.sendRecv(bindPkt)
	if err != nil {
		return "", 1, fmt.Errorf("[step 4/4 IWbemServices-bind] %w", err)
	}
	if pktType(bindResp) != dceTypBindAck {
		return "", 1, fmt.Errorf("[step 4/4 IWbemServices-bind] unexpected response type 0x%02x", pktType(bindResp))
	}

	execStub := buildExecMethodStub(cmd)
	reqPkt := buildRequest(s.nextID(), 1, 24, execStub) // opnum 24 = ExecMethod
	execResp, err := s.sendRecv(reqPkt)
	if err != nil {
		return "", 1, fmt.Errorf("[step 4/4 ExecMethod] %w", err)
	}
	if pktType(execResp) != dceTypResponse {
		return "", 1, fmt.Errorf("[step 4/4 ExecMethod] unexpected packet type 0x%02x", pktType(execResp))
	}

	// Check HRESULT in last 4 bytes of stub
	if len(execResp) < 28 {
		return "", 1, fmt.Errorf("[step 4/4 ExecMethod] response too short")
	}
	hresult := binary.LittleEndian.Uint32(execResp[len(execResp)-4:])
	if hresult != 0 {
		return "", 1, fmt.Errorf("[step 4/4 ExecMethod] HRESULT=0x%08X", hresult)
	}
	return "", 0, nil
}
