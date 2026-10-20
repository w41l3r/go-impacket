package wmi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-impacket/kit/internal/cred"
	"github.com/go-impacket/kit/internal/dcerpc"
	"github.com/go-impacket/kit/internal/transport"
	"github.com/go-impacket/kit/pkg/randname"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
)

type Executor struct {
	ep          *transport.Endpoint
	conn        *smb.Connection
	share       string
	noOutput    bool
	FallbackSCM bool
	host        string
	bundle      *cred.Bundle
}

func Connect(host string, port int, bundle *cred.Bundle, share string, noOutput bool) (*Executor, error) {
	ep, err := transport.Dial(host, port, bundle)
	if err != nil {
		return nil, err
	}
	return &Executor{
		ep:          ep,
		conn:        ep.Raw(),
		share:       share,
		noOutput:    noOutput,
		FallbackSCM: true,
		host:        host,
		bundle:      bundle,
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
	dceMaxFrag         = uint16(4280)
)

// UUIDs in MS-RPCE wire format (first 3 fields LE, last 10 bytes as-is).
var (
	uuidEPM          = msUUID("6BFFD098-A112-3610-9833-46C3F87E345A")
	uuidNDR          = msUUID("8A885D04-1CEB-11C9-9FE8-08002B104860")
	uuidWbemLogin    = msUUID("F309AD18-D86A-11D0-A075-00C04FB68820")
	uuidWbemServices = msUUID("9556DC99-828C-11CF-A37E-00AA003240C7")
)

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

func openRPC(host string, port int, timeout time.Duration) (*rpcSession, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
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
	b := make([]byte, 8+len(val))
	b[0] = authType
	b[1] = authLevel
	copy(b[8:], val)
	return b
}

// buildBind creates a DCE-RPC BIND packet (with optional NTLM verifier).
func buildBind(callID uint32, ctxID uint16, ifUUID [16]byte, ifMaj, ifMin uint16, ntlmNeg []byte) []byte {
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
		trailer = buildAuthTrailer(dceAuthNTLM, dceAuthConnect, ntlmNeg)
		authL = uint16(len(trailer))
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
func buildAuth3(callID uint32, ntlmAuth []byte) []byte {
	trailer := buildAuthTrailer(dceAuthNTLM, dceAuthConnect, ntlmAuth)
	authL := uint16(len(trailer))
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
func bindNTLM(s *rpcSession, ctxID uint16, ifUUID [16]byte, ifMaj, ifMin uint16, b *cred.Bundle) error {
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
		return fmt.Errorf("NTLM Negotiate: %w", err)
	}

	callID := s.nextID()
	pkt := buildBind(callID, ctxID, ifUUID, ifMaj, ifMin, neg)
	resp, err := s.sendRecv(pkt)
	if err != nil {
		return fmt.Errorf("BIND send/recv: %w", err)
	}
	switch pktType(resp) {
	case dceTypBindNak:
		return fmt.Errorf("BIND_NAK — interface not supported on this port")
	case dceTypBindAck:
		// ok
	default:
		return fmt.Errorf("unexpected DCE-RPC response to BIND: 0x%02x", pktType(resp))
	}

	challenge := authValue(resp)
	if len(challenge) == 0 {
		// Server accepted without challenge (null session)
		return nil
	}

	auth, err := nc.Authenticate(challenge)
	if err != nil {
		return fmt.Errorf("NTLM Authenticate: %w", err)
	}

	auth3 := buildAuth3(callID, auth)
	// AUTH3 has no server response
	return s.send(auth3)
}

// resolveWMIPort queries the Endpoint Mapper (port 135) for the dynamic TCP port
// hosting IWbemLevel1Login. Falls back to scanning 49152..49165 on EPM failure.
func resolveWMIPort(host string) (int, error) {
	s, err := openRPC(host, 135, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("EPM connect: %w", err)
	}
	defer s.Close()

	// Bind to EPM (no auth required)
	callID := s.nextID()
	bindPkt := buildBind(callID, 0, uuidEPM, 3, 0, nil)
	resp, err := s.sendRecv(bindPkt)
	if err != nil {
		return 0, fmt.Errorf("EPM BIND: %w", err)
	}
	if pktType(resp) != dceTypBindAck {
		return 0, fmt.Errorf("EPM BIND_ACK expected, got 0x%02x", pktType(resp))
	}

	// ept_map request
	stub := buildEptMapStub()
	reqPkt := buildRequest(s.nextID(), 0, 3, stub)
	resp, err = s.sendRecv(reqPkt)
	if err != nil {
		return 0, fmt.Errorf("EPM ept_map: %w", err)
	}
	if pktType(resp) != dceTypResponse {
		return 0, fmt.Errorf("EPM response type 0x%02x", pktType(resp))
	}

	port := scanForTCPPort(resp[24:]) // skip DCE hdr(16) + request hdr(8)
	if port > 0 {
		return port, nil
	}

	// Fallback: probe common DCOM dynamic range
	for p := 49152; p <= 49165; p++ {
		probe, err := openRPC(host, p, 2*time.Second)
		if err != nil {
			continue
		}
		bid := probe.nextID()
		pb := buildBind(bid, 0, uuidWbemLogin, 0, 0, nil)
		r, err := probe.sendRecv(pb)
		probe.Close()
		if err == nil && pktType(r) == dceTypBindAck {
			return p, nil
		}
	}

	return 0, fmt.Errorf("EPM could not find WMI endpoint; ensure port 135 is reachable")
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

// buildProtocolTower encodes a 4-floor protocol tower for IWbemLevel1Login over TCP.
func buildProtocolTower() []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, uint16(4)) // floor_count

	// Floor 0: IWbemLevel1Login UUID (protocol 0x0d)
	// lhs_length = 1 (proto_id) + 16 (UUID) + 2 (major) = 19
	binary.Write(b, binary.LittleEndian, uint16(19))
	b.WriteByte(0x0d)
	b.Write(uuidWbemLogin[:])
	binary.Write(b, binary.LittleEndian, uint16(0)) // major
	binary.Write(b, binary.LittleEndian, uint16(2)) // rhs_length
	binary.Write(b, binary.LittleEndian, uint16(0)) // minor

	// Floor 1: NDR transfer syntax
	binary.Write(b, binary.LittleEndian, uint16(19))
	b.WriteByte(0x0d)
	b.Write(uuidNDR[:])
	binary.Write(b, binary.LittleEndian, uint16(2)) // major
	binary.Write(b, binary.LittleEndian, uint16(2)) // rhs_length
	binary.Write(b, binary.LittleEndian, uint16(0)) // minor

	// Floor 2: TCP (protocol 0x0b), port = 0 (querying)
	binary.Write(b, binary.LittleEndian, uint16(1))  // lhs_length
	b.WriteByte(0x0b)                                 // TCP
	binary.Write(b, binary.LittleEndian, uint16(2))  // rhs_length
	binary.Write(b, binary.BigEndian, uint16(0))     // port (big-endian)

	// Floor 3: IP address (protocol 0x09)
	binary.Write(b, binary.LittleEndian, uint16(1))  // lhs_length
	b.WriteByte(0x09)                                 // IP
	binary.Write(b, binary.LittleEndian, uint16(4))  // rhs_length
	b.Write([]byte{0, 0, 0, 0})

	return b.Bytes()
}

// scanForTCPPort scans the EPM response stub for a TCP floor and extracts the port.
func scanForTCPPort(stub []byte) int {
	// TCP floor pattern in EPM response: lhs_len=0x01 0x00, proto=0x0b, rhs_len=0x02 0x00, port(2 BE)
	for i := 0; i+6 < len(stub); i++ {
		if stub[i] == 0x01 && stub[i+1] == 0x00 && stub[i+2] == 0x0b &&
			stub[i+3] == 0x02 && stub[i+4] == 0x00 {
			port := int(binary.BigEndian.Uint16(stub[i+5:]))
			if port > 1024 && port < 65535 {
				return port
			}
		}
	}
	return 0
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
	// Step 1: EPM port resolution
	wmiPort, err := resolveWMIPort(x.host)
	if err != nil {
		return "", 1, fmt.Errorf("[step 1/4 EPM] %w", err)
	}

	// Step 2: DCE-RPC connect + NTLM bind to IWbemLevel1Login
	s, err := openRPC(x.host, wmiPort, 10*time.Second)
	if err != nil {
		return "", 1, fmt.Errorf("[step 2/4 DCOM-connect port=%d] %w", wmiPort, err)
	}
	defer s.Close()

	if err := bindNTLM(s, 0, uuidWbemLogin, 0, 0, x.bundle); err != nil {
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

	// Step 4: Win32_Process.Create via IWbemServices
	// Requires a new DCE-RPC session bound to IWbemServices using the IPID,
	// then ExecMethod("Win32_Process", "Create", ...) with full COM NDR marshaling.
	// This requires implementing IOrpcThis/IOrpcThat ORPC headers and VARIANT marshaling.
	_ = ipid
	return "", 1, fmt.Errorf(
		"[step 4/4 Win32_Process.Create] IWbemServices ExecMethod not implemented: "+
			"IPID=%x — requires ORPC header + VARIANT NDR marshaling", ipid[:8])
}
