package relay

import (
	"encoding/binary"
	"testing"
)

// buildMinimalSessionSetupReq builds a minimal SMB2 SESSION_SETUP request packet
// with a given security blob, for testing extractSetupSecBlob.
func buildMinimalSessionSetupReq(secBlob []byte) []byte {
	secOff := uint16(smb2HdrSize + 25) // where the security blob starts
	body := make([]byte, 25)
	binary.LittleEndian.PutUint16(body[0:], 25)             // StructureSize
	binary.LittleEndian.PutUint16(body[12:], secOff)        // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[14:], uint16(len(secBlob))) // SecurityBufferLength
	// PreviousSessionId at body[16:24] stays zero

	hdr := make([]byte, smb2HdrSize)
	copy(hdr[0:], smb2Magic)
	binary.LittleEndian.PutUint16(hdr[12:], smb2CmdSessionSetup)

	pkt := append(hdr, body...)
	pkt = append(pkt, secBlob...)
	return pkt
}

func TestExtractSetupSecBlob(t *testing.T) {
	blob := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	pkt := buildMinimalSessionSetupReq(blob)

	got, err := extractSetupSecBlob(pkt)
	if err != nil {
		t.Fatalf("extractSetupSecBlob: %v", err)
	}
	if string(got) != string(blob) {
		t.Fatalf("got %x, want %x", got, blob)
	}
}

func TestExtractSetupSecBlobTooShort(t *testing.T) {
	_, err := extractSetupSecBlob([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short packet")
	}
}

func TestUnwrapSPNEGO_DirectNTLM(t *testing.T) {
	ntlm := []byte("NTLMSSP\x00\x01\x00\x00\x00something")
	got := unwrapSPNEGO(ntlm)
	if string(got) != string(ntlm) {
		t.Fatalf("got %x, want %x", got, ntlm)
	}
}

func TestUnwrapSPNEGO_Wrapped(t *testing.T) {
	ntlm := []byte("NTLMSSP\x00\x01\x00\x00\x00data")
	// Wrap in some SPNEGO header bytes
	wrapped := append([]byte{0x60, 0x40, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}, ntlm...)
	got := unwrapSPNEGO(wrapped)
	if string(got) != string(ntlm) {
		t.Fatalf("got %x, want %x", got, ntlm)
	}
}

func TestUnwrapSPNEGO_NoNTLM(t *testing.T) {
	got := unwrapSPNEGO([]byte{0x60, 0x20, 0x30, 0x18})
	if got != nil {
		t.Fatalf("expected nil for non-NTLM blob, got %x", got)
	}
}

func TestSMB2PacketHelpers(t *testing.T) {
	pkt := buildSMB2Negotiate()
	if smb2Command(pkt) != smb2CmdNegotiate {
		t.Fatalf("expected NEGOTIATE cmd, got 0x%04x", smb2Command(pkt))
	}

	setup := buildSMB2SessionSetup([]byte{0xAA, 0xBB})
	if smb2Command(setup) != smb2CmdSessionSetup {
		t.Fatalf("expected SESSION_SETUP cmd, got 0x%04x", smb2Command(setup))
	}
}

func TestRewriteSessionID(t *testing.T) {
	pkt := make([]byte, 64)
	binary.LittleEndian.PutUint64(pkt[40:], 0x1234567890ABCDEF)

	out := rewriteSessionID(pkt, 0xDEADBEEFCAFEBABE)
	got := binary.LittleEndian.Uint64(out[40:])
	if got != 0xDEADBEEFCAFEBABE {
		t.Fatalf("got 0x%016X, want 0xDEADBEEFCAFEBABE", got)
	}
	// Original must be unchanged
	orig := binary.LittleEndian.Uint64(pkt[40:])
	if orig != 0x1234567890ABCDEF {
		t.Fatal("rewriteSessionID modified the original packet")
	}
}

func TestWrapNTLMinSPNEGO_Type1(t *testing.T) {
	// Build a fake NTLM type 1 blob (at least 12 bytes)
	ntlm := make([]byte, 24)
	copy(ntlm, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:], 1)

	wrapped := wrapNTLMinSPNEGO(ntlm)
	// Should be SPNEGO application tag 0x60
	if len(wrapped) == 0 || wrapped[0] != 0x60 {
		t.Fatalf("expected SPNEGO application tag 0x60, got 0x%02x", wrapped[0])
	}
	// Should contain NTLMSSP magic
	found := false
	for i := 0; i+8 <= len(wrapped); i++ {
		if string(wrapped[i:i+8]) == "NTLMSSP\x00" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("NTLMSSP magic not found in SPNEGO wrapper")
	}
}

func TestWrapNTLMinSPNEGO_Type3(t *testing.T) {
	ntlm := make([]byte, 24)
	copy(ntlm, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(ntlm[8:], 3)

	wrapped := wrapNTLMinSPNEGO(ntlm)
	// Should be negTokenTarg context tag 0xa1
	if len(wrapped) == 0 || wrapped[0] != 0xa1 {
		t.Fatalf("expected negTokenTarg tag 0xa1, got 0x%02x", wrapped[0])
	}
}

func TestBerHelpers(t *testing.T) {
	// Short length
	l := berLen(5)
	if len(l) != 1 || l[0] != 5 {
		t.Fatalf("berLen(5): want [0x05], got %x", l)
	}
	// Long length
	l = berLen(200)
	if len(l) != 2 || l[0] != 0x81 || l[1] != 200 {
		t.Fatalf("berLen(200): want [0x81 0xc8], got %x", l)
	}
	// Sequence
	seq := berSeq([]byte{0x01, 0x02})
	if seq[0] != 0x30 {
		t.Fatalf("berSeq: expected tag 0x30, got 0x%02x", seq[0])
	}
}

