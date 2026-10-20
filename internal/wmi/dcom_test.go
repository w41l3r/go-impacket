package wmi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMSUUID_EPM(t *testing.T) {
	// EPM UUID "6BFFD098-A112-3610-9833-46C3F87E345A"
	// First 4 bytes (LE): 0x6BFFD098 → stored as 98 D0 FF 6B
	u := msUUID("6BFFD098-A112-3610-9833-46C3F87E345A")
	if u[0] != 0x98 || u[1] != 0xD0 || u[2] != 0xFF || u[3] != 0x6B {
		t.Fatalf("EPM UUID LE field1 wrong: got %x", u[:4])
	}
	// Second field 0xA112 → stored as 12 A1
	if u[4] != 0x12 || u[5] != 0xA1 {
		t.Fatalf("EPM UUID LE field2 wrong: got %x", u[4:6])
	}
	// Third field 0x3610 → stored as 10 36
	if u[6] != 0x10 || u[7] != 0x36 {
		t.Fatalf("EPM UUID LE field3 wrong: got %x", u[6:8])
	}
}

func TestBuildProtocolTower(t *testing.T) {
	tower := buildProtocolTower()
	if len(tower) < 4 {
		t.Fatal("protocol tower too short")
	}
	floorCount := binary.LittleEndian.Uint16(tower[0:])
	if floorCount != 4 {
		t.Fatalf("expected 4 floors, got %d", floorCount)
	}
}

func TestBuildEptMapStub(t *testing.T) {
	stub := buildEptMapStub()
	if len(stub) == 0 {
		t.Fatal("ept_map stub is empty")
	}
	// First 4 bytes: null unique pointer for obj
	nullPtr := binary.LittleEndian.Uint32(stub[0:])
	if nullPtr != 0 {
		t.Fatalf("obj pointer should be null, got 0x%08X", nullPtr)
	}
	// Second 4 bytes: non-null referent for map_tower
	ref := binary.LittleEndian.Uint32(stub[4:])
	if ref == 0 {
		t.Fatal("map_tower referent should be non-zero")
	}
}

func TestBuildBind(t *testing.T) {
	pkt := buildBind(1, 0, uuidEPM, 3, 0, nil)
	if len(pkt) < 16 {
		t.Fatal("BIND packet too short")
	}
	// Version 5.0
	if pkt[0] != 5 || pkt[1] != 0 {
		t.Fatalf("DCE-RPC version wrong: got %d.%d", pkt[0], pkt[1])
	}
	// Packet type should be BIND (0x0b)
	if pkt[2] != dceTypBind {
		t.Fatalf("expected BIND type 0x%02x, got 0x%02x", dceTypBind, pkt[2])
	}
	// Call ID
	callID := binary.LittleEndian.Uint32(pkt[12:])
	if callID != 1 {
		t.Fatalf("expected callID=1, got %d", callID)
	}
}

func TestBuildRequest(t *testing.T) {
	stub := []byte{0x01, 0x02, 0x03, 0x04}
	pkt := buildRequest(5, 0, 3, stub)
	if len(pkt) < 16+8+len(stub) {
		t.Fatal("REQUEST packet too short")
	}
	if pkt[2] != dceTypRequest {
		t.Fatalf("expected REQUEST type, got 0x%02x", pkt[2])
	}
	opnum := binary.LittleEndian.Uint16(pkt[16+6:])
	if opnum != 3 {
		t.Fatalf("expected opnum=3, got %d", opnum)
	}
}

func TestEncodeWStr(t *testing.T) {
	var b bytes.Buffer
	encodeWStr(&b, "root")
	data := b.Bytes()

	// First 4 bytes: non-null referent
	ref := binary.LittleEndian.Uint32(data[0:])
	if ref == 0 {
		t.Fatal("wstring referent should be non-null")
	}

	// max_count = len("root\x00") = 5 UTF-16 words
	maxCount := binary.LittleEndian.Uint32(data[4:])
	if maxCount != 5 {
		t.Fatalf("expected max_count=5, got %d", maxCount)
	}
}
