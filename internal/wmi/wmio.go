package wmi

// wmio.go — Minimal WMIO (MS-WMIO) encoder for Win32_Process.Create input params.
//
// Encodes a CIM instance of the Win32_Process.__PARAMETERS class with
// CommandLine set, CurrentDirectory and ProcessStartupInformation null.
// The result is wrapped in an OBJREF_CUSTOM for use as pInParams in
// IWbemServices::ExecMethod over DCOM.

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// IID of IWbemClassObject (DC12A681-737F-11CF-884D-00AA004B2E24) in wire format
// First 3 fields stored LE, last 8 bytes as-is.
var iidIWbemClassObject = [16]byte{
	0x81, 0xA6, 0x12, 0xDC, 0x7F, 0x73, 0xCF, 0x11,
	0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
}

// CLSID of WBEMClassObject custom marshaler (4590F812-1D3A-11D0-891F-00AA004B2E24)
var clsidWBEMClassObject = [16]byte{
	0x12, 0xF8, 0x90, 0x45, 0x3A, 0x1D, 0xD0, 0x11,
	0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
}

// BuildWin32ProcessCreateInParams returns a fully encoded MInterfacePointer
// (cbData + OBJREF_CUSTOM + WMIO blob) for Win32_Process.Create pInParams
// with the given commandLine.
func BuildWin32ProcessCreateInParams(commandLine string) []byte {
	wmio := buildWMIOInstanceBlob(commandLine)
	objref := buildOBJREF_CUSTOM(wmio)
	// MInterfacePointer = cbData (uint32) + abData
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(objref)))
	buf.Write(objref)
	return buf.Bytes()
}

// buildOBJREF_CUSTOM wraps the WMIO blob in an OBJREF_CUSTOM for IWbemClassObject.
func buildOBJREF_CUSTOM(data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write([]byte{0x4D, 0x45, 0x4F, 0x57}) // "MEOW"
	binary.Write(buf, binary.LittleEndian, uint32(4))          // OBJREF_CUSTOM
	buf.Write(iidIWbemClassObject[:])
	buf.Write(clsidWBEMClassObject[:])
	binary.Write(buf, binary.LittleEndian, uint32(0))           // cbExtension
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))   // size
	buf.Write(data)
	return buf.Bytes()
}

// buildWMIOInstanceBlob produces the raw WMIO-encoded CIM instance for
// Win32_Process.__PARAMETERS with CommandLine set to commandLine.
//
// Structure (MS-WMIO):
//   ClassPart  (ObjectFlags=0x01 + CurrentClassSize + DerivationList +
//               ClassQualifierSet + PropertyLookupTable + NullHeap + ClassHeap)
//   InstancePart (InstanceQualifierSet + NdTable + ValueTable + InstanceHeap)
func buildWMIOInstanceBlob(commandLine string) []byte {
	// ── Class Heap (property names, UTF-16LE + null) ──────────────────────────
	//   Property 0: CommandLine            (CIM_STRING = 8)
	//   Property 1: CurrentDirectory       (CIM_STRING = 8)
	//   Property 2: ProcessStartupInformation (CIM_OBJECT = 13)
	name0 := utf16NullBytes("CommandLine")                // 24 bytes
	name1 := utf16NullBytes("CurrentDirectory")           // 34 bytes
	name2 := utf16NullBytes("ProcessStartupInformation")  // 52 bytes

	classHeapData := concat(name0, name1, name2)
	nameRef0 := uint16(0)
	nameRef1 := uint16(len(name0))
	nameRef2 := uint16(len(name0) + len(name1))

	// Class heap blob: HeapLength (4 bytes, includes itself) + data
	classHeapLen := uint32(4 + len(classHeapData))
	classHeap := new(bytes.Buffer)
	binary.Write(classHeap, binary.LittleEndian, classHeapLen)
	classHeap.Write(classHeapData)

	// ── PropertyLookupTable ───────────────────────────────────────────────────
	// Each entry: PropertyNameRef(2) + DataType(2) + DataOffset(4)
	// DataOffset=0xFFFFFFFF → no default value.
	propTable := new(bytes.Buffer)
	binary.Write(propTable, binary.LittleEndian, uint32(3))
	writePropertyLookup(propTable, nameRef0, 0x0008, 0xFFFFFFFF)
	writePropertyLookup(propTable, nameRef1, 0x0008, 0xFFFFFFFF)
	writePropertyLookup(propTable, nameRef2, 0x000D, 0xFFFFFFFF)

	// ── DerivationList: empty (EncodingLength = 4) ────────────────────────────
	derivList := uint32LE(4)

	// ── ClassQualifierSet: empty (Size = 4) ──────────────────────────────────
	classQuals := uint32LE(4)

	// ── NullHeap (class-level defaults): empty (Size = 0) ────────────────────
	nullHeap := uint32LE(0)

	// ── Assemble ClassPart body ───────────────────────────────────────────────
	classBody := concat(derivList, classQuals, propTable.Bytes(), nullHeap, classHeap.Bytes())
	// CurrentClassSize includes ObjectFlags(1) + CurrentClassSize field(4) + classBody
	classSize := uint32(1 + 4 + len(classBody))

	classPart := new(bytes.Buffer)
	classPart.WriteByte(0x01) // ObjectFlags = ClassObject
	binary.Write(classPart, binary.LittleEndian, classSize)
	classPart.Write(classBody)

	// ── Instance Heap (string values) ────────────────────────────────────────
	cmdBytes := utf16NullBytes(commandLine)
	instHeapLen := uint32(4 + len(cmdBytes))
	instHeap := new(bytes.Buffer)
	binary.Write(instHeap, binary.LittleEndian, instHeapLen)
	instHeap.Write(cmdBytes)

	// ── NdTable (2 bits per property, LSB-first) ──────────────────────────────
	// Property 0 (CommandLine): 00 = value present
	// Property 1 (CurrentDirectory): 01 = null
	// Property 2 (ProcessStartupInformation): 01 = null
	// byte = 0b00_01_01_00 ... bits [1:0]=00,[3:2]=01,[5:4]=01 → 0x14
	ndTable := byte(0x14)

	// ── ValueTable (4 bytes per property) ────────────────────────────────────
	// String offsets are relative to start of InstanceHeap data (after HeapLength).
	// CommandLine → offset 0 in heap data
	// CurrentDirectory → 0xFFFFFFFF (null)
	// ProcessStartupInformation → 0xFFFFFFFF (null)
	valueTable := new(bytes.Buffer)
	binary.Write(valueTable, binary.LittleEndian, uint32(0))          // CommandLine at heap[0]
	binary.Write(valueTable, binary.LittleEndian, uint32(0xFFFFFFFF)) // CurrentDirectory null
	binary.Write(valueTable, binary.LittleEndian, uint32(0xFFFFFFFF)) // PSI null

	// ── InstanceQualifierSet: empty ───────────────────────────────────────────
	instQuals := uint32LE(4)

	// ── Assemble InstancePart ─────────────────────────────────────────────────
	instancePart := new(bytes.Buffer)
	instancePart.Write(instQuals)
	instancePart.WriteByte(ndTable)
	instancePart.Write(valueTable.Bytes())
	instancePart.Write(instHeap.Bytes())

	// ── Final WMIO blob ───────────────────────────────────────────────────────
	var blob bytes.Buffer
	blob.Write(classPart.Bytes())
	blob.Write(instancePart.Bytes())
	return blob.Bytes()
}

// writePropertyLookup writes one 8-byte PropertyLookup entry.
func writePropertyLookup(b *bytes.Buffer, nameRef, dataType uint16, dataOffset uint32) {
	binary.Write(b, binary.LittleEndian, nameRef)
	binary.Write(b, binary.LittleEndian, dataType)
	binary.Write(b, binary.LittleEndian, dataOffset)
}

// utf16NullBytes returns s encoded as UTF-16LE with a null terminator.
func utf16NullBytes(s string) []byte {
	r16 := utf16.Encode([]rune(s))
	r16 = append(r16, 0)
	out := make([]byte, len(r16)*2)
	for i, w := range r16 {
		binary.LittleEndian.PutUint16(out[i*2:], w)
	}
	return out
}

func uint32LE(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

func concat(parts ...[]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	return buf.Bytes()
}
