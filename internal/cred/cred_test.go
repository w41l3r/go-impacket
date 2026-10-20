package cred

import (
	"testing"
)

func TestParseTargetFull(t *testing.T) {
	d, u, p, h, err := ParseTarget("corp/admin:s3cr3t@192.168.1.1")
	if err != nil || d != "corp" || u != "admin" || p != "s3cr3t" || h != "192.168.1.1" {
		t.Fatalf("got domain=%q user=%q pass=%q host=%q err=%v", d, u, p, h, err)
	}
}

func TestParseTargetNoPass(t *testing.T) {
	d, u, p, h, err := ParseTarget("WORKGROUP/bob@10.0.0.5")
	if err != nil || d != "WORKGROUP" || u != "bob" || p != "" || h != "10.0.0.5" {
		t.Fatalf("got domain=%q user=%q pass=%q host=%q err=%v", d, u, p, h, err)
	}
}

func TestParseTargetHostOnly(t *testing.T) {
	d, u, p, h, err := ParseTarget("10.0.0.1")
	if err != nil || d != "" || u != "" || p != "" || h != "10.0.0.1" {
		t.Fatalf("got domain=%q user=%q pass=%q host=%q err=%v", d, u, p, h, err)
	}
}

func TestFromHashesValid(t *testing.T) {
	lm, nt, err := FromHashes("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatal(err)
	}
	if len(lm) != 0 {
		t.Fatalf("expected empty LM, got %x", lm)
	}
	if len(nt) != 16 {
		t.Fatalf("expected 16-byte NT hash, got %d bytes", len(nt))
	}
}

func TestFromHashesBadFormat(t *testing.T) {
	_, _, err := FromHashes("nocolon")
	if err == nil {
		t.Fatal("expected error for missing colon")
	}
}

func TestBundlePassTheHash(t *testing.T) {
	_, nt, err := FromHashes("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{Username: "admin", NTHash: nt}
	if !b.IsPassTheHash() {
		t.Fatal("expected IsPassTheHash to be true")
	}
}
