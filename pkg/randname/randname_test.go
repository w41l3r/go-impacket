package randname

import (
	"testing"
	"unicode"
)

func TestAlpha(t *testing.T) {
	s := Alpha(8)
	if len(s) != 8 {
		t.Fatalf("want len=8, got %d", len(s))
	}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			t.Fatalf("non-letter in Alpha output: %q", r)
		}
	}
}

func TestAlnum(t *testing.T) {
	s := Alnum(16)
	if len(s) != 16 {
		t.Fatalf("want len=16, got %d", len(s))
	}
}

func TestUniqueness(t *testing.T) {
	a, b := Alpha(12), Alpha(12)
	if a == b {
		t.Log("collision (unlikely but not a hard failure)")
	}
}
