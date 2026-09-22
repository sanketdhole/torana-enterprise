package security_test

import (
	"fmt"
	"testing"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/security/authn"
)

func TestRevocationList_ApplyFromProtoMessage(t *testing.T) {
	revList := authn.NewRevocationList()

	msg := &controlplanev1.Revocation{
		RevokedTokens: []string{"tok-101", "tok-102", "tok-103"},
		RevokedKeys:   []string{"key-pref-1", "key-pref-2"},
	}

	revList.ApplyRevocation(msg)

	tokCount, keyCount := revList.Count()
	if tokCount != 3 || keyCount != 2 {
		t.Fatalf("expected 3 tokens and 2 keys, got %d tokens, %d keys", tokCount, keyCount)
	}

	if !revList.IsTokenRevoked("tok-102") {
		t.Errorf("expected tok-102 to be revoked")
	}
	if revList.IsTokenRevoked("tok-nonexistent") {
		t.Errorf("expected tok-nonexistent NOT to be revoked")
	}

	if !revList.IsKeyRevoked("key-pref-1") {
		t.Errorf("expected key-pref-1 to be revoked")
	}
	if revList.IsKeyRevoked("key-pref-nonexistent") {
		t.Errorf("expected key-pref-nonexistent NOT to be revoked")
	}

	if !revList.IsRevoked("tok-103") {
		t.Errorf("expected IsRevoked(tok-103) == true")
	}
	if !revList.IsRevoked("key-pref-2") {
		t.Errorf("expected IsRevoked(key-pref-2) == true")
	}
	if revList.IsRevoked("random-clean-id") {
		t.Errorf("expected IsRevoked(random-clean-id) == false")
	}
}

func BenchmarkRevocationList_O1Lookup(b *testing.B) {
	revList := authn.NewRevocationList()

	// Seed 100,000 revoked entries
	const numEntries = 100_000
	tokens := make([]string, numEntries)
	for i := 0; i < numEntries; i++ {
		tok := fmt.Sprintf("revoked-token-uuid-%08d", i)
		tokens[i] = tok
		revList.RevokeToken(tok)
	}

	target := tokens[numEntries/2]

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !revList.IsTokenRevoked(target) {
			b.Fatal("expected target to be revoked")
		}
	}
}
