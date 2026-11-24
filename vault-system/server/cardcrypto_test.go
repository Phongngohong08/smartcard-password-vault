package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// Vector chuẩn FIPS-197 phụ lục C.1 (AES-128).
func TestAdminResponseFIPS197(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	pt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	got, err := adminResponse(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "69c4e0d86a7b0430d8cdb78070b4c55a" {
		t.Fatalf("sai: %x", got)
	}
	if _, err := adminResponse(key, pt[:15]); err == nil {
		t.Fatal("challenge 15 byte phải lỗi")
	}
}

func TestDeriveAdminKeyPerCard(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	a, b := deriveAdminKey(master, "SC000001"), deriveAdminKey(master, "SC000002")
	if len(a) != 16 || hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatal("mỗi thẻ phải có khoá 16 byte riêng")
	}
	if hex.EncodeToString(a) != hex.EncodeToString(deriveAdminKey(master, "SC000001")) {
		t.Fatal("dẫn xuất phải ổn định")
	}
}

func TestVerifyCardSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mod := priv.N.FillBytes(make([]byte, 256))
	exp := big.NewInt(int64(priv.E)).Bytes()
	pub, err := parseRSAPublicKey(mod, exp)
	if err != nil {
		t.Fatal(err)
	}
	ch := make([]byte, 32)
	rand.Read(ch)
	msg := append(append([]byte("VAULTAUTH"), "SC000001"...), ch...)
	h := sha256.Sum256(msg)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])

	if err := verifyCardSignature(pub, "SC000001", ch, sig); err != nil {
		t.Fatalf("chữ ký đúng bị từ chối: %v", err)
	}
	if verifyCardSignature(pub, "SC000002", ch, sig) == nil {
		t.Fatal("chữ ký phải gắn với mã thẻ")
	}
	ch[0] ^= 1
	if verifyCardSignature(pub, "SC000001", ch, sig) == nil {
		t.Fatal("đổi challenge phải làm chữ ký sai")
	}
}

func TestParseRSAPublicKeyRejects(t *testing.T) {
	short := make([]byte, 255)
	if _, err := parseRSAPublicKey(short, []byte{1, 0, 1}); err == nil {
		t.Fatal("modulus 255 byte phải lỗi")
	}
	mod := make([]byte, 256)
	mod[0] = 0x80
	if _, err := parseRSAPublicKey(mod, []byte{2}); err == nil {
		t.Fatal("số mũ chẵn phải lỗi")
	}
}

func TestChallengeStoreOneTimeAndBound(t *testing.T) {
	s := newChallengeStore(time.Minute)
	ch := s.issue("SC000001")
	if s.take("SC000002", ch) {
		t.Fatal("challenge của thẻ khác phải bị từ chối")
	}
	ch = s.issue("SC000001")
	if !s.take("SC000001", ch) {
		t.Fatal("challenge hợp lệ bị từ chối")
	}
	if s.take("SC000001", ch) {
		t.Fatal("challenge chỉ được dùng một lần")
	}
	s2 := newChallengeStore(-time.Second)
	if s2.take("SC000001", s2.issue("SC000001")) {
		t.Fatal("challenge hết hạn phải bị từ chối")
	}
}

func TestPendingAfter(t *testing.T) {
	cases := []struct {
		cur, act, opp string
		onCard        bool
		want          string
	}{
		{"NONE", "LOCK", "UNLOCK", false, "LOCK"},
		{"NONE", "LOCK", "UNLOCK", true, "NONE"},
		{"LOCK", "UNLOCK", "LOCK", false, "NONE"}, // khoá chưa kịp đồng bộ rồi mở lại: triệt tiêu
		{"UNLOCK", "LOCK", "UNLOCK", false, "NONE"},
	}
	for _, c := range cases {
		if got := pendingAfter(c.cur, c.act, c.opp, c.onCard); got != c.want {
			t.Errorf("pendingAfter(%v) = %s, muốn %s", c, got, c.want)
		}
	}
}
