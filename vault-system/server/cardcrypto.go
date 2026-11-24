package main

import (
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Các hằng số phải khớp với VaultApplet.
var authPrefix = []byte("VAULTAUTH")

const (
	challengeLen      = 32
	adminChallengeLen = 16
	rsaModulusLen     = 256
)

var cardIDPattern = regexp.MustCompile(`^[A-Z0-9]{8}$`)

func validCardID(id string) bool { return cardIDPattern.MatchString(id) }

// deriveAdminKey: adminKey riêng của từng thẻ = HMAC-SHA256(khoá chủ, "VAULT-ADMIN-KEY" | cardId)[0..15].
// Lộ khoá của một thẻ không ảnh hưởng các thẻ khác.
func deriveAdminKey(master []byte, cardID string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("VAULT-ADMIN-KEY"))
	mac.Write([]byte(cardID))
	return mac.Sum(nil)[:16]
}

// adminResponse = AES-128-CBC(adminKey, IV = 0, challenge 16 byte) - một khối nên bằng AES-ECB.
func adminResponse(key, challenge []byte) ([]byte, error) {
	if len(challenge) != adminChallengeLen {
		return nil, fmt.Errorf("challenge admin phải dài %d byte", adminChallengeLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, adminChallengeLen)
	block.Encrypt(out, challenge)
	return out, nil
}

// parseRSAPublicKey kiểm tra modulus 2048 bit và số mũ hợp lý.
func parseRSAPublicKey(modulus, exponent []byte) (*rsa.PublicKey, error) {
	if len(modulus) != rsaModulusLen || modulus[0]&0x80 == 0 {
		return nil, errors.New("modulus phải là số 2048 bit (256 byte)")
	}
	if len(exponent) == 0 || len(exponent) > 4 {
		return nil, errors.New("số mũ không hợp lệ")
	}
	e := new(big.Int).SetBytes(exponent)
	if e.Int64() < 3 || e.Bit(0) == 0 {
		return nil, errors.New("số mũ không hợp lệ")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())}, nil
}

// verifyCardSignature kiểm tra chữ ký SHA256withRSA (PKCS#1 v1.5) của thẻ trên
// thông điệp "VAULTAUTH" | cardId | challenge.
func verifyCardSignature(pub *rsa.PublicKey, cardID string, challenge, sig []byte) error {
	msg := make([]byte, 0, len(authPrefix)+len(cardID)+len(challenge))
	msg = append(msg, authPrefix...)
	msg = append(msg, cardID...)
	msg = append(msg, challenge...)
	h := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
}

// keyFingerprint: 8 byte đầu của SHA-256(modulus), dạng AB:CD:... để admin đối chiếu.
func keyFingerprint(modulus []byte) string {
	h := sha256.Sum256(modulus)
	parts := make([]string, 8)
	for i := range parts {
		parts[i] = strings.ToUpper(hex.EncodeToString(h[i : i+1]))
	}
	return strings.Join(parts, ":")
}

// ---------------------------------------------------------------- challenge RSA

type pendingChallenge struct {
	cardID  string
	expires time.Time
}

// challengeStore giữ các challenge đã phát; mỗi challenge chỉ dùng được một lần, có hạn.
type challengeStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]pendingChallenge
}

func newChallengeStore(ttl time.Duration) *challengeStore {
	return &challengeStore{ttl: ttl, m: map[string]pendingChallenge{}}
}

func (s *challengeStore) issue(cardID string) []byte {
	ch := make([]byte, challengeLen)
	if _, err := rand.Read(ch); err != nil {
		panic(err)
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[string(ch)] = pendingChallenge{cardID: cardID, expires: now.Add(s.ttl)}
	return ch
}

// take lấy và xoá challenge; trả false nếu không có, hết hạn hoặc không phải của thẻ này.
func (s *challengeStore) take(cardID string, ch []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[string(ch)]
	if !ok {
		return false
	}
	delete(s.m, string(ch))
	return p.cardID == cardID && time.Now().Before(p.expires)
}
