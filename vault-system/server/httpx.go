package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------- JSON

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiError là lỗi trả về cho client: {"error": "...", "code": "...", ...extra}
type apiError struct {
	Status int
	Code   string
	Msg    string
	Extra  map[string]any
}

func (e *apiError) Error() string { return e.Msg }

func errf(status int, code, format string, args ...any) *apiError {
	return &apiError{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		log.Printf("Lỗi nội bộ: %v", err)
		ae = errf(http.StatusInternalServerError, "INTERNAL", "Lỗi máy chủ")
	}
	body := map[string]any{"error": ae.Msg, "code": ae.Code}
	for k, v := range ae.Extra {
		body[k] = v
	}
	writeJSON(w, ae.Status, body)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return errf(http.StatusBadRequest, "BAD_JSON", "Dữ liệu JSON không hợp lệ")
	}
	return nil
}

func decodeHex(field, s string, wantLen int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || (wantLen > 0 && len(b) != wantLen) {
		if wantLen > 0 {
			return nil, errf(http.StatusBadRequest, "BAD_HEX", "%s phải là chuỗi hex %d byte", field, wantLen)
		}
		return nil, errf(http.StatusBadRequest, "BAD_HEX", "%s phải là chuỗi hex", field)
	}
	return b, nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handler trả về error để gom xử lý lỗi một chỗ.
type handler func(w http.ResponseWriter, r *http.Request) error

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		writeErr(w, err)
	}
}

// ---------------------------------------------------------------- token

const (
	tokenAdmin = "admin"
	tokenCard  = "card"
	// Token "pending": thẻ đã qua RSA nhưng bị khoá / thu hồi; chỉ dùng để đồng bộ thao tác admin lên thẻ.
	scopeCard    = "card"
	scopePending = "pending"
)

type Claims struct {
	Typ   string `json:"typ"`
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func (a *App) signToken(typ, subject, scope string, ttl time.Duration) (string, time.Time, error) {
	exp := time.Now().Add(ttl)
	c := Claims{Typ: typ, Scope: scope, RegisteredClaims: jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(exp),
	}}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(a.secrets.JWTSecret)
	return s, exp, err
}

func (a *App) parseToken(r *http.Request, typ string) (*Claims, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return nil, errf(http.StatusUnauthorized, "NO_TOKEN", "Chưa đăng nhập")
	}
	var c Claims
	_, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) { return a.secrets.JWTSecret, nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || c.Typ != typ {
		return nil, errf(http.StatusUnauthorized, "BAD_TOKEN", "Phiên đăng nhập không hợp lệ hoặc đã hết hạn")
	}
	return &c, nil
}

type authedHandler func(w http.ResponseWriter, r *http.Request, c *Claims) error

func (a *App) admin(h authedHandler) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		c, err := a.parseToken(r, tokenAdmin)
		if err != nil {
			return err
		}
		return h(w, r, c)
	}
}

// card yêu cầu token thẻ với một trong các scope cho phép.
func (a *App) card(scopes []string, h authedHandler) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		c, err := a.parseToken(r, tokenCard)
		if err != nil {
			return err
		}
		for _, s := range scopes {
			if c.Scope == s {
				return h(w, r, c)
			}
		}
		return errf(http.StatusForbidden, "BAD_SCOPE", "Token không đủ quyền cho thao tác này")
	}
}

// ---------------------------------------------------------------- middleware

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic: %v", p)
				writeErr(rec, errors.New("panic"))
			}
			if strings.HasPrefix(r.URL.Path, "/api/") {
				log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
			}
		}()
		next.ServeHTTP(rec, r)
	})
}
