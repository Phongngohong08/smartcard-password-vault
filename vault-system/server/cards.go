package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Card struct {
	CardID         string     `json:"cardId"`
	OwnerName      string     `json:"ownerName"`
	OwnerEmail     *string    `json:"ownerEmail"`
	OwnerPhone     *string    `json:"ownerPhone"`
	Status         string     `json:"status"`
	CardState      string     `json:"cardState"`
	PendingAction  string     `json:"pendingAction"`
	ReplacesCardID *string    `json:"replacesCardId"`
	IssuedBy       *string    `json:"issuedBy"`
	IssuedAt       *time.Time `json:"issuedAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
	LastSeenAt     *time.Time `json:"lastSeenAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	KeyFingerprint string     `json:"keyFingerprint"`

	modulus  []byte
	exponent []byte
}

const cardCols = `card_id, owner_name, owner_email, owner_phone, status, card_state, pending_action,
	replaces_card_id, issued_by, issued_at, revoked_at, last_seen_at, created_at, rsa_modulus, rsa_exponent`

type scanner interface{ Scan(dest ...any) error }

func scanCard(s scanner) (*Card, error) {
	var c Card
	var email, phone, repl, by sql.NullString
	var issued, revoked, seen sql.NullTime
	if err := s.Scan(&c.CardID, &c.OwnerName, &email, &phone, &c.Status, &c.CardState, &c.PendingAction,
		&repl, &by, &issued, &revoked, &seen, &c.CreatedAt, &c.modulus, &c.exponent); err != nil {
		return nil, err
	}
	c.OwnerEmail, c.OwnerPhone, c.ReplacesCardID, c.IssuedBy = nullString(email), nullString(phone), nullString(repl), nullString(by)
	c.IssuedAt, c.RevokedAt, c.LastSeenAt = nullTime(issued), nullTime(revoked), nullTime(seen)
	c.KeyFingerprint = keyFingerprint(c.modulus)
	return &c, nil
}

var errCardNotFound = errf(http.StatusNotFound, "CARD_NOT_FOUND", "Không tìm thấy thẻ")

func (a *App) getCard(ctx context.Context, id string) (*Card, error) {
	c, err := scanCard(a.db.QueryRowContext(ctx, `SELECT `+cardCols+` FROM cards WHERE card_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errCardNotFound
	}
	return c, err
}

func pathCardID(r *http.Request) (string, error) {
	id := strings.ToUpper(r.PathValue("id"))
	if !validCardID(id) {
		return "", errf(http.StatusBadRequest, "BAD_CARD_ID", "Mã thẻ phải gồm 8 ký tự chữ hoa hoặc số")
	}
	return id, nil
}

// ---------------------------------------------------------------- danh sách, chi tiết

func (a *App) handleListCards(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	q := `SELECT ` + cardCols + ` FROM cards WHERE 1=1`
	var args []any
	if s := r.URL.Query().Get("status"); s != "" {
		q += ` AND status = ?`
		args = append(args, s)
	}
	if s := strings.TrimSpace(r.URL.Query().Get("q")); s != "" {
		q += ` AND (card_id LIKE ? OR owner_name LIKE ? OR owner_email LIKE ?)`
		like := "%" + s + "%"
		args = append(args, like, like, like)
	}
	q += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := a.db.QueryContext(r.Context(), q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	cards := []*Card{}
	for rows.Next() {
		c, err := scanCard(rows)
		if err != nil {
			return err
		}
		cards = append(cards, c)
	}
	writeJSON(w, http.StatusOK, cards)
	return rows.Err()
}

func (a *App) handleGetCard(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	id, err := pathCardID(r)
	if err != nil {
		return err
	}
	c, err := a.getCard(r.Context(), id)
	if err != nil {
		return err
	}
	logs, err := a.queryLogs(r.Context(), logFilter{CardID: id, Size: 30, Page: 1})
	if err != nil {
		return err
	}
	backups, err := a.listBackups(r.Context(), []string{id})
	if err != nil {
		return err
	}
	var replacedBy *string
	var rb string
	if err := a.db.QueryRowContext(r.Context(), `SELECT card_id FROM cards WHERE replaces_card_id = ? LIMIT 1`, id).Scan(&rb); err == nil {
		replacedBy = &rb
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"card":        c,
		"modulusHex":  hex.EncodeToString(c.modulus),
		"exponentHex": hex.EncodeToString(c.exponent),
		"replacedBy":  replacedBy,
		"logs":        logs.Items,
		"backups":     backups,
	})
	return nil
}

// handleNextCardID gợi ý mã thẻ tiếp theo dạng SC000001.
func (a *App) handleNextCardID(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	var last sql.NullString
	if err := a.db.QueryRowContext(r.Context(),
		`SELECT MAX(card_id) FROM cards WHERE card_id REGEXP '^SC[0-9]{6}$'`).Scan(&last); err != nil {
		return err
	}
	next := 1
	if last.Valid {
		n, _ := strconv.Atoi(last.String[2:])
		next = n + 1
	}
	writeJSON(w, http.StatusOK, map[string]string{"cardId": fmt.Sprintf("SC%06d", next)})
	return nil
}

// ---------------------------------------------------------------- phát hành

// handleIssueKey trả adminKey của thẻ để agent ghi vào thẻ lúc ISSUE.
// Chỉ cấp cho mã thẻ chưa dùng hoặc đang PENDING (phát hành dở).
func (a *App) handleIssueKey(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	id, err := pathCardID(r)
	if err != nil {
		return err
	}
	c, err := a.getCard(r.Context(), id)
	if err != nil && !errors.Is(err, errCardNotFound) {
		return err
	}
	if c != nil && c.Status != "PENDING" {
		return errf(http.StatusConflict, "CARD_EXISTS", "Mã thẻ %s đã được phát hành", id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"adminKey": hex.EncodeToString(deriveAdminKey(a.secrets.AdminMasterKey, id))})
	return nil
}

// handleRegisterCard lưu khoá công khai của thẻ vừa ISSUE, trạng thái PENDING cho tới khi kiểm tra RSA xong.
func (a *App) handleRegisterCard(w http.ResponseWriter, r *http.Request, c *Claims) error {
	var req struct {
		CardID         string `json:"cardId"`
		OwnerName      string `json:"ownerName"`
		OwnerEmail     string `json:"ownerEmail"`
		OwnerPhone     string `json:"ownerPhone"`
		ModulusHex     string `json:"modulusHex"`
		ExponentHex    string `json:"exponentHex"`
		ReplacesCardID string `json:"replacesCardId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.CardID = strings.ToUpper(strings.TrimSpace(req.CardID))
	req.OwnerName = strings.TrimSpace(req.OwnerName)
	req.ReplacesCardID = strings.ToUpper(strings.TrimSpace(req.ReplacesCardID))
	if !validCardID(req.CardID) {
		return errf(http.StatusBadRequest, "BAD_CARD_ID", "Mã thẻ phải gồm 8 ký tự chữ hoa hoặc số")
	}
	if n := utf8.RuneCountInString(req.OwnerName); n == 0 || len(req.OwnerName) > 64 {
		return errf(http.StatusBadRequest, "BAD_OWNER", "Họ tên chủ thẻ bắt buộc, tối đa 64 byte")
	}
	if len(req.OwnerEmail) > 64 || len(req.OwnerPhone) > 16 {
		return errf(http.StatusBadRequest, "BAD_OWNER", "Email tối đa 64 byte, SĐT tối đa 16 byte")
	}
	mod, err := decodeHex("modulusHex", req.ModulusHex, rsaModulusLen)
	if err != nil {
		return err
	}
	exp, err := decodeHex("exponentHex", req.ExponentHex, 0)
	if err != nil {
		return err
	}
	if _, err := parseRSAPublicKey(mod, exp); err != nil {
		return errf(http.StatusBadRequest, "BAD_KEY", "Khoá công khai không hợp lệ: %v", err)
	}
	if req.ReplacesCardID != "" {
		if req.ReplacesCardID == req.CardID {
			return errf(http.StatusBadRequest, "BAD_REPLACES", "Thẻ không thể thay thế chính nó")
		}
		if _, err := a.getCard(r.Context(), req.ReplacesCardID); err != nil {
			return errf(http.StatusBadRequest, "BAD_REPLACES", "Không có thẻ cũ %s", req.ReplacesCardID)
		}
	}
	existing, err := a.getCard(r.Context(), req.CardID)
	if err != nil && !errors.Is(err, errCardNotFound) {
		return err
	}
	if existing != nil && existing.Status != "PENDING" {
		return errf(http.StatusConflict, "CARD_EXISTS", "Mã thẻ %s đã được phát hành", req.CardID)
	}
	_, err = a.db.ExecContext(r.Context(), `
		INSERT INTO cards (card_id, owner_name, owner_email, owner_phone, rsa_modulus, rsa_exponent, status, replaces_card_id, issued_by)
		VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
		ON DUPLICATE KEY UPDATE owner_name = VALUES(owner_name), owner_email = VALUES(owner_email),
			owner_phone = VALUES(owner_phone), rsa_modulus = VALUES(rsa_modulus), rsa_exponent = VALUES(rsa_exponent),
			replaces_card_id = VALUES(replaces_card_id), issued_by = VALUES(issued_by)`,
		req.CardID, req.OwnerName, optString(req.OwnerEmail), optString(req.OwnerPhone), mod, exp,
		optString(req.ReplacesCardID), c.Subject)
	if err != nil {
		return err
	}
	card, err := a.getCard(r.Context(), req.CardID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, card)
	return nil
}

// handleActivate: bước cuối của phát hành - thẻ ký challenge, server kiểm bằng khoá vừa lưu.
func (a *App) handleActivate(w http.ResponseWriter, r *http.Request, c *Claims) error {
	id, err := pathCardID(r)
	if err != nil {
		return err
	}
	var req struct {
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	card, err := a.getCard(r.Context(), id)
	if err != nil {
		return err
	}
	if card.Status != "PENDING" {
		return errf(http.StatusConflict, "NOT_PENDING", "Thẻ %s không ở trạng thái chờ kích hoạt", id)
	}
	ch, err := decodeHex("challenge", req.Challenge, challengeLen)
	if err != nil {
		return err
	}
	sig, err := decodeHex("signature", req.Signature, rsaModulusLen)
	if err != nil {
		return err
	}
	if !a.challenges.take(id, ch) {
		return errf(http.StatusBadRequest, "BAD_CHALLENGE", "Challenge không hợp lệ hoặc đã hết hạn")
	}
	pub, err := parseRSAPublicKey(card.modulus, card.exponent)
	if err != nil {
		return err
	}
	if err := verifyCardSignature(pub, id, ch, sig); err != nil {
		a.audit(r, id, adminActor(c), "RSA_AUTH", false, "Kích hoạt: chữ ký không khớp khoá công khai")
		a.audit(r, id, adminActor(c), "ISSUE", false, "Chữ ký RSA không hợp lệ")
		return errf(http.StatusBadRequest, "BAD_SIGNATURE", "Chữ ký của thẻ không khớp khoá công khai đã lưu")
	}
	_, err = a.db.ExecContext(r.Context(), `UPDATE cards SET status = 'ACTIVE', card_state = 'ACTIVE', issued_at = NOW(),
		issued_by = ?, last_seen_at = NOW() WHERE card_id = ?`, c.Subject, id)
	if err != nil {
		return err
	}
	a.audit(r, id, adminActor(c), "RSA_AUTH", true, "Kích hoạt thẻ")
	detail := "Chủ thẻ: " + card.OwnerName
	if card.ReplacesCardID != nil {
		detail += ", thay thẻ " + *card.ReplacesCardID
	}
	a.audit(r, id, adminActor(c), "ISSUE", true, detail)
	card, err = a.getCard(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, card)
	return nil
}

func (a *App) handleDeletePendingCard(w http.ResponseWriter, r *http.Request, c *Claims) error {
	id, err := pathCardID(r)
	if err != nil {
		return err
	}
	res, err := a.db.ExecContext(r.Context(), `DELETE FROM cards WHERE card_id = ? AND status = 'PENDING'`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errf(http.StatusConflict, "NOT_PENDING", "Chỉ xoá được thẻ đang chờ kích hoạt")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ---------------------------------------------------------------- quản trị trên thẻ

// handleAdminResponse tính phản hồi cho ADMIN_CHALLENGE của thẻ (agent gọi, kèm token admin).
func (a *App) handleAdminResponse(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	id, err := pathCardID(r)
	if err != nil {
		return err
	}
	var req struct {
		Challenge string `json:"challenge"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ch, err := decodeHex("challenge", req.Challenge, adminChallengeLen)
	if err != nil {
		return err
	}
	if _, err := a.getCard(r.Context(), id); err != nil {
		return err
	}
	resp, err := adminResponse(deriveAdminKey(a.secrets.AdminMasterKey, id), ch)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"response": hex.EncodeToString(resp)})
	return nil
}

// handleCardAction: LOCK / UNLOCK / REVOKE.
// onCard = true: agent đã thực hiện trên thẻ đang cắm. false: chỉ cập nhật CSDL, thao tác được
// ghi vào pending_action và đồng bộ lên thẻ ở lần kết nối sau.
func (a *App) handleCardAction(action string) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, c *Claims) error {
		id, err := pathCardID(r)
		if err != nil {
			return err
		}
		var req struct {
			OnCard bool   `json:"onCard"`
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &req); err != nil {
			return err
		}
		card, err := a.getCard(r.Context(), id)
		if err != nil {
			return err
		}
		var newStatus, newPending, newState string
		newState = card.CardState
		switch action {
		case "LOCK":
			if card.Status != "ACTIVE" {
				return errf(http.StatusConflict, "BAD_STATUS", "Chỉ khoá được thẻ đang hoạt động")
			}
			newStatus = "LOCKED"
			newPending = pendingAfter(card.PendingAction, "LOCK", "UNLOCK", req.OnCard)
			if req.OnCard {
				newState = "ADMIN_LOCKED"
			}
		case "UNLOCK":
			if card.Status != "LOCKED" {
				return errf(http.StatusConflict, "BAD_STATUS", "Chỉ mở khoá được thẻ đang bị khoá")
			}
			newStatus = "ACTIVE"
			newPending = pendingAfter(card.PendingAction, "UNLOCK", "LOCK", req.OnCard)
			if req.OnCard {
				newState = "ACTIVE"
			}
		case "REVOKE":
			if card.Status == "REVOKED" || card.Status == "PENDING" {
				return errf(http.StatusConflict, "BAD_STATUS", "Không thu hồi được thẻ ở trạng thái %s", card.Status)
			}
			newStatus = "REVOKED"
			newPending = "REVOKE"
			if req.OnCard {
				newPending, newState = "NONE", "REVOKED"
			}
		}
		_, err = a.db.ExecContext(r.Context(), `UPDATE cards SET status = ?, pending_action = ?, card_state = ?,
			revoked_at = IF(? = 'REVOKED', NOW(), revoked_at) WHERE card_id = ?`,
			newStatus, newPending, newState, newStatus, id)
		if err != nil {
			return err
		}
		detail := "Thực hiện trên thẻ"
		if !req.OnCard {
			detail = "Chỉ cập nhật CSDL, chờ đồng bộ khi thẻ kết nối"
		}
		if req.Reason != "" {
			detail += ". Lý do: " + req.Reason
		}
		a.audit(r, id, adminActor(c), action, true, detail)
		card, err = a.getCard(r.Context(), id)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, card)
		return nil
	}
}

// pendingAfter tính pending_action mới. Nếu đang chờ thao tác ngược lại (vd đang chờ LOCK mà admin
// mở khoá lại), hai thao tác triệt tiêu nhau.
func pendingAfter(current, action, opposite string, onCard bool) string {
	if onCard || current == opposite {
		return "NONE"
	}
	return action
}
