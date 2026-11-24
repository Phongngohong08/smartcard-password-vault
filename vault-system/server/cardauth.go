package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- xác thực thẻ bằng RSA

// handleCardChallenge: bước 1 mỗi lần cắm thẻ. Thẻ phải có trong CSDL.
func (a *App) handleCardChallenge(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		CardID string `json:"cardId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	id := strings.ToUpper(strings.TrimSpace(req.CardID))
	if !validCardID(id) {
		return errf(http.StatusBadRequest, "BAD_CARD_ID", "Mã thẻ không hợp lệ")
	}
	card, err := a.getCard(r.Context(), id)
	if err != nil {
		if errors.Is(err, errCardNotFound) {
			a.audit(r, "", cardActor(id), "RSA_AUTH", false, "Mã thẻ "+id+" không có trong hệ thống")
		}
		return err
	}
	ch := a.challenges.issue(id)
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":     hex.EncodeToString(ch),
		"expiresIn":     int(a.cfg.ChallengeTTL.Seconds()),
		"status":        card.Status,
		"pendingAction": card.PendingAction,
	})
	return nil
}

// handleCardVerify: bước 2 - kiểm tra chữ ký của thẻ, rồi quyết định có cho thẻ vào hay không.
func (a *App) handleCardVerify(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		CardID    string `json:"cardId"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	id := strings.ToUpper(strings.TrimSpace(req.CardID))
	if !validCardID(id) {
		return errf(http.StatusBadRequest, "BAD_CARD_ID", "Mã thẻ không hợp lệ")
	}
	ch, err := decodeHex("challenge", req.Challenge, challengeLen)
	if err != nil {
		return err
	}
	sig, err := decodeHex("signature", req.Signature, rsaModulusLen)
	if err != nil {
		return err
	}
	card, err := a.getCard(r.Context(), id)
	if err != nil {
		return err
	}
	if !a.challenges.take(id, ch) {
		a.audit(r, id, cardActor(id), "RSA_AUTH", false, "Challenge không hợp lệ hoặc đã hết hạn")
		return errf(http.StatusBadRequest, "BAD_CHALLENGE", "Challenge không hợp lệ hoặc đã hết hạn")
	}
	pub, err := parseRSAPublicKey(card.modulus, card.exponent)
	if err != nil {
		return err
	}
	if err := verifyCardSignature(pub, id, ch, sig); err != nil {
		a.audit(r, id, cardActor(id), "RSA_AUTH", false, "Chữ ký không hợp lệ - nghi thẻ giả")
		return errf(http.StatusUnauthorized, "BAD_SIGNATURE", "Thẻ không vượt qua kiểm tra RSA (nghi thẻ giả)")
	}
	a.audit(r, id, cardActor(id), "RSA_AUTH", true, "")
	_, _ = a.db.ExecContext(r.Context(), `UPDATE cards SET last_seen_at = NOW() WHERE card_id = ?`, id)

	cardInfo := map[string]any{"cardId": card.CardID, "ownerName": card.OwnerName, "status": card.Status}
	switch card.Status {
	case "PENDING":
		return errf(http.StatusForbidden, "CARD_NOT_ACTIVATED", "Thẻ chưa được kích hoạt")
	case "REVOKED", "LOCKED":
		code, msg := "CARD_REVOKED", "Thẻ đã bị thu hồi"
		if card.Status == "LOCKED" {
			code, msg = "CARD_LOCKED", "Thẻ đang bị admin khoá"
		}
		a.audit(r, id, cardActor(id), "LOGIN", false, msg)
		extra := map[string]any{"card": cardInfo, "pendingAction": card.PendingAction}
		if card.PendingAction != "NONE" {
			// Token hạn chế: chỉ đủ để thẻ nhận lệnh khoá / thu hồi đang chờ
			tok, _, err := a.signToken(tokenCard, id, scopePending, a.cfg.ChallengeTTL)
			if err != nil {
				return err
			}
			extra["token"] = tok
		}
		return &apiError{Status: http.StatusForbidden, Code: code, Msg: msg, Extra: extra}
	}

	tok, exp, err := a.signToken(tokenCard, id, scopeCard, a.cfg.CardTokenTTL)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": tok, "expiresAt": exp, "card": cardInfo, "pendingAction": card.PendingAction,
	})
	return nil
}

// ---------------------------------------------------------------- đồng bộ thao tác admin lên thẻ

func tokenCardID(r *http.Request, c *Claims) (string, error) {
	id, err := pathCardID(r)
	if err != nil {
		return "", err
	}
	if id != c.Subject {
		return "", errf(http.StatusForbidden, "WRONG_CARD", "Token không thuộc thẻ này")
	}
	return id, nil
}

// handlePendingResponse: app gửi ADMIN_CHALLENGE của thẻ, server trả phản hồi để app gửi ADMIN_AUTH
// rồi thực hiện thao tác đang chờ. Chỉ trả lời khi thẻ thật sự có thao tác chờ.
func (a *App) handlePendingResponse(w http.ResponseWriter, r *http.Request, c *Claims) error {
	id, err := tokenCardID(r, c)
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
	card, err := a.getCard(r.Context(), id)
	if err != nil {
		return err
	}
	if card.PendingAction == "NONE" {
		return errf(http.StatusConflict, "NO_PENDING", "Thẻ không có thao tác nào đang chờ")
	}
	resp, err := adminResponse(deriveAdminKey(a.secrets.AdminMasterKey, id), ch)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"action": card.PendingAction, "response": hex.EncodeToString(resp)})
	return nil
}

var cardStates = map[string]bool{"ACTIVE": true, "PIN_BLOCKED": true, "ADMIN_LOCKED": true, "REVOKED": true, "DISABLED": true}

// handlePendingDone: app báo đã thực hiện xong thao tác chờ trên thẻ.
func (a *App) handlePendingDone(w http.ResponseWriter, r *http.Request, c *Claims) error {
	id, err := tokenCardID(r, c)
	if err != nil {
		return err
	}
	var req struct {
		Action    string `json:"action"`
		CardState string `json:"cardState"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if !cardStates[req.CardState] {
		return errf(http.StatusBadRequest, "BAD_STATE", "cardState không hợp lệ")
	}
	res, err := a.db.ExecContext(r.Context(), `UPDATE cards SET pending_action = 'NONE', card_state = ?
		WHERE card_id = ? AND pending_action = ?`, req.CardState, id, req.Action)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errf(http.StatusConflict, "NO_PENDING", "Không có thao tác %s đang chờ", req.Action)
	}
	a.audit(r, id, cardActor(id), req.Action, true, "Đồng bộ thao tác admin lên thẻ")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// ---------------------------------------------------------------- app người dùng

func (a *App) handleAppLog(w http.ResponseWriter, r *http.Request, c *Claims) error {
	var req struct {
		Action string `json:"action"`
		Result string `json:"result"`
		Detail string `json:"detail"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if !userActions[req.Action] {
		return errf(http.StatusBadRequest, "BAD_ACTION", "action không hợp lệ")
	}
	if req.Result != "OK" && req.Result != "FAIL" {
		return errf(http.StatusBadRequest, "BAD_RESULT", "result phải là OK hoặc FAIL")
	}
	a.audit(r, c.Subject, cardActor(c.Subject), req.Action, req.Result == "OK", req.Detail)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	return nil
}

func (a *App) handleAppState(w http.ResponseWriter, r *http.Request, c *Claims) error {
	var req struct {
		CardState string `json:"cardState"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if !cardStates[req.CardState] {
		return errf(http.StatusBadRequest, "BAD_STATE", "cardState không hợp lệ")
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE cards SET card_state = ? WHERE card_id = ?`, req.CardState, c.Subject); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}

// backupOwners: thẻ được xem bản sao lưu của chính nó và của thẻ cũ mà nó thay thế.
func (a *App) backupOwners(r *http.Request, cardID string) ([]string, error) {
	owners := []string{cardID}
	var repl sql.NullString
	if err := a.db.QueryRowContext(r.Context(), `SELECT replaces_card_id FROM cards WHERE card_id = ?`, cardID).Scan(&repl); err != nil {
		return nil, err
	}
	if repl.Valid {
		owners = append(owners, repl.String)
	}
	return owners, nil
}

func (a *App) handleAppListBackups(w http.ResponseWriter, r *http.Request, c *Claims) error {
	owners, err := a.backupOwners(r, c.Subject)
	if err != nil {
		return err
	}
	list, err := a.listBackups(r.Context(), owners)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, list)
	return nil
}

var backupMagic = []byte("VBK1")

func (a *App) handleAppCreateBackup(w http.ResponseWriter, r *http.Request, c *Claims) error {
	var req struct {
		Data string `json:"data"` // base64 của file VBK1
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(data) < 4+48+1 || !bytes.HasPrefix(data, backupMagic) || len(data) > 64*1024 {
		return errf(http.StatusBadRequest, "BAD_BACKUP", "Dữ liệu sao lưu không đúng định dạng VBK1")
	}
	entries := int(data[4+48])
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO backups (card_id, entries, size, data) VALUES (?, ?, ?, ?)`,
		c.Subject, entries, len(data), data)
	if err != nil {
		return err
	}
	bid, _ := res.LastInsertId()
	a.audit(r, c.Subject, cardActor(c.Subject), "BACKUP", true, strconv.Itoa(entries)+" bản ghi, "+strconv.Itoa(len(data))+" byte")
	writeJSON(w, http.StatusCreated, map[string]any{"id": bid, "entries": entries, "size": len(data)})
	return nil
}

func (a *App) handleAppGetBackup(w http.ResponseWriter, r *http.Request, c *Claims) error {
	bid, err := strconv.ParseInt(r.PathValue("bid"), 10, 64)
	if err != nil {
		return errf(http.StatusBadRequest, "BAD_ID", "Mã bản sao lưu không hợp lệ")
	}
	owners, err := a.backupOwners(r, c.Subject)
	if err != nil {
		return err
	}
	var owner string
	var data []byte
	err = a.db.QueryRowContext(r.Context(), `SELECT card_id, data FROM backups WHERE id = ?`, bid).Scan(&owner, &data)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !contains(owners, owner)) {
		return errf(http.StatusNotFound, "BACKUP_NOT_FOUND", "Không tìm thấy bản sao lưu")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": bid, "cardId": owner, "data": base64.StdEncoding.EncodeToString(data)})
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
