package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bootstrapAdmin tạo tài khoản admin đầu tiên nếu bảng admins đang trống.
func (a *App) bootstrapAdmin(ctx context.Context) error {
	var n int
	if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(a.cfg.BootstrapPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO admins (username, password_hash) VALUES (?, ?)`,
		a.cfg.BootstrapUser, string(hash)); err != nil {
		return err
	}
	log.Printf("Đã tạo admin mặc định %q / %q - hãy đổi mật khẩu sau khi đăng nhập", a.cfg.BootstrapUser, a.cfg.BootstrapPassword)
	return nil
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.Username = strings.TrimSpace(req.Username)

	var hash string
	err := a.db.QueryRowContext(r.Context(), `SELECT password_hash FROM admins WHERE username = ?`, req.Username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil) {
		a.audit(r, "", "admin:"+req.Username, "ADMIN_LOGIN", false, "Sai tên đăng nhập hoặc mật khẩu")
		return errf(http.StatusUnauthorized, "BAD_LOGIN", "Sai tên đăng nhập hoặc mật khẩu")
	}
	if err != nil {
		return err
	}
	token, exp, err := a.signToken(tokenAdmin, req.Username, "", a.cfg.AdminTokenTTL)
	if err != nil {
		return err
	}
	a.audit(r, "", "admin:"+req.Username, "ADMIN_LOGIN", true, "")
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "username": req.Username, "expiresAt": exp})
	return nil
}

func (a *App) handleAdminMe(w http.ResponseWriter, r *http.Request, c *Claims) error {
	writeJSON(w, http.StatusOK, map[string]any{"username": c.Subject, "expiresAt": c.ExpiresAt.Time})
	return nil
}

func (a *App) handleAdminPassword(w http.ResponseWriter, r *http.Request, c *Claims) error {
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if len(req.NewPassword) < 8 {
		return errf(http.StatusBadRequest, "WEAK_PASSWORD", "Mật khẩu mới phải có ít nhất 8 ký tự")
	}
	var hash string
	if err := a.db.QueryRowContext(r.Context(), `SELECT password_hash FROM admins WHERE username = ?`, c.Subject).Scan(&hash); err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)) != nil {
		return errf(http.StatusBadRequest, "BAD_PASSWORD", "Mật khẩu hiện tại không đúng")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE admins SET password_hash = ? WHERE username = ?`, string(newHash), c.Subject); err != nil {
		return err
	}
	a.audit(r, "", adminActor(c), "ADMIN_PASSWORD", true, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	return nil
}
