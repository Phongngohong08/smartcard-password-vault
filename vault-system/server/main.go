// Vault server: API cho web quản trị, card agent và app người dùng.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

type App struct {
	cfg        Config
	db         *sql.DB
	secrets    *Secrets
	challenges *challengeStore
}

func main() {
	cfg := loadConfig()
	secrets, err := loadOrCreateSecrets(cfg.SecretsFile)
	if err != nil {
		log.Fatalf("Khoá bí mật: %v", err)
	}
	db, err := openDB(cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		log.Fatalf("Tạo bảng: %v", err)
	}

	app := &App{cfg: cfg, db: db, secrets: secrets, challenges: newChallengeStore(cfg.ChallengeTTL)}
	if err := app.bootstrapAdmin(context.Background()); err != nil {
		log.Fatalf("Tạo admin mặc định: %v", err)
	}

	srv := &http.Server{Addr: cfg.Addr, Handler: logRequests(app.routes()), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("Vault server: http://%s", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	cardScopes := []string{scopeCard}
	anyCard := []string{scopeCard, scopePending}

	mux.Handle("GET /api/health", handler(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, 200, map[string]any{"status": "ok", "time": time.Now()})
		return nil
	}))

	// ---- Admin: đăng nhập, tài khoản
	mux.Handle("POST /api/admin/login", handler(a.handleAdminLogin))
	mux.Handle("GET /api/admin/me", a.admin(a.handleAdminMe))
	mux.Handle("POST /api/admin/password", a.admin(a.handleAdminPassword))

	// ---- Admin: thẻ
	mux.Handle("GET /api/stats", a.admin(a.handleStats))
	mux.Handle("GET /api/cards", a.admin(a.handleListCards))
	mux.Handle("GET /api/cards/next-id", a.admin(a.handleNextCardID))
	mux.Handle("POST /api/cards", a.admin(a.handleRegisterCard))
	mux.Handle("GET /api/cards/{id}", a.admin(a.handleGetCard))
	mux.Handle("DELETE /api/cards/{id}", a.admin(a.handleDeletePendingCard))
	mux.Handle("POST /api/cards/{id}/issue-key", a.admin(a.handleIssueKey))
	mux.Handle("POST /api/cards/{id}/activate", a.admin(a.handleActivate))
	mux.Handle("POST /api/cards/{id}/admin-response", a.admin(a.handleAdminResponse))
	mux.Handle("POST /api/cards/{id}/lock", a.admin(a.handleCardAction("LOCK")))
	mux.Handle("POST /api/cards/{id}/unlock", a.admin(a.handleCardAction("UNLOCK")))
	mux.Handle("POST /api/cards/{id}/revoke", a.admin(a.handleCardAction("REVOKE")))
	mux.Handle("GET /api/logs", a.admin(a.handleListLogs))

	// ---- Thẻ: xác thực RSA (công khai)
	mux.Handle("POST /api/auth/challenge", handler(a.handleCardChallenge))
	mux.Handle("POST /api/auth/verify", handler(a.handleCardVerify))

	// ---- Thẻ: đồng bộ thao tác admin chưa ghi lên thẻ
	mux.Handle("POST /api/cards/{id}/pending/response", a.card(anyCard, a.handlePendingResponse))
	mux.Handle("POST /api/cards/{id}/pending/done", a.card(anyCard, a.handlePendingDone))

	// ---- App người dùng (sau khi thẻ qua RSA)
	mux.Handle("POST /api/app/logs", a.card(cardScopes, a.handleAppLog))
	mux.Handle("POST /api/app/state", a.card(cardScopes, a.handleAppState))
	mux.Handle("GET /api/app/backups", a.card(cardScopes, a.handleAppListBackups))
	mux.Handle("POST /api/app/backups", a.card(cardScopes, a.handleAppCreateBackup))
	mux.Handle("GET /api/app/backups/{bid}", a.card(cardScopes, a.handleAppGetBackup))

	mux.Handle("/api/", handler(func(w http.ResponseWriter, r *http.Request) error {
		return errf(http.StatusNotFound, "NOT_FOUND", "Không có API %s %s", r.Method, r.URL.Path)
	}))
	mux.Handle("/", a.staticHandler())
	return mux
}

// staticHandler phục vụ bản build của web (npm run build) nếu có; đường dẫn lạ trả về index.html (SPA).
func (a *App) staticHandler() http.Handler {
	dir := a.cfg.WebDir
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := filepath.Join(dir, "index.html")
		if _, err := os.Stat(index); err != nil {
			http.Error(w, "Chưa build web. Khi phát triển hãy mở http://localhost:5173 (npm run dev).", http.StatusNotFound)
			return
		}
		p := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			http.ServeFile(w, r, index)
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- nhật ký

// Các giá trị action trong audit_logs.
var userActions = map[string]bool{
	"LOGIN": true, "PIN_FAIL": true, "PIN_BLOCKED": true, "PUK_UNBLOCK": true, "VIEW_PASSWORD": true,
	"COPY_PASSWORD": true, "ADD_ENTRY": true, "EDIT_ENTRY": true, "DELETE_ENTRY": true, "CHANGE_PIN": true,
	"BACKUP": true, "RESTORE": true, "LOGOUT": true, "CARD_DISABLED": true,
}

// audit ghi một dòng nhật ký. detail KHÔNG BAO GIỜ được chứa mật khẩu hay PIN.
func (a *App) audit(r *http.Request, cardID, actor, action string, ok bool, detail string) {
	result := "OK"
	if !ok {
		result = "FAIL"
	}
	if len(detail) > 255 {
		detail = detail[:255]
	}
	_, err := a.db.ExecContext(r.Context(),
		`INSERT INTO audit_logs (card_id, actor, action, result, detail, ip) VALUES (?, ?, ?, ?, ?, ?)`,
		optString(cardID), actor, action, result, optString(detail), clientIP(r))
	if err != nil {
		log.Printf("Ghi nhật ký lỗi: %v", err)
	}
}

func adminActor(c *Claims) string { return "admin:" + c.Subject }
func cardActor(cardID string) string { return "card:" + cardID }
