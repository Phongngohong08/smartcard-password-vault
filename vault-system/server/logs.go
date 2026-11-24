package main

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type LogEntry struct {
	ID        int64     `json:"id"`
	CardID    *string   `json:"cardId"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	Detail    *string   `json:"detail"`
	IP        *string   `json:"ip"`
	CreatedAt time.Time `json:"createdAt"`
}

type logFilter struct {
	CardID, Action, Result, Actor, From, To string
	Page, Size                              int
}

type logPage struct {
	Items []LogEntry `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

func (a *App) queryLogs(ctx context.Context, f logFilter) (*logPage, error) {
	where := ` WHERE 1=1`
	var args []any
	add := func(cond string, v any) {
		where += ` AND ` + cond
		args = append(args, v)
	}
	if f.CardID != "" {
		add(`card_id = ?`, strings.ToUpper(f.CardID))
	}
	if f.Action != "" {
		add(`action = ?`, f.Action)
	}
	if f.Result != "" {
		add(`result = ?`, f.Result)
	}
	if f.Actor != "" {
		add(`actor LIKE ?`, "%"+f.Actor+"%")
	}
	if f.From != "" {
		add(`created_at >= ?`, f.From)
	}
	if f.To != "" {
		add(`created_at < DATE_ADD(?, INTERVAL 1 DAY)`, f.To)
	}
	if f.Size <= 0 || f.Size > 200 {
		f.Size = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	p := &logPage{Items: []LogEntry{}, Page: f.Page, Size: f.Size}
	if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs`+where, args...).Scan(&p.Total); err != nil {
		return nil, err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id, card_id, actor, action, result, detail, ip, created_at FROM audit_logs`+
		where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Size, (f.Page-1)*f.Size)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e LogEntry
		var card, detail, ip sql.NullString
		if err := rows.Scan(&e.ID, &card, &e.Actor, &e.Action, &e.Result, &detail, &ip, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.CardID, e.Detail, e.IP = nullString(card), nullString(detail), nullString(ip)
		p.Items = append(p.Items, e)
	}
	return p, rows.Err()
}

func (a *App) handleListLogs(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	p, err := a.queryLogs(r.Context(), logFilter{
		CardID: q.Get("cardId"), Action: q.Get("action"), Result: q.Get("result"), Actor: q.Get("actor"),
		From: q.Get("from"), To: q.Get("to"), Page: page, Size: size,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, p)
	return nil
}

type BackupInfo struct {
	ID        int64     `json:"id"`
	CardID    string    `json:"cardId"`
	Entries   int       `json:"entries"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

func (a *App) listBackups(ctx context.Context, cardIDs []string) ([]BackupInfo, error) {
	list := []BackupInfo{}
	if len(cardIDs) == 0 {
		return list, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(cardIDs)), ",")
	args := make([]any, len(cardIDs))
	for i, id := range cardIDs {
		args[i] = id
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id, card_id, entries, size, created_at FROM backups
		WHERE card_id IN (`+ph+`) ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b BackupInfo
		if err := rows.Scan(&b.ID, &b.CardID, &b.Entries, &b.Size, &b.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, b)
	}
	return list, rows.Err()
}

// handleStats: số liệu cho trang tổng quan.
func (a *App) handleStats(w http.ResponseWriter, r *http.Request, _ *Claims) error {
	ctx := r.Context()
	cards := map[string]int{"PENDING": 0, "ACTIVE": 0, "LOCKED": 0, "REVOKED": 0}
	rows, err := a.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM cards GROUP BY status`)
	if err != nil {
		return err
	}
	total := 0
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			rows.Close()
			return err
		}
		cards[s] = n
		total += n
	}
	rows.Close()

	var pendingSync, pinBlocked int
	if err := a.db.QueryRowContext(ctx, `SELECT
			COALESCE(SUM(pending_action <> 'NONE'), 0),
			COALESCE(SUM(card_state = 'PIN_BLOCKED'), 0) FROM cards`).Scan(&pendingSync, &pinBlocked); err != nil {
		return err
	}

	var events, rsaFail, pinFail, logins int
	if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*),
			COALESCE(SUM(action = 'RSA_AUTH' AND result = 'FAIL'), 0),
			COALESCE(SUM(action = 'PIN_FAIL'), 0),
			COALESCE(SUM(action = 'LOGIN' AND result = 'OK'), 0)
		FROM audit_logs WHERE created_at >= NOW() - INTERVAL 1 DAY`).Scan(&events, &rsaFail, &pinFail, &logins); err != nil {
		return err
	}

	// 7 ngày gần nhất, kể cả ngày không có sự kiện
	type day struct {
		Date string `json:"date"`
		OK   int    `json:"ok"`
		Fail int    `json:"fail"`
	}
	byDate := map[string]*day{}
	days := make([]*day, 7)
	for i := range days {
		d := time.Now().AddDate(0, 0, i-6).Format("2006-01-02")
		days[i] = &day{Date: d}
		byDate[d] = days[i]
	}
	drows, err := a.db.QueryContext(ctx, `SELECT DATE_FORMAT(created_at, '%Y-%m-%d') d, SUM(result = 'OK'), SUM(result = 'FAIL')
		FROM audit_logs WHERE created_at >= CURDATE() - INTERVAL 6 DAY GROUP BY d`)
	if err != nil {
		return err
	}
	for drows.Next() {
		var d string
		var ok, fail int
		if err := drows.Scan(&d, &ok, &fail); err != nil {
			drows.Close()
			return err
		}
		if x := byDate[d]; x != nil {
			x.OK, x.Fail = ok, fail
		}
	}
	drows.Close()

	recent, err := a.queryLogs(ctx, logFilter{Size: 10, Page: 1})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cards":       map[string]any{"total": total, "byStatus": cards, "pendingSync": pendingSync, "pinBlocked": pinBlocked},
		"last24h":     map[string]int{"events": events, "rsaFail": rsaFail, "pinFail": pinFail, "logins": logins},
		"daily":       days,
		"recentLogs":  recent.Items,
	})
	return nil
}
