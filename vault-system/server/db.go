package main

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

//go:embed schema.sql
var schemaSQL string

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	var lastErr error
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		lastErr = db.PingContext(ctx)
		cancel()
		if lastErr == nil {
			return db, nil
		}
		log.Printf("Chưa kết nối được MySQL (%v), thử lại...", lastErr)
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("không kết nối được MySQL: %w", lastErr)
}

// migrate chạy từng câu lệnh trong schema.sql (các câu đều là CREATE ... IF NOT EXISTS).
func migrate(db *sql.DB) error {
	for _, stmt := range strings.Split(stripComments(schemaSQL), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("%w\n%s", err, stmt)
		}
	}
	return nil
}

func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func nullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func nullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

// optString chuyển chuỗi rỗng thành NULL khi ghi vào CSDL.
func optString(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}
