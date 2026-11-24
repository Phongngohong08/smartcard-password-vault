package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config đọc từ biến môi trường (hoặc file .env cạnh server). Giá trị mặc định dùng cho máy phát triển.
type Config struct {
	Addr              string
	DSN               string
	SecretsFile       string
	WebDir            string
	BootstrapUser     string
	BootstrapPassword string
	AdminTokenTTL     time.Duration
	CardTokenTTL      time.Duration
	ChallengeTTL      time.Duration
}

func loadConfig() Config {
	loadDotEnv(".env")
	return Config{
		Addr:              env("VAULT_ADDR", "127.0.0.1:8080"),
		DSN:               env("VAULT_DB_DSN", "vault:vault_dev_pw@tcp(127.0.0.1:3306)/vault?parseTime=true&charset=utf8mb4&loc=Local"),
		SecretsFile:       env("VAULT_SECRETS_FILE", "data/secrets.json"),
		WebDir:            env("VAULT_WEB_DIR", "../web/dist"),
		BootstrapUser:     env("VAULT_ADMIN_USER", "admin"),
		BootstrapPassword: env("VAULT_ADMIN_PASSWORD", "admin123"),
		AdminTokenTTL:     8 * time.Hour,
		CardTokenTTL:      30 * time.Minute,
		ChallengeTTL:      2 * time.Minute,
	}
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// loadDotEnv nạp các dòng KEY=VALUE; biến đã có trong môi trường thì giữ nguyên.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, strings.Trim(strings.TrimSpace(v), `"`))
		}
	}
}

// Secrets là các khoá bí mật của server, sinh ngẫu nhiên một lần rồi lưu vào file.
//   - JWTSecret: ký token đăng nhập.
//   - AdminMasterKey: khoá chủ để dẫn xuất adminKey riêng cho từng thẻ.
//     MẤT FILE NÀY = không còn quản trị (khoá / thu hồi trên thẻ) được các thẻ đã phát hành.
type Secrets struct {
	JWTSecret      []byte
	AdminMasterKey []byte
}

type secretsFile struct {
	Note           string `json:"note"`
	JWTSecret      string `json:"jwtSecret"`
	AdminMasterKey string `json:"adminMasterKey"`
}

func loadOrCreateSecrets(path string) (*Secrets, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		sf := secretsFile{
			Note:           "Khoa bi mat cua Vault server. Hay sao luu file nay; mat no thi khong quan tri duoc cac the da phat hanh.",
			JWTSecret:      randomHex(32),
			AdminMasterKey: randomHex(32),
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		out, _ := json.MarshalIndent(sf, "", "  ")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return nil, err
		}
		log.Printf("Đã tạo file khoá bí mật mới: %s (hãy sao lưu file này)", path)
		b = out
	} else if err != nil {
		return nil, err
	}
	var sf secretsFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return nil, fmt.Errorf("đọc %s: %w", path, err)
	}
	jwtKey, err1 := hex.DecodeString(sf.JWTSecret)
	master, err2 := hex.DecodeString(sf.AdminMasterKey)
	if err1 != nil || err2 != nil || len(jwtKey) < 32 || len(master) < 16 {
		return nil, fmt.Errorf("file %s không hợp lệ", path)
	}
	return &Secrets{JWTSecret: jwtKey, AdminMasterKey: master}, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
