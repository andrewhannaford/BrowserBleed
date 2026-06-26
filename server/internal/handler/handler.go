package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type ReportMeta struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	UploadedAt time.Time `json:"uploaded_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	RunAt      string    `json:"run_at"`
	HitCount   string    `json:"hit_count"`
	HasCSV     bool      `json:"has_csv"`
}

type PayloadMeta struct {
	Name       string
	Size       int64
	ModifiedAt time.Time
}

var (
	reID          = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reRunAt       = regexp.MustCompile(`Run:\s+(.+)`)
	reHits        = regexp.MustCompile(`\[\+\] (\d+ unique hit\(s\)[^\n]*)`)
	rePayloadName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
)

func validPayloadName(name string) bool {
	return rePayloadName.MatchString(name) && !strings.HasPrefix(name, ".")
}

type Handler struct {
	apiKey      string
	encKey      []byte
	dataDir     string
	baseURL     string
	ttl         time.Duration
	indexTpl    *template.Template
	reportTpl   *template.Template
	loginTpl    *template.Template
	payloadsTpl *template.Template
	payloadsDir string
	mu          sync.Mutex
}

func deriveKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be a 64-char hex string (32 bytes) - generate with: openssl rand -hex 32")
	}
	return key, nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func New(apiKey, encKeyHex, dataDir, baseURL string, ttl time.Duration, webFS fs.FS) (*Handler, error) {
	encKey, err := deriveKey(encKeyHex)
	if err != nil {
		return nil, err
	}

	funcMap := template.FuncMap{
		"fmtTime": func(t time.Time) string {
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"fmtSize": func(n int64) string {
			switch {
			case n < 1024:
				return fmt.Sprintf("%d B", n)
			case n < 1024*1024:
				return fmt.Sprintf("%.1f KB", float64(n)/1024)
			default:
				return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
			}
		},
		"guessPreset": func(name string) string {
			n := strings.ToLower(name)
			switch {
			case strings.Contains(n, "chrome"):
				return "chrome"
			case strings.Contains(n, "edge") || strings.Contains(n, "msedge"):
				return "edge"
			case strings.Contains(n, "brave"):
				return "brave"
			case strings.Contains(n, "firefox") || strings.Contains(n, "plugin-container"):
				return "firefox"
			case strings.Contains(n, "opera"):
				return "opera"
			case strings.Contains(n, "slack"):
				return "slack"
			case strings.Contains(n, "discord"):
				return "discord"
			case strings.Contains(n, "teams"):
				return "teams"
			case strings.Contains(n, "zoom"):
				return "zoom"
			case strings.Contains(n, "whatsapp"):
				return "whatsapp"
			case strings.Contains(n, "telegram"):
				return "telegram"
			default:
				return ""
			}
		},
	}

	indexTpl, err := template.New("index.html").Funcs(funcMap).ParseFS(webFS, "index.html")
	if err != nil {
		return nil, err
	}
	reportTpl, err := template.New("report.html").Funcs(funcMap).ParseFS(webFS, "report.html")
	if err != nil {
		return nil, err
	}
	loginTpl, err := template.New("login.html").Funcs(funcMap).ParseFS(webFS, "login.html")
	if err != nil {
		return nil, err
	}
	payloadsTpl, err := template.New("payloads.html").Funcs(funcMap).ParseFS(webFS, "payloads.html")
	if err != nil {
		return nil, err
	}

	payloadsDir := filepath.Join(dataDir, "payloads")
	if err := os.MkdirAll(payloadsDir, 0750); err != nil {
		return nil, err
	}

	return &Handler{
		apiKey:      apiKey,
		encKey:      encKey,
		dataDir:     dataDir,
		baseURL:     strings.TrimRight(baseURL, "/"),
		ttl:         ttl,
		indexTpl:    indexTpl,
		reportTpl:   reportTpl,
		loginTpl:    loginTpl,
		payloadsTpl: payloadsTpl,
		payloadsDir: payloadsDir,
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/upload", h.handleUpload)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/r/", h.handleReport)
	mux.HandleFunc("/payloads/", h.handlePayload)
	mux.HandleFunc("/payloads", h.handlePayloads)
	mux.HandleFunc("/", h.handleIndex)
}

// StartCleanup launches the expiry goroutine. Call after New.
func (h *Handler) StartCleanup() {
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			h.deleteExpired()
		}
	}()
}

func (h *Handler) deleteExpired() {
	entries, err := os.ReadDir(h.dataDir)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !reID.MatchString(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.dataDir, id, "meta.json"))
		if err != nil {
			continue
		}
		var m ReportMeta
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if !m.ExpiresAt.IsZero() && now.After(m.ExpiresAt) {
			log.Printf("[cleanup] expiring report %s (hostname=%s)", id, m.Hostname)
			os.RemoveAll(filepath.Join(h.dataDir, id))
		}
	}
}

func (h *Handler) bearerAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == h.apiKey
}

func (h *Handler) cookieAuth(r *http.Request) bool {
	c, err := r.Cookie("bb_key")
	return err == nil && c.Value == h.apiKey
}

func (h *Handler) isAPIRequest(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" ||
		strings.Contains(r.Header.Get("Accept"), "application/json")
}

// requireAuth checks Bearer or cookie. If not authenticated, returns false
// and sends appropriate response (401 for API, redirect for browser).
func (h *Handler) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if h.bearerAuth(r) || h.cookieAuth(r) {
		return true
	}
	if h.isAPIRequest(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return false
}

func (h *Handler) setSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "bb_key",
		Value:    h.apiKey,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		// No MaxAge / Expires = session cookie
	})
}

func (h *Handler) reportURL(r *http.Request, id string) string {
	base := h.baseURL
	if base == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/r/" + id
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	type loginData struct{ Error string }
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.loginTpl.Execute(w, loginData{})
	case http.MethodPost:
		r.ParseForm()
		key := r.FormValue("key")
		if key == h.apiKey {
			h.setSessionCookie(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		h.loginTpl.Execute(w, loginData{Error: "Invalid API key."})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.bearerAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	hostname := r.FormValue("hostname")

	txtFile, _, err := r.FormFile("txt")
	if err != nil {
		http.Error(w, "missing txt file", http.StatusBadRequest)
		return
	}
	defer txtFile.Close()
	txtData, err := io.ReadAll(txtFile)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id := hex.EncodeToString(idBytes)

	dir := filepath.Join(h.dataDir, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Encrypt and write txt
	encTxt, err := encrypt(h.encKey, txtData)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "results.txt.enc"), encTxt, 0600); err != nil {
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}

	// Encrypt and write csv if present
	hasCSV := false
	if csvFile, _, err := r.FormFile("csv"); err == nil {
		defer csvFile.Close()
		csvData, _ := io.ReadAll(csvFile)
		if len(csvData) > 0 {
			encCSV, err := encrypt(h.encKey, csvData)
			if err == nil {
				os.WriteFile(filepath.Join(dir, "results.csv.enc"), encCSV, 0600)
				hasCSV = true
			}
		}
	}

	// Parse metadata from plaintext (in memory only - never written unencrypted)
	txtStr := string(txtData)
	runAt := ""
	if m := reRunAt.FindStringSubmatch(txtStr); len(m) > 1 {
		runAt = strings.TrimSpace(m[1])
	}
	hitCount := ""
	if m := reHits.FindStringSubmatch(txtStr); len(m) > 1 {
		hitCount = strings.TrimSpace(m[1])
	}

	now := time.Now().UTC()
	meta := ReportMeta{
		ID:         id,
		Hostname:   hostname,
		UploadedAt: now,
		ExpiresAt:  now.Add(h.ttl),
		RunAt:      runAt,
		HitCount:   hitCount,
		HasCSV:     hasCSV,
	}
	metaBytes, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(dir, "meta.json"), metaBytes, 0640)

	log.Printf("[upload] id=%s hostname=%s hits=%s expires=%s", id, hostname, hitCount, meta.ExpiresAt.Format(time.RFC3339))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":  id,
		"url": h.reportURL(r, id),
	})
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}

	entries, _ := os.ReadDir(h.dataDir)
	var reports []ReportMeta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !reID.MatchString(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.dataDir, id, "meta.json"))
		if err != nil {
			continue
		}
		var m ReportMeta
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		reports = append(reports, m)
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].UploadedAt.After(reports[j].UploadedAt)
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.indexTpl.Execute(w, reports)
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/r/"), "/", 2)
	id := parts[0]
	if !reID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	dir := filepath.Join(h.dataDir, id)

	// Raw file downloads - decrypt and stream
	if len(parts) == 2 {
		switch parts[1] {
		case "results.txt":
			h.serveDecrypted(w, r, filepath.Join(dir, "results.txt.enc"), "text/plain; charset=utf-8", "results.txt")
		case "results.csv":
			h.serveDecrypted(w, r, filepath.Join(dir, "results.csv.enc"), "text/csv; charset=utf-8", "results.csv")
		default:
			http.NotFound(w, r)
		}
		return
	}

	metaData, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var meta ReportMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	enc, err := os.ReadFile(filepath.Join(dir, "results.txt.enc"))
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	content, err := decrypt(h.encKey, enc)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}

	type reportPage struct {
		Meta    ReportMeta
		Content string
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.reportTpl.Execute(w, reportPage{Meta: meta, Content: string(content)})
}

func (h *Handler) serveDecrypted(w http.ResponseWriter, r *http.Request, encPath, contentType, filename string) {
	enc, err := os.ReadFile(encPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	plain, err := decrypt(h.encKey, enc)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Write(plain)
}

// ── Payload handlers ───────────────────────────────────────────────────────────

func (h *Handler) listPayloads() []PayloadMeta {
	h.mu.Lock()
	defer h.mu.Unlock()
	entries, err := os.ReadDir(h.payloadsDir)
	if err != nil {
		return nil
	}
	var payloads []PayloadMeta
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !validPayloadName(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		payloads = append(payloads, PayloadMeta{
			Name:       name,
			Size:       info.Size(),
			ModifiedAt: info.ModTime().UTC(),
		})
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].ModifiedAt.After(payloads[j].ModifiedAt)
	})
	return payloads
}

func (h *Handler) handlePayloads(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		payloads := h.listPayloads()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.payloadsTpl.Execute(w, payloads)
	case http.MethodPost:
		h.doPayloadUpload(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) doPayloadUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f, fh, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer f.Close()

	// Use explicit name param if given, else fall back to upload filename
	name := fh.Filename
	if n := r.FormValue("name"); n != "" {
		name = n
	}
	if !validPayloadName(name) {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	outPath := filepath.Join(h.payloadsDir, name)

	h.mu.Lock()
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		h.mu.Unlock()
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
	_, copyErr := io.Copy(out, f)
	out.Close()
	h.mu.Unlock()

	if copyErr != nil {
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}

	log.Printf("[payload] uploaded name=%s size=%d", name, fh.Size)

	if !h.isAPIRequest(r) {
		http.Redirect(w, r, "/payloads", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"name": name, "status": "ok"})
}

func (h *Handler) handlePayload(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/payloads/")
	parts := strings.SplitN(path, "/", 2)
	name := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	if !validPayloadName(name) {
		http.NotFound(w, r)
		return
	}

	filePath := filepath.Join(h.payloadsDir, name)

	switch action {
	case "":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		f, err := os.Open(filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		io.Copy(w, f)

	case "delete":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.mu.Lock()
		err := os.Remove(filePath)
		h.mu.Unlock()
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		log.Printf("[payload] deleted name=%s", name)
		http.Redirect(w, r, "/payloads", http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}
}
