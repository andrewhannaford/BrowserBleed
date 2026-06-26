package handler

import (
	"archive/zip"
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
	"mime"
	"net/http"
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
	Linux   []PayloadMeta
}

func detectPreset(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "chrome"):   return "chrome"
	case strings.HasPrefix(lower, "edge"):     return "edge"
	case strings.HasPrefix(lower, "brave"):    return "brave"
	case strings.HasPrefix(lower, "firefox"):  return "firefox"
	case strings.HasPrefix(lower, "opera"):    return "opera"
	case strings.HasPrefix(lower, "slack"):    return "slack"
	case strings.HasPrefix(lower, "discord"):  return "discord"
	case strings.HasPrefix(lower, "ms-teams"): return "teams"
	case strings.HasPrefix(lower, "zoom"):     return "zoom"
	case strings.HasPrefix(lower, "whatsapp"): return "whatsapp"
	case strings.HasPrefix(lower, "telegram"): return "telegram"
	default:                                   return ""
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
			platform := "linux"
			if strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
				platform = "windows"
			}
			pm := PayloadMeta{Name: e.Name(), Size: fi.Size(), ModTime: fi.ModTime().UTC(), Preset: detectPreset(e.Name()), Platform: platform}
			if platform == "windows" {
				data.Windows = append(data.Windows, pm)
			} else {
				data.Linux = append(data.Linux, pm)
			}
		}
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
