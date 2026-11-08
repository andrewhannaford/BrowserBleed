package main

import (
	"archive/zip"
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"bb-reports/internal/handler"
)

//go:embed web
var webFS embed.FS

//go:embed extension
var extFS embed.FS

func serveExtensionZip(w http.ResponseWriter, r *http.Request) {
	entries, err := fs.ReadDir(extFS, "extension")
	if err != nil {
		http.Error(w, "extension not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="browserbleed-extension.zip"`)

	zw := zip.NewWriter(w)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(extFS, "extension/"+e.Name())
		if err != nil {
			continue
		}
		f, err := zw.Create(e.Name())
		if err != nil {
			continue
		}
		f.Write(data)
	}
	zw.Close()
}

func main() {
	addr    := flag.String("addr",     ":8080",                os.Getenv("ADDR"))
	apiKey  := flag.String("api-key",  os.Getenv("API_KEY"),   "API key for uploads and browser access")
	encKey  := flag.String("enc-key",  os.Getenv("ENCRYPTION_KEY"), "64-char hex AES-256 key for at-rest encryption - openssl rand -hex 32")
	dataDir := flag.String("data-dir", "/opt/bb-reports/data", "Directory to store reports")
	baseURL := flag.String("base-url", os.Getenv("BASE_URL"),  "Public base URL (e.g. https://reports.yourdomain.com)")
	ttl     := flag.Duration("ttl",    24*time.Hour,           "How long reports are kept (e.g. 24h, 72h)")
	flag.Parse()

	if *addr == "" {
		*addr = ":8080"
	}
	if *apiKey == "" {
		log.Fatal("--api-key is required (or set API_KEY env var)")
	}
	if *encKey == "" {
		log.Fatal("--enc-key is required (or set ENCRYPTION_KEY env var) - generate with: openssl rand -hex 32")
	}

	if err := os.MkdirAll(*dataDir, 0750); err != nil {
		log.Fatalf("cannot create data dir: %v", err)
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("web FS error: %v", err)
	}

	h, err := handler.New(*apiKey, *encKey, *dataDir, *baseURL, *ttl, sub)
	if err != nil {
		log.Fatalf("handler init error: %v", err)
	}
	h.StartCleanup()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.HandleFunc("/extension.zip", serveExtensionZip)

	log.Printf("bb-reports listening on %s, data=%s, ttl=%s", *addr, *dataDir, *ttl)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}
