package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

const (
	decayExp  = 2
	minIDLen  = 4
	maxIDLen  = 24
	maxExtLen = 7
	storePath = "/data/files/"
	logPath   = "/data/uploads.log"
	filePrefix = "/f/"
)

var (
	cfgMaxFilesizeMiB int // MAX_FILESIZE (MiB)
	cfgMaxFileAgeDays int // MAX_FILE_AGE (days)
	cfgMinFileAgeDays int // MIN_FILE_AGE (days)
	cfgRequireAuth    bool // REQUIRE_AUTH (true/false); default: true when UPLOAD_TOKEN is set
)

func loadConfig() {
	cfgMaxFilesizeMiB = envInt("MAX_FILESIZE", 256)
	cfgMaxFileAgeDays = envInt("MAX_FILE_AGE", 30)
	cfgMinFileAgeDays = envInt("MIN_FILE_AGE", 3)

	// Defaults to true when UPLOAD_TOKEN is set; REQUIRE_AUTH=false overrides.
	if v := os.Getenv("REQUIRE_AUTH"); v != "" {
		cfgRequireAuth = v != "false" && v != "0"
	} else {
		cfgRequireAuth = os.Getenv("UPLOAD_TOKEN") != ""
	}
}

var allowedExts = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true,
	"webp": true, "avif": true, "heic": true,
	"pdf":  true,
	"txt":  true, "md": true, "csv": true, "log": true, "json": true,
}

// Formats served inline; all others force download. Only re-encoded rasters are
// safe for inline rendering — raw formats may carry active content.
var inlineExts = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true,
}

// Expected MIME prefix per extension; empty = skip check (not reliably detected).
var extMIME = map[string]string{
	"jpg": "image/jpeg", "jpeg": "image/jpeg",
	"png":  "image/png",
	"gif":  "image/gif",
	"webp": "image/webp",
	"avif": "",   // ISOBMFF-based; DetectContentType returns octet-stream
	"heic": "",   // ISOBMFF-based; same issue
	"pdf":  "application/pdf",
	"txt":  "text/", "md": "text/", "csv": "text/", "log": "text/",
	"json": "text/", // DetectContentType returns text/plain for JSON
}

// Validates stored filenames: alphanum ID + dot + ext.
var safeBasename = regexp.MustCompile(`^[A-Za-z0-9_\-]+\.[a-z0-9]{1,7}$`)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// ── Sessions (in-memory, single process) ─────────────────────────────────────

const sessionTTL = 8 * time.Hour

type sessionData struct {
	expiry    time.Time
	csrfToken string
}

var sessions sync.Map // token(string) → sessionData

// ── Login rate limiting ───────────────────────────────────────────────────────

const maxLoginAttempts = 10

type loginAttempt struct {
	count int
	last  time.Time
}

var (
	loginFails   = make(map[string]loginAttempt)
	loginFailsMu sync.Mutex
)

func checkLoginRateLimit(ip string) bool {
	loginFailsMu.Lock()
	defer loginFailsMu.Unlock()
	a, ok := loginFails[ip]
	if !ok {
		return true
	}
	// Reset after 1h of inactivity.
	if time.Since(a.last) > time.Hour {
		delete(loginFails, ip)
		return true
	}
	return a.count < maxLoginAttempts
}

func recordLoginFail(ip string) {
	loginFailsMu.Lock()
	defer loginFailsMu.Unlock()
	a := loginFails[ip] // zero value if not present
	a.count++
	a.last = time.Now()
	loginFails[ip] = a
}

func clearLoginFail(ip string) {
	loginFailsMu.Lock()
	defer loginFailsMu.Unlock()
	delete(loginFails, ip)
}

func init() {
	go func() {
		for range time.Tick(30 * time.Minute) {
			now := time.Now()
			sessions.Range(func(k, v any) bool {
				if now.After(v.(sessionData).expiry) {
					sessions.Delete(k)
				}
				return true
			})
			// Evict loginFails entries older than 1h.
			loginFailsMu.Lock()
			for k, v := range loginFails {
				if now.Sub(v.last) > time.Hour {
					delete(loginFails, k)
				}
			}
			loginFailsMu.Unlock()
		}
	}()
}

func newSession() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)

	// Generate CSRF token
	cb := make([]byte, 32)
	if _, err := rand.Read(cb); err != nil {
		panic(err)
	}
	csrf := hex.EncodeToString(cb)

	sessions.Store(tok, sessionData{
		expiry:    time.Now().Add(sessionTTL),
		csrfToken: csrf,
	})
	return tok
}

func isAdmin(r *http.Request) bool {
	c, err := r.Cookie("drop_session")
	if err != nil {
		return false
	}
	v, ok := sessions.Load(c.Value)
	if !ok {
		return false
	}
	if time.Now().After(v.(sessionData).expiry) {
		sessions.Delete(c.Value)
		return false
	}
	return true
}

func destroySession(r *http.Request) {
	if c, err := r.Cookie("drop_session"); err == nil {
		sessions.Delete(c.Value)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	out := make([]byte, n)
	for i, v := range b {
		out[i] = idAlphabet[int(v)%len(idAlphabet)]
	}
	return string(out)
}

// retentionDays returns how many days a file of the given size should live.
// Formula: MIN + (MAX - MIN) * (1 - size/MAX_SIZE)^EXP
func retentionDays(size int64) float64 {
	maxBytes := int64(cfgMaxFilesizeMiB) * 1024 * 1024
	ratio := float64(size) / float64(maxBytes)
	if ratio > 1 {
		ratio = 1
	}
	p := 1.0 - ratio
	for i := 1; i < decayExp; i++ {
		p *= (1.0 - ratio)
	}
	return float64(cfgMinFileAgeDays) + float64(cfgMaxFileAgeDays-cfgMinFileAgeDays)*p
}

func fmtSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func fmtAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func clientIP(r *http.Request) string {
	// X-Real-IP is set by nginx from $remote_addr; X-Forwarded-For is client-controlled.
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return r.RemoteAddr
}

func siteURL(r *http.Request) string {
	if s := os.Getenv("SITE_URL"); s != "" {
		return strings.TrimSuffix(s, "/")
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func plainErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, "Error %d: %s\n", code, msg)
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ── Upload ────────────────────────────────────────────────────────────────────

func handleUpload(w http.ResponseWriter, r *http.Request) {
	// Body size cap must be installed before any body reads.
	r.Body = http.MaxBytesReader(w, r.Body, int64(cfgMaxFilesizeMiB+2)*1024*1024)

	// Check auth headers first; form token checked post-ParseMultipartForm.
	uploadToken := os.Getenv("UPLOAD_TOKEN")
	if cfgRequireAuth && uploadToken == "" {
		// Empty token would match any empty form value — treat as misconfiguration.
		plainErr(w, http.StatusInternalServerError,
			"Server misconfiguration: UPLOAD_TOKEN must be set when REQUIRE_AUTH is true")
		return
	}
	needFormToken := false
	if cfgRequireAuth {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if !secureEqual(strings.TrimPrefix(auth, "Bearer "), uploadToken) {
				plainErr(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
		} else if h := r.Header.Get("X-Upload-Token"); h != "" {
			if !secureEqual(h, uploadToken) {
				plainErr(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
		} else {
			// No header token; fall through to form field check.
			needFormToken = true
		}
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		plainErr(w, http.StatusBadRequest, "Bad request: "+err.Error())
		return
	}

	// Browser form token check.
	if needFormToken && !secureEqual(r.FormValue("token"), uploadToken) {
		plainErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	f, hdr, err := r.FormFile("file")
	if err != nil {
		plainErr(w, http.StatusBadRequest, "No file provided")
		return
	}
	defer f.Close()

	if hdr.Size == 0 {
		plainErr(w, http.StatusBadRequest, "Empty file")
		return
	}
	if hdr.Size > int64(cfgMaxFilesizeMiB)*1024*1024 {
		plainErr(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("File exceeds %d MiB limit", cfgMaxFilesizeMiB))
		return
	}

	rawExt := strings.ToLower(filepath.Ext(hdr.Filename))
	if rawExt == "" {
		plainErr(w, http.StatusBadRequest, "File has no extension")
		return
	}
	ext := strings.TrimPrefix(rawExt, ".")
	if len(ext) > maxExtLen || !allowedExts[ext] {
		plainErr(w, http.StatusBadRequest, "File type not allowed")
		return
	}

	// Sniff MIME from first 512 bytes, then seek back.
	sniff := make([]byte, 512)
	nr, _ := f.Read(sniff)
	detected := http.DetectContentType(sniff[:nr])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		plainErr(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if expected := extMIME[ext]; expected != "" {
		if !strings.HasPrefix(detected, expected) {
			plainErr(w, http.StatusBadRequest,
				fmt.Sprintf("MIME type mismatch (got %q)", detected))
			return
		}
	}

	idLen := minIDLen
	if v := r.FormValue("id_length"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= minIDLen && n <= maxIDLen {
			idLen = n
		}
	}
	basename := randID(idLen) + "." + ext
	if !safeBasename.MatchString(basename) {
		plainErr(w, http.StatusInternalServerError, "Internal error")
		return
	}
	dest := storePath + basename

	// Re-encode JPEG/PNG/GIF to strip EXIF; raw copy for all others.
	if err := writeUploaded(f, dest, ext); err != nil {
		log.Printf("upload write error: %v", err)
		os.Remove(dest)
		plainErr(w, http.StatusInternalServerError, "Could not save file")
		return
	}
	os.Chmod(dest, 0644)

	// Token is never logged.
	if fi, err := os.Stat(dest); err == nil {
		appendLog(r, fi.Size(), hdr.Filename, basename)
	}

	url := siteURL(r) + filePrefix + basename
	isCLI := r.FormValue("formatted") == "" &&
		!strings.Contains(r.Header.Get("Accept"), "text/html")
	if isCLI {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, url)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w,
			`<!doctype html><html><head><meta charset="utf-8"><title>drop</title>`+
				`<style>body{background:#111;color:#ccc;font-family:monospace;padding:2em}a{color:#5af}</style></head>`+
				`<body><p>Uploaded: <a href="%s">%s</a></p></body></html>`,
			template.HTMLEscapeString(url), template.HTMLEscapeString(url))
	}
}

// 50 MP cap on decoded pixel area; guards against decompression-bomb DoS.
const maxImagePixels = 50_000_000

// Semaphore to limit concurrent image processing (prevents OOM).
var imageProcSem = make(chan struct{}, 4)

// writeUploaded re-encodes JPEG/PNG/GIF to strip EXIF; falls back to raw copy on decode error.
func writeUploaded(src io.ReadSeeker, dest, ext string) error {
	// Check dimensions before full decode; image.DecodeConfig reads header only.
	switch ext {
	case "jpg", "jpeg", "png", "gif":
		cfg, _, err := image.DecodeConfig(src)
		if err == nil && int64(cfg.Width)*int64(cfg.Height) > maxImagePixels {
			return fmt.Errorf("image dimensions %dx%d exceed %d MP limit",
				cfg.Width, cfg.Height, maxImagePixels/1_000_000)
		}
		if _, serr := src.Seek(0, io.SeekStart); serr != nil {
			return serr
		}
	}

	switch ext {
	case "jpg", "jpeg":
		imageProcSem <- struct{}{}
		defer func() { <-imageProcSem }()

		img, err := jpeg.Decode(src)
		if err != nil {
			if _, serr := src.Seek(0, io.SeekStart); serr != nil {
				return serr
			}
			return rawCopy(src, dest)
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()
		return jpeg.Encode(out, img, &jpeg.Options{Quality: 92})

	case "png":
		imageProcSem <- struct{}{}
		defer func() { <-imageProcSem }()

		img, err := png.Decode(src)
		if err != nil {
			if _, serr := src.Seek(0, io.SeekStart); serr != nil {
				return serr
			}
			return rawCopy(src, dest)
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()
		return png.Encode(out, img)

	case "gif":
		imageProcSem <- struct{}{}
		defer func() { <-imageProcSem }()

		g, err := gif.DecodeAll(src)
		if err != nil {
			if _, serr := src.Seek(0, io.SeekStart); serr != nil {
				return serr
			}
			return rawCopy(src, dest)
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()
		return gif.EncodeAll(out, g)

	default:
		return rawCopy(src, dest)
	}
}

func rawCopy(src io.Reader, dest string) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// ── Logging ───────────────────────────────────────────────────────────────────

// sanitizeLogField strips characters that would corrupt the TSV log or allow
// log injection: newlines, carriage returns, tabs, and null bytes.
func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == '\x00' {
			return ' '
		}
		return r
	}, s)
}

func appendLog(r *http.Request, size int64, origName, stored string) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\t%s\t%d\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339),
		clientIP(r), size, sanitizeLogField(origName), stored)
}

// ── Purge ─────────────────────────────────────────────────────────────────────

// purgeDecay removes files whose age exceeds the decay-formula retention period.
func purgeDecay() int {
	entries, err := os.ReadDir(storePath)
	if err != nil {
		return 0
	}
	n := 0
	now := time.Now()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		age := now.Sub(info.ModTime()).Hours() / 24
		if age > retentionDays(info.Size()) {
			os.Remove(filepath.Join(storePath, e.Name()))
			n++
		}
	}
	return n
}

// purgeOlderThan removes files older than the given number of days.
func purgeOlderThan(days int) (int, int64) {
	entries, err := os.ReadDir(storePath)
	if err != nil {
		return 0, 0
	}
	var count int
	var freed int64
	now := time.Now()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()).Hours()/24 > float64(days) {
			freed += info.Size()
			os.Remove(filepath.Join(storePath, e.Name()))
			count++
		}
	}
	return count, freed
}

// ── Background cleaner ────────────────────────────────────────────────────────

const (
	diskHighWatermark = 90 // eviction trigger (%)
	diskLowWatermark  = 80 // eviction target (%); gap prevents thrashing
)

func diskUsagePct() (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(storePath, &stat); err != nil {
		return 0, err
	}
	if stat.Blocks == 0 {
		return 0, nil
	}
	total := stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize) // Bavail = unprivileged free space
	return float64(total-avail) / float64(total) * 100, nil
}

// evictOldest deletes oldest files until disk usage drops below diskLowWatermark.
func evictOldest() int {
	entries, err := os.ReadDir(storePath)
	if err != nil {
		return 0
	}
	type fi struct {
		name  string
		mtime time.Time
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{e.Name(), info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].mtime.Before(files[j].mtime)
	})
	n := 0
	for _, f := range files {
		pct, err := diskUsagePct()
		if err != nil || pct < float64(diskLowWatermark) {
			break
		}
		if err := os.Remove(filepath.Join(storePath, f.name)); err == nil {
			log.Printf("cleaner: evicted %s under disk pressure", f.name)
			n++
		}
	}
	return n
}

// startCleaner runs hourly: age-based purge via purgeDecay, then disk-pressure
// eviction if usage exceeds diskHighWatermark.
func startCleaner() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		if n := purgeDecay(); n > 0 {
			log.Printf("cleaner: purged %d age-expired files", n)
		}
		pct, err := diskUsagePct()
		if err != nil {
			log.Printf("cleaner: disk stat error: %v", err)
			continue
		}
		if pct >= float64(diskHighWatermark) {
			log.Printf("cleaner: disk %.0f%% full (>%d%%), evicting oldest files",
				pct, diskHighWatermark)
			n := evictOldest()
			after, _ := diskUsagePct()
			log.Printf("cleaner: evicted %d files under disk pressure, disk now %.0f%%",
				n, after)
		}
	}
}

// ── File serving ──────────────────────────────────────────────────────────────

func handleFiles(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, filePrefix)
	if name == "" || !safeBasename.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Frame-Options", "DENY")

	// Only re-encoded rasters are safe inline; force download for everything else.
	// name is regex-validated so embedding in the filename attribute is safe.
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	if inlineExts[ext] {
		w.Header().Set("Content-Disposition", "inline")
	} else {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}

	http.ServeFile(w, r, storePath+name)
}

// ── Admin panel ───────────────────────────────────────────────────────────────

type fileRow struct {
	Name, Size, Age, ExpiresIn string
}

type adminData struct {
	LoggedIn   bool
	Flash      string
	ErrMsg     string
	Files      []fileRow
	TotalCount int
	TotalSize  string
	Log        string
	ShowLog    bool
	MaxAge     int // default value for the purge-days input
	CSRFToken  string
}

var adminTpl = template.Must(template.New("admin").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>drop :: admin</title><style>
*{box-sizing:border-box}
body{background:#111;color:#ccc;font-family:monospace;font-size:14px;padding:2em;margin:0}
a{color:#5af}
input,button{background:#222;color:#ccc;border:1px solid #444;padding:4px 8px;font-family:monospace}
button{cursor:pointer}button:hover{background:#333}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid #1a1a1a}
th{color:#555}
.prompt{color:#5af;margin-bottom:1em}
.flash{color:#0d0;margin:.5em 0}
.err{color:#f55;margin:.5em 0}
.danger{color:#f55;border-color:#633}
form{display:inline}
pre{background:#0a0a0a;padding:1em;overflow:auto;max-height:400px;font-size:12px;white-space:pre-wrap}
hr{border:none;border-top:1px solid #222;margin:1.5em 0}
</style></head><body>
<div class="prompt">root@drop:~$ ls -lah /data/files/</div>
{{- if .Flash}}<div class="flash">&#10003; {{.Flash}}</div>{{end}}
{{- if .ErrMsg}}<div class="err">&#10007; {{.ErrMsg}}</div>{{end}}
{{if .LoggedIn}}
<p>{{.TotalCount}} files &nbsp;&middot;&nbsp; {{.TotalSize}} total</p>
<table>
<tr><th>filename</th><th>size</th><th>age</th><th>expires in</th><th></th></tr>
{{range .Files}}<tr>
  <td><a href="/f/{{.Name}}">{{.Name}}</a></td>
  <td>{{.Size}}</td>
  <td>{{.Age}}</td>
  <td>{{.ExpiresIn}}</td>
  <td><form method="POST" action="/admin" onsubmit="return confirm('Delete {{.Name}}?')">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
    <input type="hidden" name="file" value="{{.Name}}">
    <button class="danger">del</button>
  </form></td>
</tr>{{end}}
</table>
<hr>
<form method="POST" action="/admin">
  <input type="hidden" name="action" value="purge">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  Delete files older than
  <input type="number" name="days" value="{{.MaxAge}}" min="1" max="9999" style="width:4em"> days
  <button onclick="return confirm('Purge old files?')">purge</button>
</form>
<hr>
<form method="POST" action="/admin">
  <input type="hidden" name="action" value="viewlog">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <button>view log</button>
</form>
{{if .ShowLog}}<pre>{{.Log}}</pre>{{end}}
<hr>
<form method="POST" action="/admin">
  <input type="hidden" name="action" value="logout">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <button>logout</button>
</form>
{{else}}
<form method="POST" action="/admin">
  <label>password: <input type="password" name="password" autofocus></label>
  <button type="submit">login</button>
</form>
{{end}}
</body></html>`))

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	data := adminData{MaxAge: cfgMaxFileAgeDays}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")

		if action == "logout" {
			// Logout doesn't strictly need CSRF check if it just clears cookie,
			// but good practice. However, if session is invalid, we just redirect.
			destroySession(r)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		if !isAdmin(r) {
			ip := clientIP(r)
			if !checkLoginRateLimit(ip) {
				plainErr(w, http.StatusTooManyRequests, "Too many login attempts")
				return
			}
			pw := r.FormValue("password")
			adminPW := os.Getenv("ADMIN_PASSWORD")
			if adminPW == "" || !secureEqual(pw, adminPW) {
				recordLoginFail(ip)
				data.ErrMsg = "Wrong password"
				adminTpl.Execute(w, data)
				return
			}
			clearLoginFail(ip)
			tok := newSession()
			http.SetCookie(w, &http.Cookie{
				Name:     "drop_session",
				Value:    tok,
				Path:     "/admin",
				HttpOnly: true,
				Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(sessionTTL.Seconds()),
			})
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		// Verify CSRF token for authenticated actions
		c, _ := r.Cookie("drop_session")
		v, ok := sessions.Load(c.Value)
		if !ok {
			// Session expired or invalid
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		sess := v.(sessionData)
		if !secureEqual(r.FormValue("csrf_token"), sess.csrfToken) {
			plainErr(w, http.StatusBadRequest, "Invalid CSRF token")
			return
		}

		data.LoggedIn = true
		data.CSRFToken = sess.csrfToken
		switch action {
		case "delete":
			name := r.FormValue("file")
			if !safeBasename.MatchString(name) {
				data.ErrMsg = "Invalid filename"
			} else if err := os.Remove(storePath + name); err != nil {
				data.ErrMsg = err.Error()
			} else {
				data.Flash = "Deleted " + name
			}
		case "purge":
			days, err := strconv.Atoi(r.FormValue("days"))
			if err != nil || days < 1 {
				data.ErrMsg = "Invalid day count"
			} else {
				count, freed := purgeOlderThan(days)
				data.Flash = fmt.Sprintf("Purged %d files (freed %s)", count, fmtSize(freed))
			}
		case "viewlog":
			data.Log = tailLog(200)
			data.ShowLog = true
		}
		data.Files, data.TotalCount, data.TotalSize = listFiles()
		adminTpl.Execute(w, data)
		return
	}

	if isAdmin(r) {
		data.LoggedIn = true
		c, _ := r.Cookie("drop_session")
		if v, ok := sessions.Load(c.Value); ok {
			data.CSRFToken = v.(sessionData).csrfToken
		}
		data.Files, data.TotalCount, data.TotalSize = listFiles()
	}
	adminTpl.Execute(w, data)
}

func listFiles() ([]fileRow, int, string) {
	entries, err := os.ReadDir(storePath)
	if err != nil {
		return nil, 0, "0 B"
	}

	type fi struct {
		name  string
		size  int64
		mtime time.Time
	}
	var all []fi
	var totalSize int64

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, fi{e.Name(), info.Size(), info.ModTime()})
		totalSize += info.Size()
	}

	sort.Slice(all, func(i, j int) bool { return all[i].mtime.After(all[j].mtime) })

	rows := make([]fileRow, len(all))
	now := time.Now()
	for i, f := range all {
		age := now.Sub(f.mtime)
		expDays := retentionDays(f.size) - age.Hours()/24
		var expStr string
		switch {
		case expDays < 0:
			expStr = "expired"
		case expDays < 1:
			expStr = fmt.Sprintf("%.0fh", expDays*24)
		default:
			expStr = fmt.Sprintf("%.0fd", expDays)
		}
		rows[i] = fileRow{
			Name:      f.name,
			Size:      fmtSize(f.size),
			Age:       fmtAge(age),
			ExpiresIn: expStr,
		}
	}
	return rows, len(all), fmtSize(totalSize)
}

func tailLog(n int) string {
	return tailLogFile(logPath, n)
}

func tailLogFile(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return "(no log yet)"
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return ""
	}
	size := stat.Size()
	if size == 0 {
		return ""
	}

	// Check if file ends with newline to determine newline target count
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, size-1); err != nil {
		return ""
	}
	target := n
	if buf[0] == '\n' {
		target++
	}

	const chunkSize = 4096
	offset := size
	newlinesFound := 0
	chunk := make([]byte, chunkSize)

	for offset > 0 {
		readSize := int64(chunkSize)
		if offset < readSize {
			readSize = offset
		}
		readOffset := offset - readSize

		c := chunk[:readSize]
		if _, err := f.ReadAt(c, readOffset); err != nil {
			break
		}

		for i := len(c) - 1; i >= 0; i-- {
			if c[i] == '\n' {
				newlinesFound++
				if newlinesFound >= target {
					return readLogFromPos(f, readOffset+int64(i)+1, n)
				}
			}
		}
		offset -= readSize
	}
	return readLogFromPos(f, 0, n)
}

func readLogFromPos(f *os.File, pos int64, n int) string {
	if _, err := f.Seek(pos, io.SeekStart); err != nil {
		return ""
	}
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ── Index page ────────────────────────────────────────────────────────────────

type indexData struct {
	SiteURL  string
	MaxSize  int
	MinAge   int
	MaxAge   int
	HasToken bool
	Email    string
}

var indexTpl = template.Must(template.New("index").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>drop</title><style>
*{box-sizing:border-box}
body{background:#111;color:#ccc;font-family:monospace;font-size:14px;padding:2em;margin:0;max-width:760px}
a{color:#5af}
pre{background:#0a0a0a;padding:1em;overflow-x:auto;border-left:3px solid #252525;margin:0}
input[type=file],input[type=password]{background:#222;color:#ccc;border:1px solid #444;padding:4px 8px;font-family:monospace}
button{background:#222;color:#ccc;border:1px solid #444;padding:4px 16px;font-family:monospace;cursor:pointer}
button:hover{background:#333}
h1{color:#5af;margin:0 0 .25em;font-size:2em}
h2{color:#444;font-size:12px;text-transform:uppercase;letter-spacing:.1em;margin:2em 0 .5em;border-bottom:1px solid #1e1e1e;padding-bottom:.25em}
.dim{color:#555}
</style></head><body>
<h1>drop</h1>
<p class="dim">max {{.MaxSize}} MiB &nbsp;&middot;&nbsp; files live {{.MinAge}}&ndash;{{.MaxAge}} days</p>

<h2>upload via curl</h2>
<pre>
{{- if .HasToken -}}
# with token
curl -H "Authorization: Bearer TOKEN" \
     -F "file=@photo.jpg" {{.SiteURL}}

{{end -}}
# basic upload
curl -F "file=@photo.jpg" {{.SiteURL}}

# pipe with extension
echo "hello" | curl -F "file=@-;filename=note.txt" {{.SiteURL}}

# custom id length
curl -F "file=@report.pdf" -F "id_length=12" {{.SiteURL}}

# ShareX / Hupl configs
curl "{{.SiteURL}}?sharex" -o drop.sxcu
curl "{{.SiteURL}}?hupl"   -o drop.hupl</pre>

<h2>upload via browser</h2>
<form id="uform" method="POST" enctype="multipart/form-data">
{{- if .HasToken}}
  <div style="margin-bottom:.5em">
    <label>token <input type="password" name="token" id="tok"></label>
  </div>
{{- end}}
  <input type="file" name="file" id="fi">
  <input type="hidden" name="formatted" value="true">
  <button type="submit">upload</button>
  <span class="dim" style="margin-left:1em">or paste image</span>
</form>

<h2>retention formula</h2>
<pre>days = {{.MinAge}} + ({{.MaxAge}} &minus; {{.MinAge}}) &times; (1 &minus; size &divide; {{.MaxSize}} MiB)&sup2;</pre>
<p class="dim">small files live longer &nbsp;&middot;&nbsp; large files expire sooner</p>

<h2>contact</h2>
<p>
  <a href="mailto:{{.Email}}">{{.Email}}</a>
  &nbsp;&middot;&nbsp;
  <a href="/admin">admin panel</a>
</p>

<script>
document.addEventListener('paste', function(e) {
  var cd = e.clipboardData || window.clipboardData;
  if (!cd) return;
  for (var i = 0; i < cd.items.length; i++) {
    var it = cd.items[i];
    if (it.kind === 'file') {
      var blob = it.getAsFile();
      if (!blob) continue;
      var dt = new DataTransfer();
      dt.items.add(blob);
      document.getElementById('fi').files = dt.files;
      document.getElementById('uform').submit();
      return;
    }
  }
});
</script>
</body></html>`))

// ── ShareX / Hupl configs ─────────────────────────────────────────────────────

func serveShareX(w http.ResponseWriter, r *http.Request) {
	if cfgRequireAuth && !isAdmin(r) {
		plainErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	tok := os.Getenv("UPLOAD_TOKEN")
	headers := ""
	if tok != "" {
		headers = fmt.Sprintf(`,
  "Headers": {"Authorization": "Bearer %s"}`, tok)
	}
	// json.Marshal escapes the URL to prevent Host-header injection.
	urlJSON, _ := json.Marshal(siteURL(r))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="drop.sxcu"`)
	fmt.Fprintf(w, `{
  "Version": "14.0.0",
  "Name": "drop",
  "DestinationType": "ImageUploader, FileUploader",
  "RequestMethod": "POST",
  "RequestURL": %s,
  "Body": "MultipartFormData",
  "FileFormName": "file",
  "URL": "$json:url$"%s
}`, urlJSON, headers)
}

func serveHupl(w http.ResponseWriter, r *http.Request) {
	if cfgRequireAuth && !isAdmin(r) {
		plainErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	tok := os.Getenv("UPLOAD_TOKEN")
	auth := ""
	if tok != "" {
		auth = fmt.Sprintf(`"Authorization": "Bearer %s"`, tok)
	}
	urlJSON, _ := json.Marshal(siteURL(r))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="drop.hupl"`)
	fmt.Fprintf(w, `{"url": %s, "fileParam": "file", "headers": {%s}, "responseType": "text"}`,
		urlJSON, auth)
}

// ── Middleware ────────────────────────────────────────────────────────────────

func withSecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// ── Router ────────────────────────────────────────────────────────────────────

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	switch r.URL.RawQuery {
	case "sharex":
		serveShareX(w, r)
		return
	case "hupl":
		serveHupl(w, r)
		return
	}
	if r.Method == http.MethodPost {
		handleUpload(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTpl.Execute(w, indexData{
		SiteURL:  siteURL(r),
		MaxSize:  cfgMaxFilesizeMiB,
		MinAge:   cfgMinFileAgeDays,
		MaxAge:   cfgMaxFileAgeDays,
		HasToken: cfgRequireAuth,
		Email:    env("ADMIN_EMAIL", "admin@example.com"),
	})
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	loadConfig()

	// Purge mode: invoked by cron or Docker healthcheck.
	if len(os.Args) > 1 && os.Args[1] == "purge" {
		os.MkdirAll(storePath, 0755)
		n := purgeDecay()
		fmt.Printf("purged %d files\n", n)
		return
	}

	os.MkdirAll(storePath, 0755)

	go startCleaner()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/f/", handleFiles)
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/admin/", handleAdmin)

	port := env("PORT", "8080")
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	srv := &http.Server{
		Addr:    port,
		Handler: withSecureHeaders(mux),

		ReadHeaderTimeout: 10 * time.Second, // Slowloris defence
		ReadTimeout:       10 * time.Minute, // must cover slow body uploads
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("drop listening on %s", port)
	log.Fatal(srv.ListenAndServe())
}
