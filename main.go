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
	decayExp        = 2
	minIDLen        = 4
	maxIDLen        = 24
	maxExtLen       = 7
	storePath       = "/data/files/"
	logPath         = "/data/uploads.log"
	extConfigPath   = "/data/extensions.json"
	tokenConfigPath = "/data/tokens.json"
	filePrefix      = "/f/"
)

var (
	cfgMaxFilesizeMiB int    // MAX_FILESIZE (MiB)
	cfgMaxFileAgeDays int    // MAX_FILE_AGE (days)
	cfgMinFileAgeDays int    // MIN_FILE_AGE (days)
	cfgRequireAuth    bool   // REQUIRE_AUTH (true/false); default: true when UPLOAD_TOKEN is set
	cfgUploadToken    string // UPLOAD_TOKEN
	cfgAdminPassword  string // ADMIN_PASSWORD
	cfgAdminEmail     string // ADMIN_EMAIL
)

func loadConfig() {
	cfgMaxFilesizeMiB = envInt("MAX_FILESIZE", 256)
	cfgMaxFileAgeDays = envInt("MAX_FILE_AGE", 30)
	cfgMinFileAgeDays = envInt("MIN_FILE_AGE", 3)
	cfgUploadToken = os.Getenv("UPLOAD_TOKEN")
	cfgAdminPassword = env("ADMIN_PASSWORD", "changeme")
	cfgAdminEmail = env("ADMIN_EMAIL", "admin@example.com")

	// Defaults to true when UPLOAD_TOKEN is set; REQUIRE_AUTH=false overrides.
	if v := os.Getenv("REQUIRE_AUTH"); v != "" {
		cfgRequireAuth = v != "false" && v != "0"
	} else {
		cfgRequireAuth = cfgUploadToken != ""
	}

	loadAllowedExts()
	loadAppTokens()
}

// loadJSON reads a JSON file into dest. Returns false if the file doesn't exist.
func loadJSON(path string, dest any) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if err := json.Unmarshal(data, dest); err != nil {
		log.Printf("failed to parse %s: %v", path, err)
		return false
	}
	return true
}

// saveJSON writes data as indented JSON to path.
func saveJSON(path string, data any) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("failed to marshal JSON for %s: %v", path, err)
		return
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		log.Printf("failed to save %s: %v", path, err)
	}
}

var (
	allowedExtsMu sync.RWMutex
	allowedExts   = map[string]bool{
		"jpg": true, "jpeg": true, "png": true, "gif": true,
		"webp": true, "avif": true, "heic": true,
		"pdf":  true,
		"txt":  true, "md": true, "csv": true, "log": true, "json": true,
	}
)

var validExtRe = regexp.MustCompile(`^[a-z0-9]{1,7}$`)

func isExtAllowed(ext string) bool {
	allowedExtsMu.RLock()
	defer allowedExtsMu.RUnlock()
	return allowedExts[ext]
}

func getAllowedExts() []string {
	allowedExtsMu.RLock()
	defer allowedExtsMu.RUnlock()
	out := make([]string, 0, len(allowedExts))
	for k := range allowedExts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setAllowedExt(ext string) {
	allowedExtsMu.Lock()
	defer allowedExtsMu.Unlock()
	allowedExts[ext] = true
	saveAllowedExtsLocked()
}

func removeAllowedExt(ext string) {
	allowedExtsMu.Lock()
	defer allowedExtsMu.Unlock()
	delete(allowedExts, ext)
	saveAllowedExtsLocked()
}

// saveAllowedExtsLocked writes current allowedExts to disk. Caller must hold allowedExtsMu.
func saveAllowedExtsLocked() {
	exts := make([]string, 0, len(allowedExts))
	for k := range allowedExts {
		exts = append(exts, k)
	}
	sort.Strings(exts)
	saveJSON(extConfigPath, exts)
}

// loadAllowedExts loads extensions from disk if the config file exists.
func loadAllowedExts() {
	var exts []string
	if !loadJSON(extConfigPath, &exts) {
		return // file doesn't exist yet; keep hardcoded defaults
	}
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = strings.ToLower(strings.TrimPrefix(e, "."))
		if validExtRe.MatchString(e) {
			m[e] = true
		}
	}
	allowedExtsMu.Lock()
	allowedExts = m
	allowedExtsMu.Unlock()
}

// ── App tokens ────────────────────────────────────────────────────────────────

type appToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Token      string `json:"token"`
	Created    string `json:"created"`
	Uploads    int    `json:"uploads"`
	TotalBytes int64  `json:"total_bytes"`
	LastUsed   string `json:"last_used,omitempty"`
}

var (
	appTokensMu sync.RWMutex
	appTokens   []appToken
)

func loadAppTokens() {
	var tokens []appToken
	if !loadJSON(tokenConfigPath, &tokens) {
		return
	}
	appTokensMu.Lock()
	appTokens = tokens
	appTokensMu.Unlock()
}

// saveAppTokensLocked writes app tokens to disk. Caller must hold appTokensMu.
func saveAppTokensLocked() {
	saveJSON(tokenConfigPath, appTokens)
}

func hasAppTokens() bool {
	appTokensMu.RLock()
	defer appTokensMu.RUnlock()
	return len(appTokens) > 0
}

func isValidAppToken(token string) (string, bool) {
	appTokensMu.RLock()
	defer appTokensMu.RUnlock()
	for _, t := range appTokens {
		if secureEqual(token, t.Token) {
			return t.ID, true
		}
	}
	return "", false
}

func recordAppTokenUsage(id string, size int64) {
	appTokensMu.Lock()
	defer appTokensMu.Unlock()
	for i := range appTokens {
		if appTokens[i].ID == id {
			appTokens[i].Uploads++
			appTokens[i].TotalBytes += size
			appTokens[i].LastUsed = time.Now().UTC().Format(time.RFC3339)
			saveAppTokensLocked()
			return
		}
	}
}

func getAppTokens() []appToken {
	appTokensMu.RLock()
	defer appTokensMu.RUnlock()
	out := make([]appToken, len(appTokens))
	copy(out, appTokens)
	return out
}

func getAppTokenByID(id string) (appToken, bool) {
	appTokensMu.RLock()
	defer appTokensMu.RUnlock()
	for _, t := range appTokens {
		if t.ID == id {
			return t, true
		}
	}
	return appToken{}, false
}

func generateAppToken(name string) appToken {
	t := appToken{
		ID:      randID(8),
		Name:    name,
		Token:   randHex(32),
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	appTokensMu.Lock()
	appTokens = append(appTokens, t)
	saveAppTokensLocked()
	appTokensMu.Unlock()
	return t
}

func revokeAppToken(id string) bool {
	appTokensMu.Lock()
	defer appTokensMu.Unlock()
	for i, t := range appTokens {
		if t.ID == id {
			appTokens = append(appTokens[:i], appTokens[i+1:]...)
			saveAppTokensLocked()
			return true
		}
	}
	return false
}

func adminTokenRows() []adminTokenRow {
	tokens := getAppTokens()
	rows := make([]adminTokenRow, len(tokens))
	for i, t := range tokens {
		created := t.Created
		if ts, err := time.Parse(time.RFC3339, t.Created); err == nil {
			created = ts.Format("2006-01-02")
		}
		lastUsed := "never"
		if t.LastUsed != "" {
			if ts, err := time.Parse(time.RFC3339, t.LastUsed); err == nil {
				lastUsed = fmtAge(time.Since(ts)) + " ago"
			}
		}
		rows[i] = adminTokenRow{
			ID:        t.ID,
			Name:      t.Name,
			Created:   created,
			Uploads:   strconv.Itoa(t.Uploads),
			TotalSize: fmtSize(t.TotalBytes),
			LastUsed:  lastUsed,
		}
	}
	return rows
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
	expiry time.Time
	csrf   string
	role   string // "admin" or "upload"
}

var sessions sync.Map // token(string) → sessionData

// ── Login rate limiting ───────────────────────────────────────────────────────

const maxLoginAttempts = 10

type loginAttempt struct {
	count int
	last  time.Time
}

var (
	loginFailsMu  sync.Mutex
	loginFails = map[string]loginAttempt{}
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
	a := loginFails[ip]
	a.count++
	a.last = time.Now()
	loginFails[ip] = a
}

func clearLoginFail(ip string) {
	loginFailsMu.Lock()
	defer loginFailsMu.Unlock()
	delete(loginFails, ip)
}

// ── Upload rate limiting ──────────────────────────────────────────────────────

const (
	maxUploadsPerHour = 60
	uploadRateWindow  = time.Hour
)

type uploadCounter struct {
	count int
	reset time.Time // window expiry
}

var (
	uploadRateMu sync.Mutex
	uploadRates  = map[string]uploadCounter{}
)

// checkUploadRateLimit returns true if the IP has uploads remaining in the current window.
func checkUploadRateLimit(ip string) bool {
	uploadRateMu.Lock()
	defer uploadRateMu.Unlock()
	c := uploadRates[ip]
	now := time.Now()
	if now.After(c.reset) {
		// Start a new window.
		uploadRates[ip] = uploadCounter{count: 1, reset: now.Add(uploadRateWindow)}
		return true
	}
	if c.count >= maxUploadsPerHour {
		return false
	}
	c.count++
	uploadRates[ip] = c
	return true
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
			// Evict expired upload rate counters.
			uploadRateMu.Lock()
			for k, v := range uploadRates {
				if now.After(v.reset) {
					delete(uploadRates, k)
				}
			}
			uploadRateMu.Unlock()
		}
	}()
}

func newSession(role string) string {
	tok := randHex(32)
	sessions.Store(tok, sessionData{
		expiry: time.Now().Add(sessionTTL),
		csrf:   randHex(16),
		role:   role,
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
	sd := v.(sessionData)
	if time.Now().After(sd.expiry) {
		sessions.Delete(c.Value)
		return false
	}
	return sd.role == "admin"
}

// isUploader returns true if the request has a valid upload or admin session.
func isUploader(r *http.Request) bool {
	c, err := r.Cookie("drop_session")
	if err != nil {
		return false
	}
	v, ok := sessions.Load(c.Value)
	if !ok {
		return false
	}
	sd := v.(sessionData)
	if time.Now().After(sd.expiry) {
		sessions.Delete(c.Value)
		return false
	}
	return sd.role == "upload" || sd.role == "admin"
}

// csrfToken returns the CSRF token for the current session, or empty string.
func csrfToken(r *http.Request) string {
	c, err := r.Cookie("drop_session")
	if err != nil {
		return ""
	}
	v, ok := sessions.Load(c.Value)
	if !ok {
		return ""
	}
	return v.(sessionData).csrf
}

// validCSRF checks that the form's csrf field matches the session's CSRF token.
func validCSRF(r *http.Request) bool {
	tok := csrfToken(r)
	return tok != "" && secureEqual(r.FormValue("csrf"), tok)
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

// randHex returns a cryptographically random hex string of n bytes (2n hex chars).
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// storeFile holds metadata for a file in storePath.
type storeFile struct {
	name  string
	size  int64
	mtime time.Time
}

// readStoreFiles returns metadata for all regular files in storePath.
func readStoreFiles() []storeFile {
	entries, err := os.ReadDir(storePath)
	if err != nil {
		return nil
	}
	files := make([]storeFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, storeFile{e.Name(), info.Size(), info.ModTime()})
	}
	return files
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

// validateUploadToken checks a token against app tokens (if any) or the master upload token.
// Returns the app token ID (empty for master token) and whether the token is valid.
func validateUploadToken(tok string) (string, bool) {
	if id, ok := isValidAppToken(tok); ok {
		return id, true
	}
	if cfgUploadToken != "" && secureEqual(tok, cfgUploadToken) {
		return "", true
	}
	return "", false
}

// ── Upload ────────────────────────────────────────────────────────────────────

func handleUpload(w http.ResponseWriter, r *http.Request) {
	// Body size cap must be installed before any body reads.
	r.Body = http.MaxBytesReader(w, r.Body, int64(cfgMaxFilesizeMiB+2)*1024*1024)

	// Check auth headers first; form token checked post-ParseMultipartForm.
	if cfgRequireAuth && !hasAppTokens() && cfgUploadToken == "" {
		plainErr(w, http.StatusInternalServerError,
			"Server misconfiguration: UPLOAD_TOKEN must be set when REQUIRE_AUTH is true")
		return
	}
	needFormToken := false
	var usedTokenID string // app token ID used for this upload (for tracking)
	if cfgRequireAuth && isUploader(r) {
		// Logged-in session (admin or upload) — skip token auth.
	} else if cfgRequireAuth {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			id, ok := validateUploadToken(strings.TrimPrefix(auth, "Bearer "))
			if !ok {
				plainErr(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			usedTokenID = id
		} else if h := r.Header.Get("X-Upload-Token"); h != "" {
			id, ok := validateUploadToken(h)
			if !ok {
				plainErr(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			usedTokenID = id
		} else {
			needFormToken = true
		}
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		plainErr(w, http.StatusBadRequest, "Bad request: "+err.Error())
		return
	}

	// Browser form token check.
	if needFormToken {
		formTok := r.FormValue("token")
		id, ok := validateUploadToken(formTok)
		if !ok {
			log.Printf("upload auth failed: needFormToken=true tokenPresent=%v tokenLen=%d hasFile=%v ip=%s ua=%s",
				formTok != "", len(formTok), r.MultipartForm != nil && len(r.MultipartForm.File["file"]) > 0,
				clientIP(r), r.UserAgent())
			plainErr(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		usedTokenID = id
	}

	// Per-IP upload rate limit.
	if !checkUploadRateLimit(clientIP(r)) {
		plainErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("Upload rate limit exceeded (%d/hour)", maxUploadsPerHour))
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
	if len(ext) > maxExtLen || !isExtAllowed(ext) {
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
		os.Remove(dest)
		log.Printf("upload write error: %v", err)
		plainErr(w, http.StatusInternalServerError, "Could not save file")
		return
	}
	os.Chmod(dest, 0644)

	// Token is never logged.
	if fi, err := os.Stat(dest); err == nil {
		appendLog(r, fi.Size(), hdr.Filename, basename)
		if usedTokenID != "" {
			recordAppTokenUsage(usedTokenID, fi.Size())
		}
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

// imgSem limits concurrent image re-encodes. Each 50 MP decode holds ~200 MB
// of pixel data; without a cap, many simultaneous uploads can exhaust memory.
var imgSem = make(chan struct{}, 4)

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
		imgSem <- struct{}{}
		defer func() { <-imgSem }()
	}

	switch ext {
	case "jpg", "jpeg":
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

var (
	logWriter   *os.File
	logWriterMu sync.Mutex
)

func openLogWriter() {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("failed to open log file: %v", err)
		return
	}
	logWriter = f
}

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
	logWriterMu.Lock()
	defer logWriterMu.Unlock()
	if logWriter == nil {
		return
	}
	fmt.Fprintf(logWriter, "%s\t%s\t%d\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339),
		clientIP(r), size, sanitizeLogField(origName), stored)
}

// ── Purge ─────────────────────────────────────────────────────────────────────

// purgeDecay removes files whose age exceeds the decay-formula retention period.
func purgeDecay() int {
	files := readStoreFiles()
	n := 0
	now := time.Now()
	for _, f := range files {
		age := now.Sub(f.mtime).Hours() / 24
		if age > retentionDays(f.size) {
			os.Remove(filepath.Join(storePath, f.name))
			n++
		}
	}
	return n
}

// purgeOlderThan removes files older than the given number of days.
func purgeOlderThan(days int) (int, int64) {
	files := readStoreFiles()
	var count int
	var freed int64
	now := time.Now()
	for _, f := range files {
		if now.Sub(f.mtime).Hours()/24 > float64(days) {
			freed += f.size
			os.Remove(filepath.Join(storePath, f.name))
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
	files := readStoreFiles()
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

type adminFileRow struct {
	Name, Size, Age, ExpiresIn string
	IsImage                    bool
}

type adminTokenRow struct {
	ID, Name, Created, Uploads, TotalSize, LastUsed string
}

type adminData struct {
	LoggedIn   bool
	Flash      string
	ErrMsg     string
	Files      []adminFileRow
	TotalCount int
	TotalSize  string
	Log        string
	ShowLog    bool
	MaxAge     int // default value for the purge-days input
	Extensions []string
	Tokens     []adminTokenRow
	NewToken   string // shown once after generation
	CSRF       string // per-session CSRF token for forms
}

var adminTpl = template.Must(template.New("admin").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>drop :: admin</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
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
.thumb{width:40px;height:40px;object-fit:cover;border:1px solid #333;border-radius:2px;vertical-align:middle;cursor:pointer;transition:transform .15s}
.thumb:hover{transform:scale(3);position:relative;z-index:10}
.sel-bar{display:none;margin:.5em 0;padding:6px 10px;background:#1a1a1a;border:1px solid #333;border-radius:3px}
.sel-bar.active{display:block}
</style></head><body>
<div class="prompt"><a href="/" style="color:#5af;text-decoration:none">root@drop</a>:~$ ls -lah /data/files/</div>
{{- if .Flash}}<div class="flash">&#10003; {{.Flash}}</div>{{end}}
{{- if .ErrMsg}}<div class="err">&#10007; {{.ErrMsg}}</div>{{end}}
{{if .LoggedIn}}
<p>{{.TotalCount}} files &nbsp;&middot;&nbsp; {{.TotalSize}} total</p>
<div id="selbar" class="sel-bar">
  <span id="selcount">0</span> selected &nbsp;
  <button class="danger" id="delbtn">delete selected</button>
  <button id="selbtnNone" style="margin-left:8px">deselect all</button>
</div>
<form id="bulkform" method="POST" action="/admin" style="display:none">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="delete_bulk">
  <div id="bulkfiles"></div>
</form>
<table>
<tr><th><input type="checkbox" id="selall" title="select all"></th><th></th><th>filename</th><th>size</th><th>age</th><th>expires in</th><th></th></tr>
{{range .Files}}<tr>
  <td><input type="checkbox" class="fsel" data-name="{{.Name}}"></td>
  <td>{{if .IsImage}}<img class="thumb" src="/f/{{.Name}}" alt="" loading="lazy">{{end}}</td>
  <td><a href="/f/{{.Name}}">{{.Name}}</a></td>
  <td>{{.Size}}</td>
  <td>{{.Age}}</td>
  <td>{{.ExpiresIn}}</td>
  <td><form method="POST" action="/admin" onsubmit="return confirm('Delete {{.Name}}?')">
    <input type="hidden" name="csrf" value="{{$.CSRF}}">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="file" value="{{.Name}}">
    <button class="danger">del</button>
  </form></td>
</tr>{{end}}
</table>
<script>
(function(){
  var selall = document.getElementById('selall');
  var boxes = document.querySelectorAll('.fsel');
  var bar = document.getElementById('selbar');
  var cnt = document.getElementById('selcount');
  var delbtn = document.getElementById('delbtn');
  var selbtnNone = document.getElementById('selbtnNone');
  var bulkform = document.getElementById('bulkform');
  var bulkfiles = document.getElementById('bulkfiles');

  function updateBar(){
    var n = document.querySelectorAll('.fsel:checked').length;
    cnt.textContent = n;
    bar.className = n > 0 ? 'sel-bar active' : 'sel-bar';
  }

  selall.addEventListener('change', function(){
    boxes.forEach(function(cb){ cb.checked = selall.checked; });
    updateBar();
  });
  boxes.forEach(function(cb){
    cb.addEventListener('change', function(){
      if (!cb.checked) selall.checked = false;
      updateBar();
    });
  });
  selbtnNone.addEventListener('click', function(){
    selall.checked = false;
    boxes.forEach(function(cb){ cb.checked = false; });
    updateBar();
  });
  delbtn.addEventListener('click', function(){
    var sel = document.querySelectorAll('.fsel:checked');
    if (sel.length === 0) return;
    if (!confirm('Delete ' + sel.length + ' file(s)?')) return;
    bulkfiles.innerHTML = '';
    sel.forEach(function(cb){
      var inp = document.createElement('input');
      inp.type = 'hidden'; inp.name = 'files'; inp.value = cb.dataset.name;
      bulkfiles.appendChild(inp);
    });
    bulkform.submit();
  });
})();
</script>
<hr>
<form method="POST" action="/admin">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="purge">
  Delete files older than
  <input type="number" name="days" value="{{.MaxAge}}" min="1" max="9999" style="width:4em"> days
  <button onclick="return confirm('Purge old files?')">purge</button>
</form>
<hr>
<p style="color:#555;margin-bottom:.5em">&mdash; file extensions &mdash;</p>
<div style="margin-bottom:.5em">
{{range .Extensions}}<form method="POST" action="/admin" style="display:inline-block;margin:0 6px 4px 0">
  <input type="hidden" name="csrf" value="{{$.CSRF}}">
  <input type="hidden" name="action" value="rm_ext">
  <input type="hidden" name="ext" value="{{.}}">
  <span style="background:#222;padding:2px 6px;border:1px solid #444;border-radius:3px">{{.}} <button style="border:none;background:none;color:#f55;cursor:pointer;padding:0 2px">&times;</button></span>
</form>{{end}}
</div>
<form method="POST" action="/admin" style="margin-bottom:1em">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="add_ext">
  <input type="text" name="ext" placeholder="ext" maxlength="7" style="width:6em">
  <button>add</button>
</form>
<hr>
<form method="POST" action="/admin">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="viewlog">
  <button>view log</button>
</form>
{{if .ShowLog}}<pre>{{.Log}}</pre>{{end}}
<hr>
<p style="color:#555;margin-bottom:.5em">&mdash; api tokens &mdash;</p>
{{if .NewToken}}<div class="flash" style="word-break:break-all">New token: <code>{{.NewToken}}</code><br><small style="color:#555">Copy now — it won't be shown again.</small></div>{{end}}
{{if .Tokens}}
<table>
<tr><th>name</th><th>created</th><th>uploads</th><th>total</th><th>last used</th><th>config</th><th></th></tr>
{{range .Tokens}}<tr>
  <td>{{.Name}}</td>
  <td>{{.Created}}</td>
  <td>{{.Uploads}}</td>
  <td>{{.TotalSize}}</td>
  <td>{{.LastUsed}}</td>
  <td><a href="/?sharex&token={{.ID}}">sharex</a> &middot; <a href="/?hupl&token={{.ID}}">hupl</a></td>
  <td><form method="POST" action="/admin" onsubmit="return confirm('Revoke token {{.Name}}?')">
    <input type="hidden" name="csrf" value="{{$.CSRF}}">
    <input type="hidden" name="action" value="revoke_token">
    <input type="hidden" name="token_id" value="{{.ID}}">
    <button class="danger">revoke</button>
  </form></td>
</tr>{{end}}
</table>
{{else}}<p class="dim">No app tokens yet. Generate one to use instead of the master upload token.</p>{{end}}
<form method="POST" action="/admin" style="margin:.5em 0 1em">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="gen_token">
  <input type="text" name="token_name" placeholder="label (e.g. ShareX laptop)" maxlength="32" style="width:20em">
  <button>generate</button>
</form>
{{if not .Tokens}}<p><a href="/?sharex">download ShareX config</a> &nbsp;&middot;&nbsp; <a href="/?hupl">download Hupl config</a></p>{{end}}
<hr>
<form method="POST" action="/admin">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="logout">
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

		if !isAdmin(r) {
			ip := clientIP(r)
			if !checkLoginRateLimit(ip) {
				plainErr(w, http.StatusTooManyRequests, "Too many login attempts")
				return
			}
			pw := r.FormValue("password")
			if cfgAdminPassword == "" || !secureEqual(pw, cfgAdminPassword) {
				recordLoginFail(ip)
				data.ErrMsg = "Wrong password"
				adminTpl.Execute(w, data)
				return
			}
			clearLoginFail(ip)
			tok := newSession("admin")
			http.SetCookie(w, &http.Cookie{
				Name:     "drop_session",
				Value:    tok,
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(sessionTTL.Seconds()),
			})
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		// All authenticated actions require a valid CSRF token.
		if !validCSRF(r) {
			plainErr(w, http.StatusForbidden, "Invalid or missing CSRF token")
			return
		}

		if action == "logout" {
			destroySession(r)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		data.LoggedIn = true
		data.CSRF = csrfToken(r)
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
		case "delete_bulk":
			names := r.Form["files"]
			var deleted int
			for _, name := range names {
				if !safeBasename.MatchString(name) {
					continue
				}
				if err := os.Remove(storePath + name); err == nil {
					deleted++
				}
			}
			if deleted > 0 {
				data.Flash = fmt.Sprintf("Deleted %d file(s)", deleted)
			} else {
				data.ErrMsg = "No files deleted"
			}
		case "purge":
			days, err := strconv.Atoi(r.FormValue("days"))
			if err != nil || days < 1 {
				data.ErrMsg = "Invalid day count"
			} else {
				count, freed := purgeOlderThan(days)
				data.Flash = fmt.Sprintf("Purged %d files (freed %s)", count, fmtSize(freed))
			}
		case "add_ext":
			ext := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.FormValue("ext"), ".")))
			if !validExtRe.MatchString(ext) {
				data.ErrMsg = "Invalid extension (1-7 alphanumeric chars)"
			} else if isExtAllowed(ext) {
				data.ErrMsg = "Extension already allowed"
			} else {
				setAllowedExt(ext)
				data.Flash = "Added extension: " + ext
			}
		case "rm_ext":
			ext := strings.ToLower(strings.TrimSpace(r.FormValue("ext")))
			if !validExtRe.MatchString(ext) {
				data.ErrMsg = "Invalid extension"
			} else {
				removeAllowedExt(ext)
				data.Flash = "Removed extension: " + ext
			}
		case "gen_token":
			name := strings.TrimSpace(r.FormValue("token_name"))
			if name == "" || len(name) > 32 {
				data.ErrMsg = "Token label must be 1-32 characters"
			} else {
				t := generateAppToken(name)
				data.NewToken = t.Token
				data.Flash = fmt.Sprintf("Generated token %q", name)
			}
		case "revoke_token":
			id := r.FormValue("token_id")
			if revokeAppToken(id) {
				data.Flash = "Token revoked"
			} else {
				data.ErrMsg = "Token not found"
			}
		case "viewlog":
			data.Log = tailLog(200)
			data.ShowLog = true
		}
		data.Tokens = adminTokenRows()
		data.Extensions = getAllowedExts()
		data.Files, data.TotalCount, data.TotalSize = listFiles()
		adminTpl.Execute(w, data)
		return
	}

	if isAdmin(r) {
		data.LoggedIn = true
		data.CSRF = csrfToken(r)
		data.Extensions = getAllowedExts()
		data.Tokens = adminTokenRows()
		data.Files, data.TotalCount, data.TotalSize = listFiles()
	}
	adminTpl.Execute(w, data)
}

func listFiles() ([]adminFileRow, int, string) {
	all := readStoreFiles()
	var totalSize int64
	for _, f := range all {
		totalSize += f.size
	}

	sort.Slice(all, func(i, j int) bool { return all[i].mtime.After(all[j].mtime) })

	rows := make([]adminFileRow, len(all))
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
		ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(f.name)), ".")
		rows[i] = adminFileRow{
			Name:      f.name,
			Size:      fmtSize(f.size),
			Age:       fmtAge(age),
			ExpiresIn: expStr,
			IsImage:   inlineExts[ext],
		}
	}
	return rows, len(all), fmtSize(totalSize)
}

func tailLog(n int) string {
	f, err := os.Open(logPath)
	if err != nil {
		return "(no log yet)"
	}
	defer f.Close()
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
	LoggedIn bool
	AuthErr  bool
	Email    string
}

var indexTpl = template.Must(template.New("index").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>drop</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
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
# upload
curl -H "Authorization: Bearer TOKEN" \
     -F "file=@photo.jpg" {{.SiteURL}}

# pipe with extension
echo "hello" | curl -H "Authorization: Bearer TOKEN" \
     -F "file=@-;filename=note.txt" {{.SiteURL}}

# custom id length
curl -H "Authorization: Bearer TOKEN" \
     -F "file=@report.pdf" -F "id_length=12" {{.SiteURL}}

# ShareX / Hupl configs
curl "{{.SiteURL}}?sharex" -o drop.sxcu
curl "{{.SiteURL}}?hupl"   -o drop.hupl
{{- else -}}
# upload
curl -F "file=@photo.jpg" {{.SiteURL}}

# pipe with extension
echo "hello" | curl -F "file=@-;filename=note.txt" {{.SiteURL}}

# custom id length
curl -F "file=@report.pdf" -F "id_length=12" {{.SiteURL}}

# ShareX / Hupl configs
curl "{{.SiteURL}}?sharex" -o drop.sxcu
curl "{{.SiteURL}}?hupl"   -o drop.hupl
{{- end}}</pre>

<h2>upload via browser</h2>
<div id="dropzone" style="border:2px dashed #333;padding:1.5em;margin-bottom:1em;transition:border-color .2s,background .2s">
{{- if and .HasToken (not .LoggedIn)}}
  <form method="POST" style="margin-bottom:1em">
    <input type="hidden" name="action" value="login">
    <label style="color:#555">token <input type="password" name="token" id="tok" style="width:220px"></label>
    <button type="submit" style="margin-left:.5em">login</button>
    {{- if .AuthErr}}
    <span style="color:#f55;margin-left:.5em">invalid token</span>
    {{- end}}
  </form>
  <p class="dim" style="margin:0">log in to upload files</p>
{{- else}}
  {{- if and .HasToken .LoggedIn}}
  <div style="margin-bottom:1em">
    <span style="color:#0d0">&#10003;</span> <span class="dim">authenticated</span>
    <form method="POST" style="display:inline;margin-left:1em">
      <input type="hidden" name="action" value="logout">
      <button type="submit" style="border:none;background:none;color:#555;cursor:pointer;font-family:monospace;padding:0;text-decoration:underline">logout</button>
    </form>
  </div>
  {{- end}}
  <p style="margin:0 0 1em;color:#555">drag &amp; drop file here</p>
  <form id="uform" method="POST" enctype="multipart/form-data">
    <input type="file" name="file" id="fi">
    <input type="hidden" name="formatted" value="true">
    <button type="submit" style="margin-left:.5em">upload</button>
    <span class="dim" style="margin-left:.5em">or paste image</span>
  </form>
{{- end}}
</div>
<div id="progress" style="display:none;margin-bottom:1em">
  <div style="background:#222;border:1px solid #444;height:22px;position:relative">
    <div id="pbar" style="background:#5af;height:100%;width:0%;transition:width .15s"></div>
    <span id="ptxt" style="position:absolute;top:0;left:0;right:0;text-align:center;line-height:22px;font-size:12px"></span>
  </div>
</div>
<div id="result" style="display:none;margin-bottom:1em"></div>

<h2>retention formula</h2>
<pre>days = {{.MinAge}} + ({{.MaxAge}} &minus; {{.MinAge}}) &times; (1 &minus; size &divide; {{.MaxSize}} MiB)&sup2;</pre>
<p class="dim">small files live longer &nbsp;&middot;&nbsp; large files expire sooner</p>

<h2>contact</h2>
<p>
  <a href="mailto:{{.Email}}">{{.Email}}</a>
  &nbsp;&middot;&nbsp;
  <a href="/admin">admin panel</a>
</p>

{{- if or (not .HasToken) .LoggedIn}}
<script>
(function(){
  var dz = document.getElementById('dropzone');
  var fi = document.getElementById('fi');
  var form = document.getElementById('uform');

  function uploadFile(file) {
    var fd = new FormData();
    fd.append('file', file);

    var prog = document.getElementById('progress');
    var pbar = document.getElementById('pbar');
    var ptxt = document.getElementById('ptxt');
    var res = document.getElementById('result');
    prog.style.display = 'block';
    res.style.display = 'none';
    pbar.style.width = '0%';
    ptxt.textContent = '0%';

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/');
    xhr.upload.onprogress = function(e) {
      if (e.lengthComputable) {
        var pct = Math.round(e.loaded / e.total * 100);
        pbar.style.width = pct + '%';
        ptxt.textContent = pct + '%';
      }
    };
    xhr.onload = function() {
      pbar.style.width = '100%';
      ptxt.textContent = '100%';
      if (xhr.status >= 200 && xhr.status < 300) {
        var url = xhr.responseText.trim();
        var a = document.createElement('a');
        a.href = url; a.textContent = url; a.style.color = '#5af';
        res.textContent = '';
        var ok = document.createElement('span');
        ok.style.color = '#0d0'; ok.innerHTML = '&#10003; ';
        res.appendChild(ok); res.appendChild(a);
      } else {
        res.textContent = '';
        var fail = document.createElement('span');
        fail.style.color = '#f55'; fail.innerHTML = '&#10007; ';
        res.appendChild(fail);
        res.appendChild(document.createTextNode(xhr.responseText.trim()));
      }
      res.style.display = 'block';
    };
    xhr.onerror = function() {
      ptxt.textContent = 'failed';
      res.innerHTML = '<span style="color:#f55">&#10007;</span> Upload failed';
      res.style.display = 'block';
    };
    xhr.send(fd);
  }

  // Drag and drop
  ['dragenter','dragover'].forEach(function(ev) {
    dz.addEventListener(ev, function(e) {
      e.preventDefault(); e.stopPropagation();
      dz.style.borderColor = '#5af'; dz.style.background = '#1a1a2a';
    });
  });
  ['dragleave','drop'].forEach(function(ev) {
    dz.addEventListener(ev, function(e) {
      e.preventDefault(); e.stopPropagation();
      dz.style.borderColor = '#333'; dz.style.background = '';
    });
  });
  dz.addEventListener('drop', function(e) {
    var files = e.dataTransfer.files;
    if (files.length > 0) uploadFile(files[0]);
  });

  // Form submit via XHR
  form.addEventListener('submit', function(e) {
    if (fi.files.length > 0) {
      e.preventDefault();
      uploadFile(fi.files[0]);
    }
  });

  // Paste
  document.addEventListener('paste', function(e) {
    var cd = e.clipboardData || window.clipboardData;
    if (!cd) return;
    for (var i = 0; i < cd.items.length; i++) {
      if (cd.items[i].kind === 'file') {
        var blob = cd.items[i].getAsFile();
        if (blob) { e.preventDefault(); uploadFile(blob); return; }
      }
    }
  });
})();
</script>
{{- end}}
</body></html>`))

// ── ShareX / Hupl configs ─────────────────────────────────────────────────────

func resolveConfigToken(r *http.Request) (string, error) {
	if id := r.URL.Query().Get("token"); id != "" {
		t, ok := getAppTokenByID(id)
		if !ok {
			return "", fmt.Errorf("unknown token ID")
		}
		return t.Token, nil
	}
	if hasAppTokens() {
		return "", fmt.Errorf("app tokens exist; specify ?token=<id>")
	}
	return cfgUploadToken, nil
}

func serveShareX(w http.ResponseWriter, r *http.Request) {
	if cfgRequireAuth && !isAdmin(r) {
		plainErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	tok, err := resolveConfigToken(r)
	if err != nil {
		plainErr(w, http.StatusBadRequest, err.Error())
		return
	}
	headers := ""
	if tok != "" {
		headers = fmt.Sprintf(`,
  "Headers": {"Authorization": "Bearer %s"}`, tok)
	}
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
  "URL": "$response$"%s
}`, urlJSON, headers)
}

func serveHupl(w http.ResponseWriter, r *http.Request) {
	if cfgRequireAuth && !isAdmin(r) {
		plainErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	tok, err := resolveConfigToken(r)
	if err != nil {
		plainErr(w, http.StatusBadRequest, err.Error())
		return
	}
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

// ── Favicon ───────────────────────────────────────────────────────────────────

// 16x16 SVG favicon: a downward arrow into a tray (represents "drop"/download).
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" rx="3" fill="#111"/><path d="M8 2v7M5 7l3 3 3-3" stroke="#5af" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/><path d="M3 12h10" stroke="#555" stroke-width="1.5" stroke-linecap="round"/></svg>`

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	fmt.Fprint(w, faviconSVG)
}

func handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !checkLoginRateLimit(ip) {
		plainErr(w, http.StatusTooManyRequests, "Too many login attempts")
		return
	}
	tok := r.FormValue("token")
	if _, ok := validateUploadToken(tok); !ok {
		recordLoginFail(ip)
		http.Redirect(w, r, "/?err=badtoken", http.StatusSeeOther)
		return
	}
	clearLoginFail(ip)
	sess := newSession("upload")
	http.SetCookie(w, &http.Cookie{
		Name:     "drop_session",
		Value:    sess,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode, // Lax (not Strict) so cookie survives the POST→redirect→GET flow
		MaxAge:   int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Router ────────────────────────────────────────────────────────────────────

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if _, ok := q["sharex"]; ok {
		serveShareX(w, r)
		return
	}
	if _, ok := q["hupl"]; ok {
		serveHupl(w, r)
		return
	}
	if r.Method == http.MethodPost {
		// ParseForm first to read "action" field without consuming multipart body.
		// For multipart uploads, FormValue("action") will be empty and we fall through.
		if r.FormValue("action") == "login" {
			handleTokenLogin(w, r)
			return
		}
		if r.FormValue("action") == "logout" {
			destroySession(r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
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
		LoggedIn: isUploader(r),
		AuthErr:  r.URL.Query().Get("err") == "badtoken",
		Email:    cfgAdminEmail,
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
	openLogWriter()

	go startCleaner()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/f/", handleFiles)
	mux.HandleFunc("/favicon.ico", handleFavicon)
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
		WriteTimeout:      10 * time.Minute, // must cover slow body uploads (same as ReadTimeout)
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("drop listening on %s", port)
	log.Fatal(srv.ListenAndServe())
}
