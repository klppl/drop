package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net"
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
	decayExp   = 2
	minIDLen   = 4
	maxIDLen   = 24
	maxExtLen  = 7
	filePrefix = "/f/"
)

// Storage paths, derived from DATA_DIR (default /data) by setDataDir.
var (
	storePath       string // uploaded files, with trailing slash
	metaPath        string // per-file metadata (<name>.json), with trailing slash
	burnPath        string // burn-after-reading files being served, with trailing slash
	logPath         string
	extConfigPath   string
	tokenConfigPath string
)

func setDataDir(dir string) {
	dir = strings.TrimRight(dir, "/")
	storePath = dir + "/files/"
	metaPath = dir + "/meta/"
	burnPath = dir + "/burn/"
	logPath = dir + "/uploads.log"
	extConfigPath = dir + "/extensions.json"
	tokenConfigPath = dir + "/tokens.json"
}

var (
	cfgMaxFilesizeMiB int    // MAX_FILESIZE (MiB)
	cfgMaxFileAgeDays int    // MAX_FILE_AGE (days)
	cfgMinFileAgeDays int    // MIN_FILE_AGE (days)
	cfgRequireAuth    bool   // REQUIRE_AUTH (true/false); default: true when UPLOAD_TOKEN is set
	cfgUploadToken    string // UPLOAD_TOKEN
	cfgAdminPassword  string // ADMIN_PASSWORD
	cfgAdminEmail     string // ADMIN_EMAIL
	cfgUploadRate     int    // UPLOAD_RATE_LIMIT: anonymous uploads per IP per hour; 0 = unlimited
)

func loadConfig() {
	setDataDir(env("DATA_DIR", "/data"))
	cfgMaxFilesizeMiB = envInt("MAX_FILESIZE", 256)
	cfgMaxFileAgeDays = envInt("MAX_FILE_AGE", 30)
	cfgMinFileAgeDays = envInt("MIN_FILE_AGE", 3)
	cfgUploadToken = os.Getenv("UPLOAD_TOKEN")
	cfgAdminPassword = env("ADMIN_PASSWORD", "changeme")
	cfgAdminEmail = env("ADMIN_EMAIL", "admin@example.com")
	cfgUploadRate = 60
	if v := os.Getenv("UPLOAD_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfgUploadRate = n
		}
	}

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

// saveJSON writes data as indented JSON to path, atomically and owner-only
// (tokens.json holds secrets).
func saveJSON(path string, data any) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("failed to marshal JSON for %s: %v", path, err)
		return
	}
	if err := writeFileAtomic(path, b, 0600); err != nil {
		log.Printf("failed to save %s: %v", path, err)
	}
}

// writeFileAtomic writes to a temp file in the same directory, then renames it
// over path so readers never see a half-written file.
func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

var (
	allowedExtsMu sync.RWMutex
	allowedExts   = map[string]bool{
		"jpg": true, "jpeg": true, "png": true, "gif": true,
		"webp": true, "avif": true, "heic": true,
		"pdf": true,
		"txt": true, "md": true, "csv": true, "log": true, "json": true,
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
	"avif": "", // ISOBMFF-based; DetectContentType returns octet-stream
	"heic": "", // ISOBMFF-based; same issue
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
	token  string // upload token used to log in ("upload" role only); memory only, never logged
}

var sessions sync.Map // token(string) → sessionData

// ── Login rate limiting ───────────────────────────────────────────────────────

const maxLoginAttempts = 10

type loginAttempt struct {
	count int
	last  time.Time
}

var (
	loginFailsMu sync.Mutex
	loginFails   = map[string]loginAttempt{}
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

const uploadRateWindow = time.Hour

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
	if cfgUploadRate == 0 {
		return true
	}
	uploadRateMu.Lock()
	defer uploadRateMu.Unlock()
	c := uploadRates[ip]
	now := time.Now()
	if now.After(c.reset) {
		// Start a new window.
		uploadRates[ip] = uploadCounter{count: 1, reset: now.Add(uploadRateWindow)}
		return true
	}
	if c.count >= cfgUploadRate {
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

func newSession(role, token string) string {
	tok := randHex(32)
	sessions.Store(tok, sessionData{
		expiry: time.Now().Add(sessionTTL),
		csrf:   randHex(16),
		role:   role,
		token:  token,
	})
	return tok
}

// currentSession returns the live session for the request, if any.
func currentSession(r *http.Request) (sessionData, bool) {
	c, err := r.Cookie("drop_session")
	if err != nil {
		return sessionData{}, false
	}
	v, ok := sessions.Load(c.Value)
	if !ok {
		return sessionData{}, false
	}
	sd := v.(sessionData)
	if time.Now().After(sd.expiry) {
		sessions.Delete(c.Value)
		return sessionData{}, false
	}
	// Upload sessions live only as long as their token: revoking an app token
	// (or rotating UPLOAD_TOKEN) also logs out browsers that used it.
	if sd.role == "upload" {
		if _, ok := validateUploadToken(sd.token); !ok {
			sessions.Delete(c.Value)
			return sessionData{}, false
		}
	}
	return sd, true
}

func isAdmin(r *http.Request) bool {
	sd, ok := currentSession(r)
	return ok && sd.role == "admin"
}

// isUploader returns true if the request has a valid upload or admin session.
func isUploader(r *http.Request) bool {
	sd, ok := currentSession(r)
	return ok && (sd.role == "upload" || sd.role == "admin")
}

// sessionUploadToken returns the upload token to show a logged-in user, or "".
// Upload sessions get the token they logged in with; admins get UPLOAD_TOKEN.
func sessionUploadToken(r *http.Request) string {
	sd, ok := currentSession(r)
	switch {
	case !ok:
		return ""
	case sd.role == "upload":
		return sd.token
	case sd.role == "admin":
		return cfgUploadToken
	}
	return ""
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

// randID returns n random characters from idAlphabet. Bytes >= 248 are
// rejected so every character is equally likely (256 % 62 != 0).
func randID(n int) string {
	const limit = 256 - 256%len(idAlphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n+8)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for _, v := range buf {
			if int(v) < limit && len(out) < n {
				out = append(out, idAlphabet[int(v)%len(idAlphabet)])
			}
		}
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
	// RemoteAddr is "ip:port"; drop the port so rate limits key on the client.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
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

	// Per-IP rate limit for anonymous uploads only; token holders and
	// logged-in users are trusted (revoke the token to stop abuse).
	if !cfgRequireAuth && !checkUploadRateLimit(clientIP(r)) {
		plainErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("Upload rate limit exceeded (%d/hour)", cfgUploadRate))
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
	// Optional earlier expiry and burn-after-reading; every upload gets a
	// delete token so its uploader can remove it.
	var meta fileMeta
	if v := r.FormValue("expires"); v != "" {
		d, err := parseExpiry(v)
		if err != nil {
			plainErr(w, http.StatusBadRequest, "Invalid expires (use e.g. 10m, 1h, 7d)")
			return
		}
		meta.Expires = time.Now().Add(d).Unix()
	}
	meta.Burn = isTruthy(r.FormValue("burn"))
	deleteToken := randHex(16)
	meta.DeleteHash = hashToken(deleteToken)

	out, basename, err := createUnique(idLen, ext)
	if err != nil {
		log.Printf("upload create error: %v", err)
		plainErr(w, http.StatusInternalServerError, "Could not save file")
		return
	}
	dest := storePath + basename

	// Re-encode JPEG/PNG/GIF to strip EXIF; raw copy for all others.
	werr := writeUploaded(f, out, ext)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(dest)
		var bad badImageError
		if errors.As(werr, &bad) {
			plainErr(w, http.StatusBadRequest, bad.Error())
			return
		}
		log.Printf("upload write error: %v", werr)
		plainErr(w, http.StatusInternalServerError, "Could not save file")
		return
	}

	if err := saveMeta(basename, meta); err != nil {
		removeStored(basename)
		log.Printf("upload meta error: %v", err)
		plainErr(w, http.StatusInternalServerError, "Could not save file")
		return
	}

	// Token is never logged.
	if fi, err := os.Stat(dest); err == nil {
		appendLog(r, fi.Size(), hdr.Filename, basename)
		if usedTokenID != "" {
			recordAppTokenUsage(usedTokenID, fi.Size())
		}
		exp := expiresAt(storeFile{basename, fi.Size(), fi.ModTime()}, meta)
		w.Header().Set("X-Expires", exp.UTC().Format(time.RFC3339))
	}
	w.Header().Set("X-Delete-Token", deleteToken)

	url := siteURL(r) + filePrefix + basename
	isCLI := r.FormValue("formatted") == "" &&
		!strings.Contains(r.Header.Get("Accept"), "text/html")
	if isCLI {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, url)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w,
			`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>drop</title>`+
				`<style>body{background:#111;color:#ccc;font-family:monospace;padding:2em;margin:0}a{color:#5af;word-break:break-all}@media(max-width:600px){body{padding:1em}}</style></head>`+
				`<body><p>Uploaded: <a href="%s">%s</a></p><p style="color:#555">delete token: %s</p></body></html>`,
			template.HTMLEscapeString(url), template.HTMLEscapeString(url), deleteToken)
	}
}

// 50 MP cap on decoded pixel area; guards against decompression-bomb DoS.
const maxImagePixels = 50_000_000

// GIF frames decode to 1 byte/pixel each, so cap the sum over all frames.
var maxGIFTotalPixels int64 = 200_000_000

// imgSem limits concurrent image re-encodes. Each 50 MP decode holds ~200 MB
// of pixel data; without a cap, many simultaneous uploads can exhaust memory.
var imgSem = make(chan struct{}, 4)

// badImageError marks an upload rejected for its content (client error).
type badImageError struct{ msg string }

func (e badImageError) Error() string { return e.msg }

// newID generates file IDs; a variable so tests can force collisions.
var newID = randID

// createUnique creates storePath/<random id>.<ext> exclusively, retrying on
// the rare ID collision instead of overwriting someone else's file.
func createUnique(idLen int, ext string) (*os.File, string, error) {
	for i := 0; i < 10; i++ {
		basename := newID(idLen) + "." + ext
		if !safeBasename.MatchString(basename) {
			return nil, "", fmt.Errorf("unsafe basename %q", basename)
		}
		f, err := os.OpenFile(storePath+basename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			return f, basename, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
		// Short IDs fill up; grow the ID after a few collisions.
		if i >= 2 && idLen < maxIDLen {
			idLen++
		}
	}
	return nil, "", fmt.Errorf("could not find a free file ID")
}

// writeUploaded re-encodes JPEG/PNG/GIF to strip EXIF; other types are copied
// as-is. Images that fail to decode are rejected rather than stored raw, since
// raw bytes would keep EXIF and are served inline.
func writeUploaded(src io.ReadSeeker, out io.Writer, ext string) error {
	switch ext {
	case "jpg", "jpeg", "png", "gif":
	default:
		_, err := io.Copy(out, src)
		return err
	}

	// Check dimensions before full decode; image.DecodeConfig reads header only.
	cfg, _, err := image.DecodeConfig(src)
	if err != nil {
		return badImageError{"Could not decode image"}
	}
	if int64(cfg.Width)*int64(cfg.Height) > maxImagePixels {
		return badImageError{fmt.Sprintf("Image dimensions %dx%d exceed %d MP limit",
			cfg.Width, cfg.Height, maxImagePixels/1_000_000)}
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if ext == "gif" {
		total, err := gifTotalPixels(src)
		if err != nil {
			return badImageError{"Could not decode image"}
		}
		if total > maxGIFTotalPixels {
			return badImageError{fmt.Sprintf("GIF frames exceed %d MP in total",
				maxGIFTotalPixels/1_000_000)}
		}
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}

	imgSem <- struct{}{}
	defer func() { <-imgSem }()

	switch ext {
	case "gif":
		g, err := gif.DecodeAll(src)
		if err != nil {
			return badImageError{"Could not decode image"}
		}
		return gif.EncodeAll(out, g)
	case "png":
		img, err := png.Decode(src)
		if err != nil {
			return badImageError{"Could not decode image"}
		}
		return png.Encode(out, img)
	default: // jpg, jpeg
		img, err := jpeg.Decode(src)
		if err != nil {
			return badImageError{"Could not decode image"}
		}
		return jpeg.Encode(out, img, &jpeg.Options{Quality: 92})
	}
}

// gifTotalPixels walks the GIF block structure without decoding pixel data and
// returns the summed area of all frames, which is what gif.DecodeAll allocates.
func gifTotalPixels(r io.Reader) (int64, error) {
	br := bufio.NewReader(r)
	hdr := make([]byte, 13) // signature + logical screen descriptor
	if _, err := io.ReadFull(br, hdr); err != nil {
		return 0, err
	}
	if string(hdr[:3]) != "GIF" {
		return 0, fmt.Errorf("not a GIF")
	}
	if hdr[10]&0x80 != 0 { // global color table
		if _, err := br.Discard(3 << (hdr[10]&7 + 1)); err != nil {
			return 0, err
		}
	}
	skipSubBlocks := func() error {
		for {
			n, err := br.ReadByte()
			if err != nil {
				return err
			}
			if n == 0 {
				return nil
			}
			if _, err := br.Discard(int(n)); err != nil {
				return err
			}
		}
	}
	var total int64
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case 0x21: // extension: label byte, then sub-blocks
			if _, err := br.ReadByte(); err != nil {
				return 0, err
			}
			if err := skipSubBlocks(); err != nil {
				return 0, err
			}
		case 0x2C: // image descriptor
			d := make([]byte, 9)
			if _, err := io.ReadFull(br, d); err != nil {
				return 0, err
			}
			w := int64(d[4]) | int64(d[5])<<8
			h := int64(d[6]) | int64(d[7])<<8
			total += w * h
			if total > maxGIFTotalPixels {
				return total, nil
			}
			if d[8]&0x80 != 0 { // local color table
				if _, err := br.Discard(3 << (d[8]&7 + 1)); err != nil {
					return 0, err
				}
			}
			if _, err := br.ReadByte(); err != nil { // LZW minimum code size
				return 0, err
			}
			if err := skipSubBlocks(); err != nil {
				return 0, err
			}
		case 0x3B: // trailer
			return total, nil
		default:
			return 0, fmt.Errorf("bad GIF block 0x%02x", b)
		}
	}
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

// ── Per-file metadata ─────────────────────────────────────────────────────────

// fileMeta is stored at metaPath/<name>.json next to each upload.
type fileMeta struct {
	DeleteHash string `json:"delete_hash,omitempty"` // sha256 of the uploader's delete token
	Expires    int64  `json:"expires,omitempty"`     // unix seconds; 0 = retention formula only
	Burn       bool   `json:"burn,omitempty"`        // delete after the first download
}

func metaFile(name string) string { return metaPath + name + ".json" }

// loadMeta returns the file's metadata; files from before metadata existed
// (or with a missing sidecar) get the zero value.
func loadMeta(name string) fileMeta {
	var m fileMeta
	loadJSON(metaFile(name), &m)
	return m
}

func saveMeta(name string, m fileMeta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(metaFile(name), b, 0600)
}

// removeStored deletes an upload and its metadata.
func removeStored(name string) error {
	err := os.Remove(storePath + name)
	os.Remove(metaFile(name))
	return err
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// expiresAt is when a file expires: the retention formula, or earlier if the
// uploader asked for it.
func expiresAt(f storeFile, m fileMeta) time.Time {
	t := f.mtime.Add(time.Duration(retentionDays(f.size) * float64(24*time.Hour)))
	if m.Expires > 0 {
		if e := time.Unix(m.Expires, 0); e.Before(t) {
			t = e
		}
	}
	return t
}

// parseExpiry accepts Go durations ("10m", "1h30m") plus a "d" suffix for days.
func parseExpiry(v string) (time.Duration, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	var d time.Duration
	if n, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, err
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, err
		}
	}
	if d < time.Minute || d > 3650*24*time.Hour {
		return 0, fmt.Errorf("expiry out of range")
	}
	return d, nil
}

func isTruthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// sweepMeta removes metadata whose file is gone and leftover burn files from
// requests that died mid-download.
func sweepMeta() {
	if entries, err := os.ReadDir(metaPath); err == nil {
		for _, e := range entries {
			name, ok := strings.CutSuffix(e.Name(), ".json")
			if !ok {
				continue
			}
			if _, err := os.Stat(storePath + name); os.IsNotExist(err) {
				os.Remove(metaPath + e.Name())
			}
		}
	}
	if entries, err := os.ReadDir(burnPath); err == nil {
		for _, e := range entries {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
				os.Remove(burnPath + e.Name())
			}
		}
	}
}

// ── Purge ─────────────────────────────────────────────────────────────────────

// purgeDecay removes files whose age exceeds the decay-formula retention period.
func purgeDecay() int {
	files := readStoreFiles()
	n := 0
	now := time.Now()
	for _, f := range files {
		if now.After(expiresAt(f, loadMeta(f.name))) {
			removeStored(f.name)
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
			removeStored(f.name)
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
		if err := removeStored(f.name); err == nil {
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
		sweepMeta()
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
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodDelete:
		handleDelete(w, r, name)
		return
	default:
		w.Header().Set("Allow", "GET, HEAD, DELETE")
		plainErr(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	fi, err := os.Stat(storePath + name)
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	meta := loadMeta(name)
	if time.Now().After(expiresAt(storeFile{name, fi.Size(), fi.ModTime()}, meta)) {
		removeStored(name)
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

	path := storePath + name
	if meta.Burn {
		w.Header().Set("Cache-Control", "no-store")
		// Admins can look without burning; HEAD never burns.
		if r.Method == http.MethodGet && !isAdmin(r) {
			// Rename is atomic, so exactly one request claims the file.
			claimed := burnPath + randHex(8) + "-" + name
			if err := os.Rename(path, claimed); err != nil {
				http.NotFound(w, r)
				return
			}
			os.Remove(metaFile(name))
			defer os.Remove(claimed)
			path = claimed
			// Always send the full body: a 206 or 304 would burn the file
			// without delivering it.
			for _, h := range []string{"Range", "If-Range", "If-Modified-Since", "If-None-Match"} {
				r.Header.Del(h)
			}
		}
	}

	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// handleDelete lets an uploader remove their file with the delete token
// returned in the upload's X-Delete-Token header.
func handleDelete(w http.ResponseWriter, r *http.Request, name string) {
	if _, err := os.Stat(storePath + name); err != nil {
		http.NotFound(w, r)
		return
	}
	tok := r.Header.Get("X-Delete-Token")
	meta := loadMeta(name)
	if tok == "" || meta.DeleteHash == "" || !secureEqual(hashToken(tok), meta.DeleteHash) {
		plainErr(w, http.StatusForbidden, "Invalid delete token")
		return
	}
	if err := removeStored(name); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Deleted")
}

// handleHealth reports whether the store directory is reachable.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(storePath); err != nil {
		plainErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintln(w, "ok")
}

// runHealthcheck is the Docker HEALTHCHECK: GET /healthz on the local port.
func runHealthcheck(port string) int {
	c := http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://127.0.0.1" + port + "/healthz")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("status", resp.StatusCode)
		return 1
	}
	return 0
}

// ── Admin panel ───────────────────────────────────────────────────────────────

type adminFileRow struct {
	Name, Size, Age, ExpiresIn string
	IsImage, Burn              bool
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
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>drop :: admin</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
*{box-sizing:border-box}
body{background:#111;color:#ccc;font-family:monospace;font-size:14px;padding:2em;margin:0}
a{color:#5af}
input,button{background:#222;color:#ccc;border:1px solid #444;padding:6px 8px;font-family:monospace}
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
@media(max-width:600px){body{padding:1em;font-size:13px}.prompt{font-size:12px;word-break:break-all}.tbl-wrap{overflow-x:auto;margin:0 -1em;padding:0 1em}table{min-width:500px}input[name=days]{width:3em!important}input[name=token_name]{width:100%!important;margin-bottom:.5em}button{padding-top:10px;padding-bottom:10px}.tbl-wrap button{padding-top:6px;padding-bottom:6px}input[type=text],input[type=number],input[type=password]{padding-top:10px;padding-bottom:10px}}
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
<div class="tbl-wrap">
<table>
<tr><th><input type="checkbox" id="selall" title="select all"></th><th></th><th>filename</th><th>size</th><th>age</th><th>expires in</th><th></th></tr>
{{range .Files}}<tr>
  <td><input type="checkbox" class="fsel" data-name="{{.Name}}"></td>
  <td>{{if .IsImage}}<img class="thumb" src="/f/{{.Name}}" alt="" loading="lazy">{{end}}</td>
  <td><a href="/f/{{.Name}}">{{.Name}}</a></td>
  <td>{{.Size}}</td>
  <td>{{.Age}}</td>
  <td>{{.ExpiresIn}}{{if .Burn}} <span style="color:#fa5">burn</span>{{end}}</td>
  <td><form method="POST" action="/admin" onsubmit="return confirm('Delete {{.Name}}?')">
    <input type="hidden" name="csrf" value="{{$.CSRF}}">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="file" value="{{.Name}}">
    <button class="danger">del</button>
  </form></td>
</tr>{{end}}
</table>
</div>
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
{{if .NewToken}}<div class="flash" style="word-break:break-all">New token: <code>{{.NewToken}}</code><br><code style="color:#ccc">export DROP_TOKEN={{.NewToken}}</code><br><small style="color:#555">Copy now — it won't be shown again.</small></div>{{end}}
{{if .Tokens}}
<div class="tbl-wrap">
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
</div>
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
			tok := newSession("admin", "")
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
			} else if err := removeStored(name); err != nil {
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
				if err := removeStored(name); err == nil {
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
		meta := loadMeta(f.name)
		expDays := expiresAt(f, meta).Sub(now).Hours() / 24
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
			IsImage:   inlineExts[ext] && !meta.Burn, // a thumbnail would not burn, but keep it hidden
			Burn:      meta.Burn,
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
	Token    string // shown to logged-in users only
	LoggedIn bool
	AuthErr  bool
	Email    string
}

var indexTpl = template.Must(template.New("index").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>drop</title>
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<style>
*{box-sizing:border-box}
body{background:#111;color:#ccc;font-family:monospace;font-size:14px;padding:2em;margin:0;max-width:760px}
a{color:#5af}
pre{background:#0a0a0a;padding:1em;overflow-x:auto;border-left:3px solid #252525;margin:0}
input[type=file],input[type=password]{background:#222;color:#ccc;border:1px solid #444;padding:6px 8px;font-family:monospace}input[type=file]::file-selector-button{background:#333;color:#ccc;border:1px solid #555;padding:3px 10px;font-family:monospace;cursor:pointer}
button{background:#222;color:#ccc;border:1px solid #444;padding:6px 16px;font-family:monospace;cursor:pointer}
button:hover{background:#333}
h1{color:#5af;margin:0 0 .25em;font-size:2em}
h2{color:#444;font-size:12px;text-transform:uppercase;letter-spacing:.1em;margin:2em 0 .5em;border-bottom:1px solid #1e1e1e;padding-bottom:.25em}
.dim{color:#555}
select,textarea,input[type=text]{background:#222;color:#ccc;border:1px solid #444;padding:6px 8px;font-family:monospace}
textarea{width:100%;margin-top:.5em;resize:vertical}
.opts{margin-top:1em;color:#555;display:flex;flex-wrap:wrap;gap:.5em 1.5em;align-items:center}
details{margin-top:1em}summary{color:#555;cursor:pointer}
.flist{list-style:none;padding:0;margin:0 0 1em}.flist li{padding:4px 0;border-bottom:1px solid #1a1a1a;word-break:break-all}
.mini{padding:2px 8px;margin-left:.5em;font-size:12px}
.ok{color:#0d0}.bad{color:#f55}.tag{color:#fa5}
@media(max-width:600px){body{padding:1em;font-size:13px}h1{font-size:1.4em}pre{font-size:11px}#dropzone{padding:1em!important}#uform{display:flex;flex-wrap:wrap;gap:.5em}#uform input[type=file]{width:100%}#uform button{margin-left:0!important;width:100%}#uform .dim{margin-left:0!important;display:block;margin-top:.5em}#tok{width:100%!important;margin-bottom:.5em}#dropzone form button{margin-left:0!important;display:block;margin-top:.5em;width:100%}button,input[type=file],input[type=password]{padding-top:10px!important;padding-bottom:10px!important}}
</style></head><body>
<h1>drop</h1>
<p class="dim">max {{.MaxSize}} MiB &nbsp;&middot;&nbsp; files live {{.MinAge}}&ndash;{{.MaxAge}} days</p>

<h2>upload via curl</h2>
{{- $auth := ""}}{{if .HasToken}}{{$auth = "-H \"Authorization: Bearer $DROP_TOKEN\" \\\n     "}}{{end}}
<pre>
{{- if .HasToken}}# set your upload token once (add to ~/.bashrc to keep it)
export DROP_TOKEN={{if .Token}}<span id="tokval">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>{{else}}&lt;your upload token&gt;{{end}}

{{end -}}
# upload
curl {{$auth}}-F "file=@photo.jpg" {{.SiteURL}}

# pipe with extension
echo "hello" | curl {{$auth}}-F "file=@-;filename=note.txt" {{.SiteURL}}

# custom id length (4-24)
curl {{$auth}}-F "file=@report.pdf" -F "id_length=12" {{.SiteURL}}

# expire sooner (10m, 1h, 7d) and/or delete after the first download
curl {{$auth}}-F "file=@secret.pdf" -F "expires=1h" -F "burn=1" {{.SiteURL}}

# delete your upload: -i shows the X-Delete-Token response header
curl -i {{$auth}}-F "file=@photo.jpg" {{.SiteURL}}
curl -X DELETE -H "X-Delete-Token: &lt;token&gt;" {{.SiteURL}}/f/abcd.jpg

# shell helper:  drop photo.jpg
drop() { curl {{$auth}}-F "file=@$1" {{.SiteURL}}; }
{{- if not .HasToken}}

# ShareX / Hupl configs
curl "{{.SiteURL}}?sharex" -o drop.sxcu
curl "{{.SiteURL}}?hupl"   -o drop.hupl
{{- end}}</pre>
{{- if .HasToken}}
{{- if .Token}}
<p id="tokbar" data-tok="{{.Token}}" style="margin:.5em 0 0">
  <button type="button" id="tokshow">show token</button>
  <button type="button" id="tokcopy" style="margin-left:.5em">copy export line</button>
  <span class="dim" style="margin-left:.5em">&middot; <a href="/?sharex">ShareX config</a> &middot; <a href="/?hupl">Hupl config</a></span>
</p>
<script>
(function(){
  var bar = document.getElementById('tokbar');
  var tok = bar.dataset.tok;
  var val = document.getElementById('tokval');
  var show = document.getElementById('tokshow');
  var copy = document.getElementById('tokcopy');
  var mask = val.textContent;
  show.addEventListener('click', function(){
    var hidden = val.textContent === mask;
    val.textContent = hidden ? tok : mask;
    show.textContent = hidden ? 'hide token' : 'show token';
  });
  copy.addEventListener('click', function(){
    var line = "export DROP_TOKEN='" + tok.replace(/'/g, "'\\''") + "'";
    function done(){ copy.textContent = 'copied'; setTimeout(function(){ copy.textContent = 'copy export line'; }, 1500); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(line).then(done, function(){ window.prompt('Copy:', line); });
    } else {
      window.prompt('Copy:', line);
    }
  });
})();
</script>
{{- else if .LoggedIn}}
<p class="dim" style="margin:.5em 0 0">no UPLOAD_TOKEN is set &mdash; generate an app token in the <a href="/admin">admin panel</a></p>
{{- else}}
<p class="dim" style="margin:.5em 0 0">log in below with your upload token to reveal it here and download ShareX / Hupl configs</p>
{{- end}}
{{- end}}

<h2>upload via browser</h2>
<div id="dropzone" style="border:2px dashed #333;padding:1.5em;margin-bottom:1em;transition:border-color .2s,background .2s">
{{- if and .HasToken (not .LoggedIn)}}
  <form method="POST" style="margin-bottom:1em">
    <input type="hidden" name="action" value="login">
    <label style="color:#555">upload token <input type="password" name="token" id="tok" style="width:220px"></label>
    <button type="submit" style="margin-left:.5em">login</button>
    {{- if .AuthErr}}
    <span style="color:#f55;margin-left:.5em">incorrect token</span>
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
  <p style="margin:0 0 1em;color:#555">drag &amp; drop files here</p>
  <form id="uform" method="POST" enctype="multipart/form-data">
    <input type="file" name="file" id="fi" multiple>
    <input type="hidden" name="formatted" value="true">
    <button type="submit" style="margin-left:.5em">upload</button>
    <span class="dim" style="margin-left:.5em">or paste image</span>
    <div class="opts">
      <label>expires <select name="expires" id="exp">
        <option value="">default</option><option>10m</option><option>1h</option><option>1d</option><option>7d</option>
      </select></label>
      <label><input type="checkbox" name="burn" value="1" id="burn"> delete after first download</label>
    </div>
  </form>
  <details id="pastebox">
    <summary>paste text</summary>
    <textarea id="ptext" rows="8" spellcheck="false" placeholder="text to share"></textarea>
    <div style="margin-top:.5em">
      <input type="text" id="pname" value="paste.txt" maxlength="64" aria-label="filename">
      <button type="button" id="pbtn" style="margin-left:.5em">upload text</button>
    </div>
  </details>
{{- end}}
</div>
<div id="progress" style="display:none;margin-bottom:1em">
  <div style="background:#222;border:1px solid #444;height:22px;position:relative">
    <div id="pbar" style="background:#5af;height:100%;width:0%;transition:width .15s"></div>
    <span id="ptxt" style="position:absolute;top:0;left:0;right:0;text-align:center;line-height:22px;font-size:12px"></span>
  </div>
</div>
<ul id="results" class="flist"></ul>
<div id="recentwrap" style="display:none">
  <h2>recent uploads <span style="text-transform:none;letter-spacing:0">(this browser)</span></h2>
  <ul id="recent" class="flist"></ul>
  <button type="button" id="rclear" class="mini">forget list</button>
</div>

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
  var exp = document.getElementById('exp');
  var burn = document.getElementById('burn');
  var prog = document.getElementById('progress');
  var pbar = document.getElementById('pbar');
  var ptxt = document.getElementById('ptxt');
  var results = document.getElementById('results');
  var recentWrap = document.getElementById('recentwrap');
  var recent = document.getElementById('recent');
  var RKEY = 'drop_recent';

  // ── recent uploads (localStorage, this browser only) ──
  function loadRecent() {
    try { return JSON.parse(localStorage.getItem(RKEY)) || []; } catch (e) { return []; }
  }
  function saveRecent(list) {
    try { localStorage.setItem(RKEY, JSON.stringify(list.slice(0, 50))); } catch (e) {}
  }
  function liveRecent() {
    var now = Date.now();
    return loadRecent().filter(function(x) { return !x.exp || Date.parse(x.exp) > now; });
  }
  function forget(url) {
    saveRecent(loadRecent().filter(function(x) { return x.url !== url; }));
  }
  function renderRecent() {
    var list = liveRecent();
    saveRecent(list);
    recent.textContent = '';
    list.forEach(function(item) { recent.appendChild(fileRow(item)); });
    recentWrap.style.display = list.length ? 'block' : 'none';
  }
  document.getElementById('rclear').addEventListener('click', function() {
    if (confirm('Forget the list? Files stay online until they expire.')) { saveRecent([]); renderRecent(); }
  });

  // ── rows ──
  function mini(label, fn) {
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'mini'; b.textContent = label;
    b.addEventListener('click', function() { fn(b); });
    return b;
  }
  function copyText(text, b) {
    function done() { b.textContent = 'copied'; setTimeout(function() { b.textContent = 'copy'; }, 1500); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function() { window.prompt('Copy:', text); });
    } else {
      window.prompt('Copy:', text);
    }
  }
  function fmtLeft(iso) {
    var ms = Date.parse(iso) - Date.now();
    if (!(ms > 0)) return '';
    var m = Math.round(ms / 60000);
    if (m < 60) return m + 'm';
    if (m < 2880) return Math.round(m / 60) + 'h';
    return Math.round(m / 1440) + 'd';
  }
  function fileRow(item) {
    var li = document.createElement('li');
    var ok = document.createElement('span');
    ok.className = 'ok'; ok.textContent = '\u2713 ';
    var a = document.createElement('a');
    a.href = item.url; a.textContent = item.url;
    li.appendChild(ok); li.appendChild(a);
    var info = document.createElement('span');
    info.className = 'dim';
    var left = item.exp ? fmtLeft(item.exp) : '';
    info.textContent = (item.name ? '  ' + item.name : '') + (left ? ' \u00b7 ' + left + ' left' : '');
    li.appendChild(info);
    if (item.burn) {
      var t = document.createElement('span');
      t.className = 'tag'; t.textContent = ' burn';
      li.appendChild(t);
    }
    li.appendChild(mini('copy', function(b) { copyText(item.url, b); }));
    if (item.del) {
      li.appendChild(mini('delete', function(b) {
        if (!confirm('Delete ' + item.url + '?')) return;
        b.disabled = true;
        fetch(item.url, { method: 'DELETE', headers: { 'X-Delete-Token': item.del } })
          .then(function(r) {
            if (r.ok || r.status === 404) {
              forget(item.url);
              li.style.opacity = '.4'; a.removeAttribute('href'); b.textContent = 'deleted';
              renderRecent();
            } else {
              return r.text().then(function(t) { b.disabled = false; alert(t.trim()); });
            }
          }, function() { b.disabled = false; alert('Delete failed'); });
      }));
    }
    return li;
  }
  function errorRow(name, msg) {
    var li = document.createElement('li');
    var x = document.createElement('span');
    x.className = 'bad'; x.textContent = '\u2717 ';
    li.appendChild(x);
    li.appendChild(document.createTextNode((name ? name + ': ' : '') + msg));
    results.insertBefore(li, results.firstChild);
  }

  // ── uploads (one at a time) ──
  var queue = [], busy = false;
  // Options are captured when files are queued, not when they upload.
  function enqueue(files) {
    var opts = { exp: exp.value, burn: burn.checked };
    for (var i = 0; i < files.length; i++) queue.push({ file: files[i], opts: opts });
    next();
  }
  function next() {
    if (busy || !queue.length) return;
    busy = true;
    var job = queue.shift();
    uploadFile(job.file, job.opts, function() { busy = false; next(); });
  }
  function uploadFile(file, opts, done) {
    var name = file.name || 'paste.png';
    var fd = new FormData();
    fd.append('file', file, name);
    if (opts.exp) fd.append('expires', opts.exp);
    if (opts.burn) fd.append('burn', '1');

    var label = name + (queue.length ? ' (+' + queue.length + ' queued)' : '');
    prog.style.display = 'block';
    pbar.style.width = '0%';
    ptxt.textContent = label + ' 0%';

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/');
    xhr.upload.onprogress = function(e) {
      if (e.lengthComputable) {
        var pct = Math.round(e.loaded / e.total * 100);
        pbar.style.width = pct + '%';
        ptxt.textContent = label + ' ' + pct + '%';
      }
    };
    xhr.onload = function() {
      if (xhr.status >= 200 && xhr.status < 300) {
        var item = {
          url: xhr.responseText.trim(),
          del: xhr.getResponseHeader('X-Delete-Token') || '',
          exp: xhr.getResponseHeader('X-Expires') || '',
          name: name,
          burn: opts.burn
        };
        var list = loadRecent();
        list.unshift(item);
        saveRecent(list);
        results.insertBefore(fileRow(item), results.firstChild);
        renderRecent();
      } else {
        errorRow(name, xhr.responseText.trim() || ('HTTP ' + xhr.status));
      }
      if (!queue.length) prog.style.display = 'none';
      done();
    };
    xhr.onerror = function() {
      errorRow(name, 'upload failed');
      if (!queue.length) prog.style.display = 'none';
      done();
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
    if (e.dataTransfer.files.length) enqueue(e.dataTransfer.files);
  });

  // Form submit via XHR
  form.addEventListener('submit', function(e) {
    if (fi.files.length > 0) {
      e.preventDefault();
      enqueue(fi.files);
      fi.value = '';
    }
  });

  // Paste image anywhere (text pastes into the textarea as usual)
  document.addEventListener('paste', function(e) {
    var cd = e.clipboardData || window.clipboardData;
    if (!cd) return;
    for (var i = 0; i < cd.items.length; i++) {
      if (cd.items[i].kind === 'file') {
        var blob = cd.items[i].getAsFile();
        if (blob) { e.preventDefault(); enqueue([blob]); return; }
      }
    }
  });

  // Paste text
  document.getElementById('pbtn').addEventListener('click', function() {
    var text = document.getElementById('ptext').value;
    if (!text) return;
    var name = document.getElementById('pname').value.trim() || 'paste.txt';
    if (name.indexOf('.') < 0) name += '.txt';
    enqueue([new File([text], name, { type: 'text/plain' })]);
    document.getElementById('ptext').value = '';
  });

  renderRecent();
})();
</script>
{{- end}}
</body></html>`))

// ── ShareX / Hupl configs ─────────────────────────────────────────────────────

// resolveConfigToken picks the token to bake into a ShareX/Hupl config.
// Upload sessions always get their own token; admins may pick an app token by
// ID. Anonymous callers (only allowed when auth is off) never receive a token.
func resolveConfigToken(r *http.Request) (string, error) {
	sd, ok := currentSession(r)
	if ok && sd.role == "upload" {
		return sd.token, nil
	}
	if !ok || sd.role != "admin" {
		if cfgRequireAuth {
			return "", errUnauthorized
		}
		return "", nil
	}
	if id := r.URL.Query().Get("token"); id != "" {
		t, ok := getAppTokenByID(id)
		if !ok {
			return "", fmt.Errorf("unknown token ID")
		}
		return t.Token, nil
	}
	if hasAppTokens() && cfgUploadToken == "" {
		return "", fmt.Errorf("app tokens exist; specify ?token=<id>")
	}
	return cfgUploadToken, nil
}

var errUnauthorized = errors.New("Unauthorized")

// writeConfigErr maps a resolveConfigToken error to an HTTP response.
func writeConfigErr(w http.ResponseWriter, err error) {
	if err == errUnauthorized {
		plainErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	plainErr(w, http.StatusBadRequest, err.Error())
}

func serveShareX(w http.ResponseWriter, r *http.Request) {
	tok, err := resolveConfigToken(r)
	if err != nil {
		writeConfigErr(w, err)
		return
	}
	headers := ""
	if tok != "" {
		authJSON, _ := json.Marshal("Bearer " + tok)
		headers = fmt.Sprintf(`,
  "Headers": {"Authorization": %s}`, authJSON)
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
	tok, err := resolveConfigToken(r)
	if err != nil {
		writeConfigErr(w, err)
		return
	}
	auth := ""
	if tok != "" {
		authJSON, _ := json.Marshal("Bearer " + tok)
		auth = fmt.Sprintf(`"Authorization": %s`, authJSON)
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
	sess := newSession("upload", tok)
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
		// Multipart bodies go straight to handleUpload: calling FormValue here
		// would parse the whole upload before auth and the size cap run.
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/") {
			handleUpload(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		switch r.FormValue("action") {
		case "login":
			handleTokenLogin(w, r)
		case "logout":
			destroySession(r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		default:
			plainErr(w, http.StatusBadRequest, "Bad request: expected multipart/form-data upload")
		}
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTpl.Execute(w, indexData{
		SiteURL:  siteURL(r),
		MaxSize:  cfgMaxFilesizeMiB,
		MinAge:   cfgMinFileAgeDays,
		MaxAge:   cfgMaxFileAgeDays,
		HasToken: cfgRequireAuth,
		Token:    sessionUploadToken(r),
		LoggedIn: isUploader(r),
		AuthErr:  r.URL.Query().Get("err") == "badtoken",
		Email:    cfgAdminEmail,
	})
}

// ── Main ──────────────────────────────────────────────────────────────────────

func newMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/f/", handleFiles)
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/admin/", handleAdmin)
	return withSecureHeaders(mux)
}

func main() {
	loadConfig()

	port := env("PORT", "8080")
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	// Purge mode: manual or cron-driven one-off purge.
	if len(os.Args) > 1 && os.Args[1] == "purge" {
		os.MkdirAll(storePath, 0755)
		n := purgeDecay()
		sweepMeta()
		fmt.Printf("purged %d files\n", n)
		return
	}
	// Health mode: Docker HEALTHCHECK.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		os.Exit(runHealthcheck(port))
	}

	for _, d := range []string{storePath, metaPath, burnPath} {
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Printf("mkdir %s: %v", d, err)
		}
	}
	openLogWriter()

	go startCleaner()

	srv := &http.Server{
		Addr:    port,
		Handler: newMux(),

		ReadHeaderTimeout: 10 * time.Second, // Slowloris defence
		ReadTimeout:       10 * time.Minute, // must cover slow body uploads
		WriteTimeout:      10 * time.Minute, // must cover slow body uploads (same as ReadTimeout)
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("drop listening on %s", port)
	log.Fatal(srv.ListenAndServe())
}
