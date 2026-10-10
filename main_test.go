package main

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testHandler http.Handler

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "drop-test")
	if err != nil {
		panic(err)
	}
	os.Setenv("DATA_DIR", dir)
	os.Setenv("ADMIN_PASSWORD", "adminpw")
	os.Unsetenv("UPLOAD_TOKEN")
	os.Unsetenv("REQUIRE_AUTH")
	loadConfig()
	for _, d := range []string{storePath, metaPath, burnPath} {
		os.MkdirAll(d, 0755)
	}
	testHandler = newMux()
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// setAuth configures upload auth for one test and restores it afterwards.
func setAuth(t *testing.T, token string) {
	t.Helper()
	oldTok, oldReq := cfgUploadToken, cfgRequireAuth
	cfgUploadToken, cfgRequireAuth = token, token != ""
	t.Cleanup(func() { cfgUploadToken, cfgRequireAuth = oldTok, oldReq })
}

type upload struct {
	name    string
	data    []byte
	fields  map[string]string
	headers map[string]string
	cookie  string
}

func doUpload(t *testing.T, u upload) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range u.fields {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", u.name)
	fw.Write(u.data)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for k, v := range u.headers {
		req.Header.Set(k, v)
	}
	if u.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "drop_session", Value: u.cookie})
	}
	rec := httptest.NewRecorder()
	testHandler.ServeHTTP(rec, req)
	return rec
}

func do(method, target string, headers map[string]string, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "drop_session", Value: cookie})
	}
	rec := httptest.NewRecorder()
	testHandler.ServeHTTP(rec, req)
	return rec
}

// storedName returns "<id>.<ext>" from an upload response URL.
func storedName(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", rec.Code, rec.Body.String())
	}
	u := strings.TrimSpace(rec.Body.String())
	i := strings.LastIndex(u, filePrefix)
	if i < 0 {
		t.Fatalf("unexpected upload response %q", u)
	}
	return u[i+len(filePrefix):]
}

func loginUpload(t *testing.T, token string) string {
	t.Helper()
	form := url.Values{"action": {"login"}, "token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	testHandler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "drop_session" {
			return c.Value
		}
	}
	t.Fatalf("login with token failed: %d", rec.Code)
	return ""
}

func pngBytes(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func TestUploadAuth(t *testing.T) {
	setAuth(t, "secret")
	txt := upload{name: "a.txt", data: []byte("hello")}

	if rec := doUpload(t, txt); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}
	txt.headers = map[string]string{"Authorization": "Bearer wrong"}
	if rec := doUpload(t, txt); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rec.Code)
	}
	txt.headers = map[string]string{"Authorization": "Bearer secret"}
	storedName(t, doUpload(t, txt))
	txt.headers = map[string]string{"X-Upload-Token": "secret"}
	storedName(t, doUpload(t, txt))
	txt.headers = nil
	txt.fields = map[string]string{"token": "secret"}
	storedName(t, doUpload(t, txt))
}

func TestNonMultipartPostRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	testHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestIndexShowsSessionToken(t *testing.T) {
	setAuth(t, "master")

	anon := do(http.MethodGet, "/", nil, "")
	if strings.Contains(anon.Body.String(), "master") {
		t.Fatal("anonymous index page leaks the upload token")
	}

	app := generateAppToken("test")
	t.Cleanup(func() { revokeAppToken(app.ID) })
	sess := loginUpload(t, app.Token)
	if body := do(http.MethodGet, "/", nil, sess).Body.String(); !strings.Contains(body, `data-tok="`+app.Token+`"`) {
		t.Fatal("logged-in index page does not show the session's token")
	}

	// Revoking the token ends the session.
	revokeAppToken(app.ID)
	if rec := doUpload(t, upload{name: "a.txt", data: []byte("x"), cookie: sess}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session upload: got %d, want 401", rec.Code)
	}
}

func TestConfigTokens(t *testing.T) {
	setAuth(t, "master")
	if rec := do(http.MethodGet, "/?sharex", nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous sharex with auth: got %d, want 401", rec.Code)
	}

	app := generateAppToken("cfg")
	t.Cleanup(func() { revokeAppToken(app.ID) })
	sess := loginUpload(t, app.Token)
	for _, q := range []string{"/?sharex", "/?hupl", "/?hupl&token=other"} {
		rec := do(http.MethodGet, q, nil, sess)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Bearer "+app.Token) {
			t.Fatalf("%s: got %d %s, want config with session token", q, rec.Code, rec.Body.String())
		}
		if !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s: invalid JSON", q)
		}
	}

	// Auth off but token configured: anonymous configs must not contain it.
	cfgRequireAuth = false
	if body := do(http.MethodGet, "/?sharex", nil, "").Body.String(); strings.Contains(body, "Authorization") {
		t.Fatalf("anonymous config leaks a token: %s", body)
	}
}

func TestDeleteToken(t *testing.T) {
	setAuth(t, "")
	rec := doUpload(t, upload{name: "d.txt", data: []byte("delete me")})
	name := storedName(t, rec)
	tok := rec.Header().Get("X-Delete-Token")
	if tok == "" {
		t.Fatal("no X-Delete-Token header")
	}

	if r := do(http.MethodDelete, "/f/"+name, map[string]string{"X-Delete-Token": "nope"}, ""); r.Code != http.StatusForbidden {
		t.Fatalf("wrong delete token: got %d, want 403", r.Code)
	}
	if r := do(http.MethodDelete, "/f/"+name, nil, ""); r.Code != http.StatusForbidden {
		t.Fatalf("missing delete token: got %d, want 403", r.Code)
	}
	if r := do(http.MethodDelete, "/f/"+name, map[string]string{"X-Delete-Token": tok}, ""); r.Code != http.StatusOK {
		t.Fatalf("delete: got %d, want 200", r.Code)
	}
	if r := do(http.MethodGet, "/f/"+name, nil, ""); r.Code != http.StatusNotFound {
		t.Fatalf("after delete: got %d, want 404", r.Code)
	}
	if _, err := os.Stat(metaFile(name)); !os.IsNotExist(err) {
		t.Fatal("metadata left behind after delete")
	}
}

func TestExpires(t *testing.T) {
	setAuth(t, "")
	if rec := doUpload(t, upload{name: "e.txt", data: []byte("x"), fields: map[string]string{"expires": "soon"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad expires: got %d, want 400", rec.Code)
	}

	rec := doUpload(t, upload{name: "e.txt", data: []byte("x"), fields: map[string]string{"expires": "1h"}})
	name := storedName(t, rec)
	exp, err := time.Parse(time.RFC3339, rec.Header().Get("X-Expires"))
	if err != nil || exp.Sub(time.Now()) > time.Hour+time.Minute {
		t.Fatalf("X-Expires = %q, want about 1h from now", rec.Header().Get("X-Expires"))
	}
	if r := do(http.MethodGet, "/f/"+name, nil, ""); r.Code != http.StatusOK {
		t.Fatalf("before expiry: got %d", r.Code)
	}

	// Move the expiry into the past: the file is gone on next access.
	m := loadMeta(name)
	m.Expires = time.Now().Add(-time.Minute).Unix()
	saveMeta(name, m)
	if r := do(http.MethodGet, "/f/"+name, nil, ""); r.Code != http.StatusNotFound {
		t.Fatalf("after expiry: got %d, want 404", r.Code)
	}
	if _, err := os.Stat(storePath + name); !os.IsNotExist(err) {
		t.Fatal("expired file not removed")
	}
}

func TestPurgeHonorsExpires(t *testing.T) {
	setAuth(t, "")
	name := storedName(t, doUpload(t, upload{name: "p.txt", data: []byte("x"), fields: map[string]string{"expires": "10m"}}))
	m := loadMeta(name)
	m.Expires = time.Now().Add(-time.Second).Unix()
	saveMeta(name, m)
	purgeDecay()
	if _, err := os.Stat(storePath + name); !os.IsNotExist(err) {
		t.Fatal("purgeDecay kept a file past its uploader expiry")
	}
}

func TestBurnAfterReading(t *testing.T) {
	setAuth(t, "")
	name := storedName(t, doUpload(t, upload{name: "b.txt", data: []byte("once"), fields: map[string]string{"burn": "1"}}))

	if r := do(http.MethodHead, "/f/"+name, nil, ""); r.Code != http.StatusOK {
		t.Fatalf("HEAD: got %d", r.Code)
	}
	r := do(http.MethodGet, "/f/"+name, map[string]string{"Range": "bytes=0-0"}, "")
	if r.Code != http.StatusOK || r.Body.String() != "once" {
		t.Fatalf("first GET: got %d %q, want full body", r.Code, r.Body.String())
	}
	if r := do(http.MethodGet, "/f/"+name, nil, ""); r.Code != http.StatusNotFound {
		t.Fatalf("second GET: got %d, want 404", r.Code)
	}
	if entries, _ := os.ReadDir(burnPath); len(entries) != 0 {
		t.Fatalf("burn dir not cleaned: %v", entries)
	}
}

func TestImageChecks(t *testing.T) {
	setAuth(t, "")
	storedName(t, doUpload(t, upload{name: "ok.png", data: pngBytes(4, 4)}))

	// Sniffs as JPEG but does not decode: rejected, not stored raw.
	bad := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("not really a jpeg")...)
	if rec := doUpload(t, upload{name: "bad.jpg", data: bad}); rec.Code != http.StatusBadRequest {
		t.Fatalf("undecodable jpeg: got %d, want 400", rec.Code)
	}

	// GIF frame cap.
	old := maxGIFTotalPixels
	maxGIFTotalPixels = 2500
	t.Cleanup(func() { maxGIFTotalPixels = old })
	pal := color.Palette{color.Black, color.White}
	g := &gif.GIF{}
	for i := 0; i < 3; i++ {
		g.Image = append(g.Image, image.NewPaletted(image.Rect(0, 0, 40, 40), pal))
		g.Delay = append(g.Delay, 0)
	}
	var b bytes.Buffer
	gif.EncodeAll(&b, g)
	if n, err := gifTotalPixels(bytes.NewReader(b.Bytes())); err != nil || n < 2500 {
		t.Fatalf("gifTotalPixels = %d, %v", n, err)
	}
	if rec := doUpload(t, upload{name: "anim.gif", data: b.Bytes()}); rec.Code != http.StatusBadRequest {
		t.Fatalf("GIF over frame cap: got %d, want 400", rec.Code)
	}
	maxGIFTotalPixels = 1 << 30
	storedName(t, doUpload(t, upload{name: "anim.gif", data: b.Bytes()}))
}

func TestCreateUniqueNeverOverwrites(t *testing.T) {
	ids := []string{"same", "same", "diff"}
	old := newID
	newID = func(int) string { id := ids[0]; ids = ids[1:]; return id }
	t.Cleanup(func() { newID = old })

	f1, n1, err := createUnique(4, "txt")
	if err != nil {
		t.Fatal(err)
	}
	f1.WriteString("first")
	f1.Close()
	f2, n2, err := createUnique(4, "txt")
	if err != nil {
		t.Fatal(err)
	}
	f2.Close()
	if n1 != "same.txt" || n2 != "diff.txt" {
		t.Fatalf("got %s, %s; want same.txt, diff.txt", n1, n2)
	}
	if b, _ := os.ReadFile(storePath + n1); string(b) != "first" {
		t.Fatal("existing file was overwritten")
	}
}

func TestRandID(t *testing.T) {
	for _, n := range []int{minIDLen, 12, maxIDLen} {
		id := randID(n)
		if len(id) != n || strings.Trim(id, idAlphabet) != "" {
			t.Fatalf("randID(%d) = %q", n, id)
		}
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.7:51234"
	if got := clientIP(r); got != "192.0.2.7" {
		t.Fatalf("clientIP = %q, want port stripped", got)
	}
	r.Header.Set("X-Real-IP", "198.51.100.1")
	if got := clientIP(r); got != "198.51.100.1" {
		t.Fatalf("clientIP = %q, want X-Real-IP", got)
	}
}

func TestRateLimitAnonymousOnly(t *testing.T) {
	old := cfgUploadRate
	cfgUploadRate = 2
	t.Cleanup(func() { cfgUploadRate = old })
	ip := map[string]string{"X-Real-IP": "203.0.113.9"}

	setAuth(t, "")
	for i := 0; i < 2; i++ {
		storedName(t, doUpload(t, upload{name: "r.txt", data: []byte("x"), headers: ip}))
	}
	if rec := doUpload(t, upload{name: "r.txt", data: []byte("x"), headers: ip}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("anonymous over limit: got %d, want 429", rec.Code)
	}

	cfgUploadToken, cfgRequireAuth = "tok", true
	authed := map[string]string{"X-Real-IP": "203.0.113.9", "Authorization": "Bearer tok"}
	storedName(t, doUpload(t, upload{name: "r.txt", data: []byte("x"), headers: authed}))
}

func TestParseExpiry(t *testing.T) {
	good := map[string]time.Duration{"10m": 10 * time.Minute, "1h": time.Hour, "7d": 7 * 24 * time.Hour, "1H30M": 90 * time.Minute}
	for in, want := range good {
		if d, err := parseExpiry(in); err != nil || d != want {
			t.Errorf("parseExpiry(%q) = %v, %v; want %v", in, d, err, want)
		}
	}
	for _, in := range []string{"", "1s", "-1h", "abc", "0d", "99999d"} {
		if _, err := parseExpiry(in); err == nil {
			t.Errorf("parseExpiry(%q) succeeded, want error", in)
		}
	}
}

func TestHealthz(t *testing.T) {
	if r := do(http.MethodGet, "/healthz", nil, ""); r.Code != http.StatusOK {
		t.Fatalf("healthz: got %d", r.Code)
	}
}

func TestSaveJSONPermissions(t *testing.T) {
	p := filepath.Join(filepath.Dir(filepath.Clean(storePath)), "perm.json")
	saveJSON(p, []string{"a"})
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}
