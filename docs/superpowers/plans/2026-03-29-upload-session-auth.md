# Upload Session Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-upload token field with a session-based "login" flow so browser uploads (paste, drag-drop, form) work without re-entering the token.

**Architecture:** Add a `role` field to the existing `sessionData` struct to distinguish admin vs upload sessions. Add an upload-token login handler in `handleRoot`. Modify `handleUpload` to accept upload sessions. Update the index template to show a login form instead of an inline token field.

**Tech Stack:** Go stdlib (net/http, sync, crypto), HTML/JS (inline template)

**Note:** This project has no tests. Steps skip TDD and go straight to implementation + manual verification.

---

### Task 1: Add role field to sessionData and create isUploader helper

**Files:**
- Modify: `main.go:345-348` (sessionData struct)
- Modify: `main.go:462-469` (newSession function)
- Add new function after `isAdmin`

- [ ] **Step 1: Add `role` field to `sessionData`**

Change the struct at line 345:

```go
type sessionData struct {
	expiry time.Time
	csrf   string
	role   string // "admin" or "upload"
}
```

- [ ] **Step 2: Update `newSession` to accept a role parameter**

Change `newSession` (line 462) to:

```go
func newSession(role string) string {
	tok := randHex(32)
	sessions.Store(tok, sessionData{
		expiry: time.Now().Add(sessionTTL),
		csrf:   randHex(16),
		role:   role,
	})
	return tok
}
```

- [ ] **Step 3: Update the one existing call to `newSession` in `handleAdmin`**

At line 1263, change:

```go
tok := newSession()
```

to:

```go
tok := newSession("admin")
```

- [ ] **Step 4: Add `isUploader` function after `isAdmin` (after line 486)**

```go
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
```

- [ ] **Step 5: Verify it compiles**

Run: `cd /home/alex/GitHub/drop && go build -o /dev/null .`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add main.go
git commit -m "feat: add role field to sessions and isUploader helper"
```

---

### Task 2: Add upload-token login handler in handleRoot

**Files:**
- Modify: `main.go:1723-1751` (handleRoot function)

- [ ] **Step 1: Add token login handling in `handleRoot`**

In `handleRoot`, before the existing `r.Method == http.MethodPost` check (line 1737), add a handler for `action=login` POSTs. Replace the POST block:

```go
if r.Method == http.MethodPost {
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
```

- [ ] **Step 2: Add `handleTokenLogin` function (before `handleRoot`)**

```go
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
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

Note: Uses `SameSiteLaxMode` (not Strict) so the cookie survives normal navigation back to the site. The admin panel uses Strict which is fine for its POST-only actions, but the index page needs Lax for the redirect after login to preserve the cookie.

- [ ] **Step 3: Verify it compiles**

Run: `cd /home/alex/GitHub/drop && go build -o /dev/null .`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add main.go
git commit -m "feat: add upload-token login/logout handlers"
```

---

### Task 3: Update handleUpload to accept upload sessions

**Files:**
- Modify: `main.go:653` (handleUpload auth check)

- [ ] **Step 1: Change `isAdmin(r)` to `isUploader(r)` in handleUpload**

At line 653, change:

```go
} else if cfgRequireAuth && isAdmin(r) {
	// Logged-in admin session — skip token auth entirely.
```

to:

```go
} else if cfgRequireAuth && isUploader(r) {
	// Logged-in session (admin or upload) — skip token auth.
```

Note: `isUploader` returns true for both `"admin"` and `"upload"` roles, so admin sessions still work.

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/alex/GitHub/drop && go build -o /dev/null .`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add main.go
git commit -m "feat: accept upload sessions in handleUpload auth"
```

---

### Task 4: Update index template — login form and authenticated state

**Files:**
- Modify: `main.go:1496-1509` (upload form in index template)
- Modify: `main.go:1536-1539` (JS uploadFile token handling)

- [ ] **Step 1: Replace the token input with a login/authenticated UI**

Replace the upload form section (lines 1496-1509):

```html
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
```

- [ ] **Step 2: Add `AuthErr` field to `indexData`**

In the `indexData` struct (line 1434), add:

```go
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
```

- [ ] **Step 3: Set `AuthErr` in `handleRoot` when `?err=badtoken` is present**

In `handleRoot`, update the template execution block:

```go
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
```

Note: `LoggedIn` now uses `isUploader(r)` instead of `isAdmin(r)` so upload sessions are recognized.

- [ ] **Step 4: Update JS `uploadFile` — remove token header logic**

In the `uploadFile` function, remove the token-related lines. The function should no longer look for `#tok`:

```javascript
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
```

The rest of the XHR handler (onload, onerror, send) stays the same.

- [ ] **Step 5: Verify it compiles**

Run: `cd /home/alex/GitHub/drop && go build -o /dev/null .`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add main.go
git commit -m "feat: update index page with login/logout UI for upload token"
```

---

### Task 5: Manual verification

- [ ] **Step 1: Build and run locally**

```bash
cd /home/alex/GitHub/drop && go build -o drop .
UPLOAD_TOKEN=testtoken ./drop
```

- [ ] **Step 2: Verify login flow**

1. Visit `http://localhost:8080` — should see token login form, no upload form
2. Enter wrong token, click login — should redirect back with "invalid token" message
3. Enter `testtoken`, click login — should redirect back, see "authenticated" + logout + upload form
4. Upload a file via the form — should work without entering token
5. Paste an image (ctrl-v) — should work without entering token
6. Click logout — should see the login form again

- [ ] **Step 3: Verify curl still works**

```bash
echo "test" | curl -H "Authorization: Bearer testtoken" -F "file=@-;filename=test.txt" http://localhost:8080
```

Expected: returns a URL

- [ ] **Step 4: Verify admin panel is unaffected**

Visit `http://localhost:8080/admin` — should still require admin password, not upload token
