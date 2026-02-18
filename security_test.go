package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSiteURL(t *testing.T) {
	// 1. Default case (no SITE_URL)
	os.Unsetenv("SITE_URL")
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	got := siteURL(req)
	want := "http://example.com"
	if got != want {
		t.Errorf("Default: got %q, want %q", got, want)
	}

	// 2. With SITE_URL
	os.Setenv("SITE_URL", "https://mydomain.com")
	got = siteURL(req)
	want = "https://mydomain.com"
	if got != want {
		t.Errorf("With Env: got %q, want %q", got, want)
	}

	// 3. With trailing slash
	os.Setenv("SITE_URL", "https://mydomain.com/")
	got = siteURL(req)
	want = "https://mydomain.com"
	if got != want {
		t.Errorf("Trailing slash: got %q, want %q", got, want)
	}
	os.Unsetenv("SITE_URL")
}

func TestCSRFProtection(t *testing.T) {
	// We need to test handleAdmin.
	// But handleAdmin depends on global 'sessions' and 'loginFails'.
	// We can manipulate the global 'sessions' map.

	// Setup a session
	tok := "testtoken"
	csrf := "testcsrf"
	sessions.Store(tok, sessionData{
		expiry:    time.Now().Add(time.Hour),
		csrfToken: csrf,
	})

	// Helper to make authenticated request
	makeReq := func(method, action, csrfVal string) *http.Response {
		url := "/admin"
		if action != "" {
			url += "?action=" + action
		}
		req := httptest.NewRequest(method, url, nil)
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// Create form body
			if action != "" {
				// hacky but sufficient for test since we parse form
			}
			// Re-create request with body
			body := fmt.Sprintf("action=%s&csrf_token=%s", action, csrfVal)
			req = httptest.NewRequest(method, "/admin", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		req.AddCookie(&http.Cookie{Name: "drop_session", Value: tok})
		w := httptest.NewRecorder()
		handleAdmin(w, req)
		return w.Result()
	}

	// 1. GET request should pass (renders page)
	resp := makeReq("GET", "", "")
	if resp.StatusCode != 200 {
		t.Errorf("GET /admin failed: %d", resp.StatusCode)
	}

	// 2. POST with valid CSRF
	// Use 'viewlog' action as it is safe and side-effect free (mostly)
	resp = makeReq("POST", "viewlog", csrf)
	if resp.StatusCode != 200 {
		t.Errorf("POST valid CSRF failed: %d", resp.StatusCode)
	}

	// 3. POST with invalid CSRF
	resp = makeReq("POST", "viewlog", "wrongtoken")
	if resp.StatusCode != 400 {
		t.Errorf("POST invalid CSRF: got %d, want 400", resp.StatusCode)
	}

	// 4. POST with missing CSRF
	resp = makeReq("POST", "viewlog", "")
	if resp.StatusCode != 400 {
		t.Errorf("POST missing CSRF: got %d, want 400", resp.StatusCode)
	}
}
