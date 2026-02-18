package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTailLog(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// Write 20 lines
	for i := 0; i < 20; i++ {
		tmpfile.WriteString(fmt.Sprintf("line %d\n", i))
	}
	tmpfile.Close()

	got := tailLogFile(tmpfile.Name(), 5)
	expected := "line 15\nline 16\nline 17\nline 18\nline 19"
	if got != expected {
		t.Errorf("Expected:\n%q\nGot:\n%q", expected, got)
	}

	// Test with fewer lines than requested
	got = tailLogFile(tmpfile.Name(), 30)
	expectedFull := make([]string, 20)
	for i := 0; i < 20; i++ {
		expectedFull[i] = fmt.Sprintf("line %d", i)
	}
	expected = strings.Join(expectedFull, "\n")
	if got != expected {
		t.Errorf("Expected full log, got:\n%q", got)
	}

	// Test with large log to verify chunk reading (ensure > 4096 bytes)
	tmpfileLarge, err := os.CreateTemp("", "log_large")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfileLarge.Name())

	for i := 0; i < 1000; i++ {
		tmpfileLarge.WriteString(fmt.Sprintf("line %04d\n", i))
	}
	tmpfileLarge.Close()

	got = tailLogFile(tmpfileLarge.Name(), 5)
	expected = "line 0995\nline 0996\nline 0997\nline 0998\nline 0999"
	if got != expected {
		t.Errorf("Large log mismatch.\nExpected:\n%q\nGot:\n%q", expected, got)
	}
}

func TestLoginRateLimitRace(t *testing.T) {
	// Clear global map
	loginFailsMu.Lock()
	for k := range loginFails {
		delete(loginFails, k)
	}
	loginFailsMu.Unlock()

	ip := "1.2.3.4"
	var passed int32
	var wg sync.WaitGroup

	// Try 50 concurrent login attempts (wrong password)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each attempt first checks if allowed
			if checkLoginRateLimit(ip) {
				// Simulate check failure (wrong password) -> record failure
				// Add sleep to widen the race window, similar to password check time
				time.Sleep(10 * time.Millisecond)
				recordLoginFail(ip)
				atomic.AddInt32(&passed, 1)
			}
		}()
	}
	wg.Wait()

	t.Logf("Passed attempts (allowed by check): %d", passed)

	loginFailsMu.Lock()
	count := loginFails[ip].count
	loginFailsMu.Unlock()
	t.Logf("Final failure count in map: %d", count)

	// With Mutex, we expect no lost updates, so count should be exactly passed.
	// (Assuming recordLoginFail is called for every passed check)
	if int32(count) != passed {
		t.Errorf("Lost updates detected! Count %d != Passed %d", count, passed)
	}

	// Note: We accept that 'passed' might be > 10 due to check-then-act race.
	// The fix ensures we count all failures so subsequent requests are blocked.
}
