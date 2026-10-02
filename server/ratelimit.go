package server

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for the sign-up, password-reset and password-login abuse limits.
const (
	// codeSendPerEmail and codeSendPerIP cap verification emails (sign-up and password reset).
	codeSendPerEmail = 5
	codeSendPerIP    = 20
	codeSendWindow   = 15 * time.Minute

	// codeVerifyPerEmail and codeVerifyPerIP cap sign-up and password-reset submissions.
	codeVerifyPerEmail = 10
	codeVerifyPerIP    = 30
	codeVerifyWindow   = 15 * time.Minute

	// maxWrongCodes is how many wrong verification codes an email may enter before its code is revoked.
	maxWrongCodes = 5
	// wrongCodesTTL outlives the 5 minute code lifetime so a counter never resets mid-code.
	wrongCodesTTL = 15 * time.Minute

	// loginFailuresPerAccount consecutive failures lock the account for loginLockout.
	loginFailuresPerAccount = 10
	loginLockout            = 15 * time.Minute
	// loginFailuresPerIP counts failed password logins only, so busy shared NATs are not throttled.
	loginFailuresPerIP = 50
	loginIPWindow      = 15 * time.Minute

	// checkHandlerPerIP caps email lookups on the first sign-in step.
	checkHandlerPerIP  = 60
	checkHandlerWindow = time.Minute

	// maxTrackedKeys bounds each limiter's memory.
	maxTrackedKeys = 100_000

	rateLimitedError    = "rate_limited"
	tooManyWrongCodeMsg = "Too many incorrect codes. Request a new code."
)

// authLimits holds the in-memory abuse counters; each dex replica counts on its own, so the effective limit is per replica.
type authLimits struct {
	codeSendEmail   *rateLimiter
	codeSendIP      *rateLimiter
	codeVerifyEmail *rateLimiter
	codeVerifyIP    *rateLimiter
	wrongCodes      *failureCounter
	loginAccount    *failureCounter
	loginIP         *rateLimiter
	checkIP         *rateLimiter
}

func newAuthLimits(now func() time.Time) *authLimits {
	return &authLimits{
		codeSendEmail:   newRateLimiter(now, codeSendPerEmail, codeSendWindow),
		codeSendIP:      newRateLimiter(now, codeSendPerIP, codeSendWindow),
		codeVerifyEmail: newRateLimiter(now, codeVerifyPerEmail, codeVerifyWindow),
		codeVerifyIP:    newRateLimiter(now, codeVerifyPerIP, codeVerifyWindow),
		wrongCodes:      newFailureCounter(now, maxWrongCodes, wrongCodesTTL),
		loginAccount:    newFailureCounter(now, loginFailuresPerAccount, loginLockout),
		loginIP:         newRateLimiter(now, loginFailuresPerIP, loginIPWindow),
		checkIP:         newRateLimiter(now, checkHandlerPerIP, checkHandlerWindow),
	}
}

// allowCodeSend counts one verification email for the client and the address.
func (l *authLimits) allowCodeSend(r *http.Request, email string) (time.Duration, bool) {
	if wait, ok := l.codeSendIP.allow(clientIP(r)); !ok {
		return wait, false
	}
	return l.codeSendEmail.allow(limitKey(email))
}

// allowCodeVerify counts one sign-up or password-reset submission for the client and the address.
func (l *authLimits) allowCodeVerify(r *http.Request, email string) (time.Duration, bool) {
	if wait, ok := l.codeVerifyIP.allow(clientIP(r)); !ok {
		return wait, false
	}
	return l.codeVerifyEmail.allow(limitKey(email))
}

// loginBlocked reports whether a password login must be refused without checking the password.
func (l *authLimits) loginBlocked(r *http.Request, account string) (time.Duration, bool) {
	if wait, blocked := l.loginIP.blocked(clientIP(r)); blocked {
		return wait, true
	}
	return l.loginAccount.blocked(limitKey(account))
}

func (l *authLimits) loginFailed(r *http.Request, account string) {
	l.loginIP.hit(clientIP(r))
	l.loginAccount.fail(limitKey(account))
}

func (l *authLimits) loginSucceeded(account string) {
	l.loginAccount.reset(limitKey(account))
}

// rateLimiter is a fixed-window counter per key.
type rateLimiter struct {
	store  counterStore
	limit  int
	window time.Duration
}

func newRateLimiter(now func() time.Time, limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{store: newCounterStore(now), limit: limit, window: window}
}

// allow counts one request for key and reports how long to wait when the window is used up.
func (l *rateLimiter) allow(key string) (time.Duration, bool) {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	now := l.store.now()
	e := l.store.get(key, now)
	if e != nil && e.count >= l.limit {
		return e.expires.Sub(now), false
	}
	l.add(key, e, now)
	return 0, true
}

// blocked reports whether key has used up its window without counting a request.
func (l *rateLimiter) blocked(key string) (time.Duration, bool) {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	now := l.store.now()
	if e := l.store.get(key, now); e != nil && e.count >= l.limit {
		return e.expires.Sub(now), true
	}
	return 0, false
}

func (l *rateLimiter) hit(key string) {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	now := l.store.now()
	l.add(key, l.store.get(key, now), now)
}

func (l *rateLimiter) add(key string, e *counterEntry, now time.Time) {
	if e == nil {
		e = l.store.put(key, now.Add(l.window), now)
		if e == nil {
			return
		}
	}
	e.count++
}

// failureCounter counts consecutive failures per key; each failure extends the entry by ttl.
type failureCounter struct {
	store     counterStore
	threshold int
	ttl       time.Duration
}

func newFailureCounter(now func() time.Time, threshold int, ttl time.Duration) *failureCounter {
	return &failureCounter{store: newCounterStore(now), threshold: threshold, ttl: ttl}
}

// blocked reports whether key reached the threshold and for how much longer it stays blocked.
func (c *failureCounter) blocked(key string) (time.Duration, bool) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	now := c.store.now()
	if e := c.store.get(key, now); e != nil && e.count >= c.threshold {
		return e.expires.Sub(now), true
	}
	return 0, false
}

// fail returns the consecutive failure count including this one.
func (c *failureCounter) fail(key string) int {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	now := c.store.now()
	e := c.store.get(key, now)
	if e == nil {
		if e = c.store.put(key, now, now); e == nil {
			return 1
		}
	}
	e.count++
	e.expires = now.Add(c.ttl)
	return e.count
}

func (c *failureCounter) reset(key string) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	delete(c.store.entries, key)
}

// counterStore is a size-bounded map of counters whose entries expire lazily.
type counterStore struct {
	mu        sync.Mutex
	now       func() time.Time
	entries   map[string]*counterEntry
	lastSweep time.Time
}

type counterEntry struct {
	count   int
	expires time.Time
}

func newCounterStore(now func() time.Time) counterStore {
	return counterStore{now: now, entries: make(map[string]*counterEntry)}
}

// get returns the live entry for key, dropping it if it expired. Callers hold mu.
func (c *counterStore) get(key string, now time.Time) *counterEntry {
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !now.Before(e.expires) {
		delete(c.entries, key)
		return nil
	}
	return e
}

// put adds a zero entry for key, or returns nil when the store is full. Callers hold mu.
func (c *counterStore) put(key string, expires, now time.Time) *counterEntry {
	if len(c.entries) >= maxTrackedKeys {
		// Sweeping is O(n), so under a flood of new keys it runs at most once a minute.
		if now.Sub(c.lastSweep) < time.Minute {
			return nil
		}
		c.lastSweep = now
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxTrackedKeys {
			return nil
		}
	}
	e := &counterEntry{expires: expires}
	c.entries[key] = e
	return e
}

// clientIP is the address the request middleware trusted (see Config.RealIPHeader), else the TCP peer.
func clientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(RequestKeyRemoteIP).(string); ok && ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func limitKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func tooManyAttemptsMessage(wait time.Duration) string {
	minutes := int(math.Ceil(wait.Minutes()))
	if minutes < 1 {
		minutes = 1
	}
	unit := "minutes"
	if minutes == 1 {
		unit = "minute"
	}
	return fmt.Sprintf("Too many attempts. Try again in %d %s.", minutes, unit)
}

func setRetryAfter(w http.ResponseWriter, wait time.Duration) {
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
}
