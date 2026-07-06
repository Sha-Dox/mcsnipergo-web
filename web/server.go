package web

import (
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kqzz/MCsniperGO/claimer"
	"github.com/Kqzz/MCsniperGO/pkg/mc"
	"github.com/Kqzz/MCsniperGO/pkg/parser"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

//go:embed static
var staticFiles embed.FS

const Version = "1.1.0"

type Server struct {
	passwordHash  []byte
	sessions      map[string]time.Time
	sessMu        sync.RWMutex
	mu            sync.RWMutex
	activeClaim   *claimer.Claim
	accounts      []*mc.MCaccount
	proxies       []string
	sseClients    map[chan string]struct{}
	sseMu         sync.RWMutex
	loginAttempts map[string]loginAttempt
	loginMu       sync.Mutex
	rateLimiter   *RateLimiter
	sseConns      map[string]int
	sseConnsMu    sync.Mutex
}

type loginAttempt struct {
	count    int
	lastFail time.Time
}

type RateLimiter struct {
	mu       sync.Mutex
	requests map[string]*tokenBucket
}

type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

const (
	maxLoginAttempts = 5
	lockoutDuration  = 5 * time.Minute
	maxRequestSize   = 1 << 20
	maxSSEConnsPerIP = 3
	apiRateLimit     = 100
	apiRateRefill    = 10
	maxConcurrent    = 50
)

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		requests: make(map[string]*tokenBucket),
	}
}

func (rl *RateLimiter) Allow(key string, maxTokens, refillRate float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.requests[key]
	if !exists {
		bucket = &tokenBucket{
			tokens:     maxTokens,
			maxTokens:  maxTokens,
			refillRate: refillRate,
			lastRefill: time.Now(),
		}
		rl.requests[key] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens += elapsed * bucket.refillRate
	if bucket.tokens > bucket.maxTokens {
		bucket.tokens = bucket.maxTokens
	}
	bucket.lastRefill = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}

func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

func NewServer(password string) (*Server, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	s := &Server{
		passwordHash:  hash,
		sessions:      make(map[string]time.Time),
		sseClients:    make(map[chan string]struct{}),
		loginAttempts: make(map[string]loginAttempt),
		rateLimiter:   NewRateLimiter(),
		sseConns:      make(map[string]int),
	}
	claimer.OnEvent(func(ev claimer.Event) {
		s.Broadcast(fmt.Sprintf(`{"level":%q,"message":%q,"time":%q}`, ev.Level, ev.Message, ev.Time.Format(time.RFC3339Nano)))
	})
	return s, nil
}

func (s *Server) Broadcast(msg string) {
	s.sseMu.RLock()
	defer s.sseMu.RUnlock()
	for ch := range s.sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (s *Server) createSession() string {
	token := GenerateToken()
	s.sessMu.Lock()
	s.sessions[token] = time.Time{}
	s.sessMu.Unlock()
	return token
}

func (s *Server) validSession(token string) bool {
	s.sessMu.RLock()
	_, ok := s.sessions[token]
	s.sessMu.RUnlock()
	return ok
}

func (s *Server) checkRateLimit(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	
	attempt, exists := s.loginAttempts[ip]
	if !exists {
		s.loginAttempts[ip] = loginAttempt{count: 1, lastFail: time.Now()}
		return true
	}
	
	if time.Since(attempt.lastFail) > lockoutDuration {
		s.loginAttempts[ip] = loginAttempt{count: 1, lastFail: time.Now()}
		return true
	}
	
	if attempt.count >= maxLoginAttempts {
		return false
	}
	
	attempt.count++
	attempt.lastFail = time.Now()
	s.loginAttempts[ip] = attempt
	return true
}

func (s *Server) resetRateLimit(ip string) {
	s.loginMu.Lock()
	delete(s.loginAttempts, ip)
	s.loginMu.Unlock()
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			if cookie, err := r.Cookie("session"); err == nil {
				token = cookie.Value
			}
		}
		if !s.validSession(token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := strings.Split(r.RemoteAddr, ":")[0]
	
	if !s.rateLimiter.Allow("login:"+ip, 10, 1) {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}

	if !s.checkRateLimit(ip) {
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := bcrypt.CompareHashAndPassword(s.passwordHash, []byte(body.Password)); err != nil {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	s.resetRateLimit(ip)
	token := s.createSession()
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func parseNameMCInput(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if !strings.Contains(input, "/") && !strings.Contains(input, "?") {
		return input
	}
	u, err := url.Parse(input)
	if err != nil {
		return input
	}
	host := strings.ToLower(u.Hostname())
	if !strings.Contains(host, "namemc.com") && !strings.Contains(host, "3name.xyz") {
		return input
	}
	if q := u.Query().Get("q"); q != "" {
		return q
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) >= 2 && (parts[0] == "name" || parts[0] == "search") {
		return parts[1]
	}
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return input
}

func (s *Server) handleParseURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	username := parseNameMCInput(body.Input)
	
	var droptime *DropTimeResult
	if strings.Contains(body.Input, "namemc.com") || strings.Contains(body.Input, "3name.xyz") {
		droptime = fetchDropTime(body.Input)
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": username,
		"droptime": droptime,
	})
}

type DropTimeResult struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

func fetchDropTime(url string) *DropTimeResult {
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	
	bodyStr := string(body)
	
	if strings.Contains(url, "namemc.com") {
		start := extractAttr(bodyStr, `id="availability-time"`, `datetime="`)
		end := extractAttr(bodyStr, `id="availability-time2"`, `datetime="`)
		if start != "" && end != "" {
			t1, err1 := time.Parse(time.RFC3339, start)
			t2, err2 := time.Parse(time.RFC3339, end)
			if err1 == nil && err2 == nil {
				return &DropTimeResult{Start: t1.Unix(), End: t2.Unix()}
			}
		}
	}
	
	if strings.Contains(url, "3name.xyz") {
		start := extractAttr(bodyStr, `id="lower-bound-update"`, `data-lower-bound="`)
		end := extractAttr(bodyStr, `id="upper-bound-update"`, `data-upper-bound="`)
		if start != "" && end != "" {
			s, _ := strconv.ParseInt(start, 10, 64)
			e, _ := strconv.ParseInt(end, 10, 64)
			if s > 0 && e > 0 {
				return &DropTimeResult{Start: s / 1000, End: e / 1000}
			}
		}
	}
	
	return nil
}

func extractAttr(html, idAttr, dataAttr string) string {
	idx := strings.Index(html, idAttr)
	if idx == -1 {
		return ""
	}
	idx = strings.Index(html[idx:], dataAttr)
	if idx == -1 {
		return ""
	}
	start := idx + len(dataAttr)
	end := strings.Index(html[start:], `"`)
	if end == -1 {
		return ""
	}
	return html[start : start+end]
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	elapsed := time.Since(claimer.Stats.StartTime).Seconds()
	rps := float64(claimer.Stats.Total) / elapsed
	if elapsed == 0 {
		rps = 0
	}

	resp := map[string]interface{}{
		"running":           s.activeClaim != nil && s.activeClaim.Running,
		"username":          "",
		"total_requests":    claimer.Stats.Total,
		"success":           claimer.Stats.Success,
		"duplicate":         claimer.Stats.Duplicate,
		"not_allowed":       claimer.Stats.NotAllowed,
		"too_many_requests": claimer.Stats.TooManyRequests,
		"rps":               rps,
		"accounts_loaded":   len(s.accounts),
		"proxies_loaded":    len(s.proxies),
		"worker_count":      claimer.GetWorkerCount(),
	}
	if s.activeClaim != nil {
		resp["username"] = s.activeClaim.Username
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeClaim != nil && s.activeClaim.Running {
		http.Error(w, "snipe already running", http.StatusConflict)
		return
	}

	var body struct {
		Username    string `json:"username"`
		StartUnix   int64  `json:"start_unix"`
		EndUnix     int64  `json:"end_unix"`
		WorkerCount int    `json:"worker_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	if body.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	if body.WorkerCount > 0 {
		claimer.SetWorkerCount(body.WorkerCount)
	}

	accounts, err := loadAccounts()
	if err != nil {
		http.Error(w, fmt.Sprintf("account load error: %v", err), http.StatusBadRequest)
		return
	}
	s.accounts = accounts

	proxies, _ := parser.ReadLines("proxies.txt")
	s.proxies = proxies

	var start, end time.Time
	if body.StartUnix > 0 {
		start = time.Unix(body.StartUnix, 0)
	}
	if body.EndUnix > 0 {
		end = time.Unix(body.EndUnix, 0)
	}

	dropRange := mc.DropRange{Start: start, End: end}

	claimer.ResetStats()
	claimer.Stats.StartTime = time.Now()

	claim := &claimer.Claim{
		Username:  body.Username,
		Accounts:  accounts,
		DropRange: dropRange,
		Proxies:   proxies,
	}
	s.activeClaim = claim

	go func() {
		err := claimer.ClaimWithinRange(body.Username, dropRange, accounts, proxies)
		if err != nil {
			s.Broadcast(fmt.Sprintf(`{"level":"err","message":%q,"time":%q}`, err.Error(), time.Now().Format(time.RFC3339Nano)))
		}
	}()

	json.NewEncoder(w).Encode(map[string]string{"status": "started", "username": body.Username})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeClaim == nil || !s.activeClaim.Running {
		http.Error(w, "no active snipe", http.StatusBadRequest)
		return
	}

	s.activeClaim.Stop()
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	accounts, err := loadAccounts()
	if err != nil {
		http.Error(w, fmt.Sprintf("error: %v", err), http.StatusBadRequest)
		return
	}

	proxies, _ := parser.ReadLines("proxies.txt")

	s.mu.Lock()
	s.accounts = accounts
	s.proxies = proxies
	s.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"accounts": len(accounts),
		"proxies":  len(proxies),
	})
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	allowed := map[string]bool{"gc.txt": true, "ms.txt": true, "gp.txt": true, "proxies.txt": true}
	if !allowed[filename] {
		http.Error(w, "invalid file, allowed: gc.txt, ms.txt, gp.txt, proxies.txt", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(filename)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"content": ""})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"content": string(data)})

	case http.MethodPost:
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(filename, []byte(body.Content), 0600); err != nil {
			http.Error(w, fmt.Sprintf("write error: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"worker_count": claimer.GetWorkerCount(),
		})
	case http.MethodPost:
		var body struct {
			WorkerCount int `json:"worker_count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if body.WorkerCount > 0 {
			claimer.SetWorkerCount(body.WorkerCount)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"worker_count": claimer.GetWorkerCount(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	if event != "push" {
		w.WriteHeader(http.StatusOK)
		return
	}

	go func() {
		time.Sleep(10 * time.Second)
		cmd := exec.Command("bash", "-c", "cd ~/mcsnipergo-web && git pull && go build -o mcsnipergo-web ./cmd/web/ && sudo systemctl restart mcsnipergo")
		cmd.Run()
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("update triggered"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"version": Version})
}

func (s *Server) handleFreeProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	
	sources := []string{
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
	}

	var newProxies []string
	for _, src := range sources {
		resp, err := client.Get(src)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, ":") {
				newProxies = append(newProxies, line)
			}
		}
	}

	if len(newProxies) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"added": 0,
			"error": "no proxies found",
		})
		return
	}

	existing, _ := parser.ReadLines("proxies.txt")
	existingSet := make(map[string]bool)
	for _, p := range existing {
		existingSet[strings.TrimSpace(p)] = true
	}

	f, err := os.OpenFile("proxies.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		http.Error(w, fmt.Sprintf("error: %v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	added := 0
	for _, p := range newProxies {
		if !existingSet[p] {
			fmt.Fprintln(f, p)
			existingSet[p] = true
			added++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"added": added,
		"total": len(existingSet),
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	
	s.sseConnsMu.Lock()
	if s.sseConns[ip] >= maxSSEConnsPerIP {
		s.sseConnsMu.Unlock()
		http.Error(w, "too many SSE connections from this IP", http.StatusTooManyRequests)
		return
	}
	s.sseConns[ip]++
	s.sseConnsMu.Unlock()
	
	defer func() {
		s.sseConnsMu.Lock()
		s.sseConns[ip]--
		if s.sseConns[ip] <= 0 {
			delete(s.sseConns, ip)
		}
		s.sseConnsMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan string, 256)
	s.sseMu.Lock()
	s.sseClients[ch] = struct{}{}
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, ch)
		s.sseMu.Unlock()
		close(ch)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "data: {\"level\":\"info\",\"message\":\"connected to log stream\",\"time\":%q}\n\n", time.Now().Format(time.RFC3339Nano))
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type accInfo struct {
		Email string `json:"email"`
		Type  string `json:"type"`
	}
	var accs []accInfo
	for _, a := range s.accounts {
		email := a.Email
		if email == "" && len(a.Bearer) > 50 {
			email = a.Bearer[40:50] + "..."
		}
		accs = append(accs, accInfo{Email: email, Type: string(a.Type)})
	}
	json.NewEncoder(w).Encode(accs)
}

func loadAccounts() ([]*mc.MCaccount, error) {
	giftCodeLines, _ := parser.ReadLines("gc.txt")
	gamepassLines, _ := parser.ReadLines("gp.txt")
	microsoftLines, _ := parser.ReadLines("ms.txt")

	gcs, _ := parser.ParseAccounts(giftCodeLines, mc.MsPr)
	microsofts, _ := parser.ParseAccounts(microsoftLines, mc.Ms)
	gamepasses, _ := parser.ParseAccounts(gamepassLines, mc.MsGp)

	accounts := append(gcs, microsofts...)
	accounts = append(accounts, gamepasses...)

	if len(accounts) == 0 {
		return nil, fmt.Errorf("no accounts found in: gc.txt, ms.txt, gp.txt")
	}
	return accounts, nil
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		
		if !s.rateLimiter.Allow(ip, apiRateLimit, apiRateRefill) {
			http.Error(w, "rate limit exceeded, try again later", http.StatusTooManyRequests)
			return
		}
		
		next(w, r)
	}
}

func (s *Server) ListenAndServe(addr string) error {
	return s.ListenAndServeTLS(addr, "", "")
}

func (s *Server) ListenAndServeTLS(addr, domain, certDir string) error {
	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		if !s.rateLimiter.Allow("static:"+ip, 50, 20) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			fileServer.ServeHTTP(w, r)
			return
		}
		token := r.URL.Query().Get("token")
		cookie, _ := r.Cookie("session")
		if cookie != nil {
			token = cookie.Value
		}
		if token == "" {
			http.ServeFileFS(w, r, staticFS, "login.html")
			return
		}
		if !s.validSession(token) {
			http.ServeFileFS(w, r, staticFS, "login.html")
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/webhook", s.handleWebhook)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/free-proxies", s.rateLimitMiddleware(s.authMiddleware(s.handleFreeProxies)))
	mux.HandleFunc("/api/login", s.rateLimitMiddleware(s.corsMiddleware(s.handleLogin)))
	mux.HandleFunc("/api/status", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleStatus))))
	mux.HandleFunc("/api/start", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleStart))))
	mux.HandleFunc("/api/stop", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleStop))))
	mux.HandleFunc("/api/reload", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleReload))))
	mux.HandleFunc("/api/accounts", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleAccounts))))
	mux.HandleFunc("/api/stream", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleSSE))))
	mux.HandleFunc("/api/files", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleFiles))))
	mux.HandleFunc("/api/config", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleConfig))))
	mux.HandleFunc("/api/parse-url", s.rateLimitMiddleware(s.corsMiddleware(s.authMiddleware(s.handleParseURL))))

	handler := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		mux.ServeHTTP(w, r)
	}))

	semaphore := make(chan struct{}, maxConcurrent)
	limitedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
			handler.ServeHTTP(w, r)
		default:
			http.Error(w, "server busy, try again later", http.StatusServiceUnavailable)
		}
	})

	if domain != "" {
		if certDir == "" {
			certDir = "./certs"
		}
		os.MkdirAll(certDir, 0700)
		
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(certDir),
			HostPolicy: autocert.HostWhitelist(domain),
		}

		server := &http.Server{
			Addr:         addr,
			Handler:      limitedHandler,
			TLSConfig:    &tls.Config{
				GetCertificate: certManager.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			},
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		fmt.Printf("[*] web server listening on %s with HTTPS (Let's Encrypt)\n", addr)
		fmt.Printf("[*] domain: %s\n", domain)
		fmt.Printf("[*] certificates stored in: %s\n", certDir)
		return server.ListenAndServeTLS("", "")
	}

	fmt.Printf("[*] web server listening on %s (HTTP - NOT SECURE)\n", addr)
	fmt.Printf("[*] WARNING: use --domain for HTTPS in production\n")
	
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      limitedHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return httpServer.ListenAndServe()
}

func ParsePort(s string) string {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return "8080"
	}
	return s
}
