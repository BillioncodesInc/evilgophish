package core

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type URLMapper struct {
	mappings map[string]*URLMapping
	mu       sync.RWMutex
}

type URLMapping struct {
	OriginalURL  string
	RewrittenURL string
	Timestamp    time.Time
}

func NewURLMapper() *URLMapper {
	mapper := &URLMapper{
		mappings: make(map[string]*URLMapping),
	}

	// Cleanup old mappings every 5 minutes
	go mapper.cleanupLoop()

	return mapper
}

func (um *URLMapper) generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:22]
}

func (um *URLMapper) AddMapping(originalURL string, rewrittenURL string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	um.mappings[rewrittenURL] = &URLMapping{
		OriginalURL:  originalURL,
		RewrittenURL: rewrittenURL,
		Timestamp:    time.Now(),
	}
}

func (um *URLMapper) GetOriginalURL(rewrittenURL string) (string, bool) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	mapping, exists := um.mappings[rewrittenURL]
	if !exists {
		return "", false
	}

	return mapping.OriginalURL, true
}

func (um *URLMapper) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		um.cleanup()
	}
}

func (um *URLMapper) cleanup() {
	um.mu.Lock()
	defer um.mu.Unlock()

	// Remove mappings older than 1 hour
	cutoff := time.Now().Add(-1 * time.Hour)
	for key, mapping := range um.mappings {
		if mapping.Timestamp.Before(cutoff) {
			delete(um.mappings, key)
		}
	}
}
