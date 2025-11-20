package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

type BlockIP struct {
	ipv4 net.IP
	mask *net.IPNet
}

type Blacklist struct {
	ips            map[string]*BlockIP
	masks          []*BlockIP
	whitelistIps   map[string]*BlockIP
	whitelistMasks []*BlockIP
	configPath     string
	whitelistPath  string
	verbose        bool
}

func NewBlacklist(path string) (*Blacklist, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blacklist{
		ips:           make(map[string]*BlockIP),
		whitelistIps:  make(map[string]*BlockIP),
		configPath:    path,
		whitelistPath: strings.Replace(path, "blacklist.txt", "whitelist.txt", 1),
		verbose:       true,
	}

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, mask: mask})
				} else {
					log.Error("blacklist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
				} else {
					log.Error("blacklist: invalid ip address: %s", l)
				}
			}
		}
	}

	log.Info("blacklist: loaded %d ip addresses and %d ip masks", len(bl.ips), len(bl.masks))

	// Load whitelist
	bl.loadWhitelist()

	return bl, nil
}

func (bl *Blacklist) GetStats() (int, int) {
	return len(bl.ips), len(bl.masks)
}

func (bl *Blacklist) AddIP(ip string) error {
	if bl.IsBlacklisted(ip) {
		return nil
	}

	ipv4 := net.ParseIP(ip)
	if ipv4 != nil {
		bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
	} else {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	// write to file
	f, err := os.OpenFile(bl.configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ipv4.String() + "\n")
	if err != nil {
		return err
	}

	return nil
}

func (bl *Blacklist) IsBlacklisted(ip string) bool {
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}

	if _, ok := bl.ips[ip]; ok {
		return true
	}
	for _, m := range bl.masks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}
	return false
}

func (bl *Blacklist) SetVerbose(verbose bool) {
	bl.verbose = verbose
}

func (bl *Blacklist) IsVerbose() bool {
	return bl.verbose
}

func (bl *Blacklist) IsWhitelisted(ip string) bool {
	// Always whitelist localhost
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}

	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}

	// Check if IP is in whitelist
	if _, ok := bl.whitelistIps[ip]; ok {
		return true
	}

	// Check if IP matches any whitelist mask
	for _, m := range bl.whitelistMasks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}

	return false
}

// loadWhitelist loads whitelist IPs from file
func (bl *Blacklist) loadWhitelist() {
	f, err := os.OpenFile(bl.whitelistPath, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		log.Warning("whitelist: failed to open file: %v", err)
		return
	}
	defer f.Close()

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					bl.whitelistMasks = append(bl.whitelistMasks, &BlockIP{ipv4: ipv4, mask: mask})
				} else {
					log.Error("whitelist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					bl.whitelistIps[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
				} else {
					log.Error("whitelist: invalid ip address: %s", l)
				}
			}
		}
	}

	log.Info("whitelist: loaded %d ip addresses and %d ip masks", len(bl.whitelistIps), len(bl.whitelistMasks))
}

// AddWhitelistIP adds an IP address to the whitelist
func (bl *Blacklist) AddWhitelistIP(ip string) error {
	if bl.IsWhitelisted(ip) {
		return fmt.Errorf("ip address already whitelisted: %s", ip)
	}

	// Check if it's a CIDR range
	if strings.Contains(ip, "/") {
		ipv4, mask, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("invalid ip/mask address: %s", ip)
		}
		bl.whitelistMasks = append(bl.whitelistMasks, &BlockIP{ipv4: ipv4, mask: mask})

		// Write to file
		f, err := os.OpenFile(bl.whitelistPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.WriteString(ip + "\n")
		if err != nil {
			return err
		}

		log.Success("whitelist: added ip mask: %s", ip)
		return nil
	}

	// Single IP address
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	bl.whitelistIps[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}

	// Write to file
	f, err := os.OpenFile(bl.whitelistPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ipv4.String() + "\n")
	if err != nil {
		return err
	}

	log.Success("whitelist: added ip address: %s", ipv4.String())
	return nil
}

// RemoveWhitelistIP removes an IP address from the whitelist
func (bl *Blacklist) RemoveWhitelistIP(ip string) error {
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	if _, ok := bl.whitelistIps[ipv4.String()]; !ok {
		return fmt.Errorf("ip address not in whitelist: %s", ip)
	}

	delete(bl.whitelistIps, ipv4.String())

	// Rewrite whitelist file
	return bl.saveWhitelist()
}

// ClearWhitelist removes all IPs from the whitelist
func (bl *Blacklist) ClearWhitelist() error {
	bl.whitelistIps = make(map[string]*BlockIP)
	bl.whitelistMasks = []*BlockIP{}

	return bl.saveWhitelist()
}

// saveWhitelist saves the current whitelist to file
func (bl *Blacklist) saveWhitelist() error {
	f, err := os.OpenFile(bl.whitelistPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write individual IPs
	for ip := range bl.whitelistIps {
		_, err = f.WriteString(ip + "\n")
		if err != nil {
			return err
		}
	}

	// Write CIDR ranges
	for _, m := range bl.whitelistMasks {
		if m.mask != nil {
			_, err = f.WriteString(m.mask.String() + "\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// GetWhitelistStats returns the number of whitelisted IPs and masks
func (bl *Blacklist) GetWhitelistStats() (int, int) {
	return len(bl.whitelistIps), len(bl.whitelistMasks)
}

// ListWhitelist returns all whitelisted IPs and masks
func (bl *Blacklist) ListWhitelist() []string {
	var list []string

	for ip := range bl.whitelistIps {
		list = append(list, ip)
	}

	for _, m := range bl.whitelistMasks {
		if m.mask != nil {
			list = append(list, m.mask.String())
		}
	}

	return list
}
