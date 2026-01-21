package main

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

// WAFSignature mendefinisikan pola untuk mengenali firewall
type WAFSignature struct {
	Name    string
	Headers map[string]string // Key header dan pola regex untuk valuenya
	Body    string            // Pola regex untuk body
	Code    int               // Status code yang diharapkan (0 jika tidak spesifik)
}

// Database Signature WAF Populer & Defense Mechanisms
var wafSignatures = []WAFSignature{
	// [Tier 1] Strict Whitelisting
	{
		Name: "NAXSI (Nginx Anti XSS & SQL Injection)",
		Headers: map[string]string{
			"Server":        "(?i)naxsi",
			"X-Data-Origin": "(?i)naxsi",
		},
		Code: 403, // NAXSI biasanya memblokir dengan 403
	},
	// [Tier 2] Semantic & Behavioral Analysis
	{
		Name: "Cloudflare WAF",
		Headers: map[string]string{
			"Server": "(?i)cloudflare",
			"CF-RAY": ".*",
		},
		Body: "(?i)Attention Required!|Cloudflare",
		Code: 403,
	},
	{
		Name: "Akamai App & API Protector",
		Headers: map[string]string{
			"Server":              "(?i)AkamaiGHost",
			"X-Akamai-Request-ID": ".*",
		},
	},
	{
		Name: "F5 Advanced WAF (BIG-IP)",
		Headers: map[string]string{
			"X-Cnection": "(?i)^close$",
			"Set-Cookie": "(?i)BIGipServer",
			"Server":     "(?i)BigIP",
		},
	},
	{
		Name: "Imperva Cloud WAF (Incapsula)",
		Headers: map[string]string{
			"X-Iinfo": ".*",
			"X-CDN":   "(?i)Incapsula",
		},
	},
	// [Tier 3] Signature/Rule-Based
	{
		Name: "ModSecurity (OWASP CRS)",
		Headers: map[string]string{
			"Server": "(?i)ModSecurity",
		},
		Code: 403,
		Body: "(?i)Not Acceptable",
	},
	{
		Name: "AWS WAF / CloudFront",
		Headers: map[string]string{
			"Server":      "(?i)cloudfront",
			"Via":         "(?i)cloudfront",
			"X-Amz-Cf-Id": ".*",
		},
		Code: 403, // AWS WAF blocking signature
	},
	{
		Name: "Sucuri Website Firewall",
		Headers: map[string]string{
			"Server":      "(?i)Sucuri",
			"X-Sucuri-ID": ".*",
		},
		Body: "(?i)Access Denied - Sucuri Website Firewall",
	},
	{
		Name: "Palo Alto Next-Gen Firewall",
		Code: 403,
		Body: "(?i)Palo Alto Next Generation Security Platform",
	},
	{
		Name: "Fortinet FortiWeb",
		Headers: map[string]string{
			"Set-Cookie": "(?i)FORTIWAFSID",
			"Server":     "(?i)FortiWeb",
		},
	},
	{
		Name: "Citrix NetScaler",
		Headers: map[string]string{
			"Via":        "(?i)NS-CACHE",
			"X-Cnection": "(?i)^close$",
		},
	},
	// [Supplementary] Browser-Side Defense
	// Dideteksi jika tidak ada WAF yang memblokir (misal response 200 OK tapi ada header CSP)
	{
		Name: "Content Security Policy (CSP) Enabled",
		Headers: map[string]string{
			"Content-Security-Policy": ".*",
		},
	},
}

// DetectWAF mengirimkan request provokatif untuk memancing respons WAF
func DetectWAF(targetURL string, client *http.Client) string {
	// Buat payload "berisik" untuk memancing WAF
	separator := "?"
	if strings.Contains(targetURL, "?") {
		separator = "&"
	}
	// Payload standar script alert untuk trigger block
	provocativeURL := targetURL + separator + "gxss_waf_test=<script>alert(1)</script>"

	req, err := http.NewRequest("GET", provocativeURL, nil)
	if err != nil {
		return ""
	}
	
	// Gunakan UA dan Cookies global dari gxss.go
	req.Header.Set("User-Agent", getRandomUA())
	req.Close = true

	for _, cookie := range globalCookies {
		req.AddCookie(cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// Baca body secukupnya untuk analisis
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body := string(bodyBytes)

	// Analisis Signature
	for _, sig := range wafSignatures {
		// 1. Cek Status Code (jika didefinisikan dalam signature)
		if sig.Code != 0 && resp.StatusCode != sig.Code {
			continue
		}

		// 2. Cek Headers
		matchedHeaders := true
		if len(sig.Headers) > 0 {
			for k, v := range sig.Headers {
				headerVal := resp.Header.Get(k)
				
				// Handle case-insensitive header keys manual jika Get gagal
				if headerVal == "" {
					foundKey := false
					for hKey, hVal := range resp.Header {
						if strings.EqualFold(hKey, k) {
							headerVal = strings.Join(hVal, " ")
							foundKey = true
							break
						}
					}
					if !foundKey {
						matchedHeaders = false
						break
					}
				}

				if v != ".*" {
					matched, _ := regexp.MatchString(v, headerVal)
					if !matched {
						matchedHeaders = false
						break
					}
				}
			}
		}

		// Jika headers didefinisikan dan cocok, return nama WAF (Strong Signal)
		if len(sig.Headers) > 0 && matchedHeaders {
			return sig.Name
		}

		// 3. Cek Body (Fallback jika headers tidak spesifik)
		if sig.Body != "" {
			matched, _ := regexp.MatchString(sig.Body, body)
			if matched {
				return sig.Name
			}
		}
	}

	return ""
}
