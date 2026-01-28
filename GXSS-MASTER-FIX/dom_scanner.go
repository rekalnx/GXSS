package main // <--- WAJIB MAIN

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// TaintResult menyimpan hasil analisis DOM
type TaintResult struct {
	IsVulnerable bool
	Sink         string // Fungsi JS yang tereksekusi
	Payload      string
	StackTrace   string
}

// JS_TAINT_HOOK: Script mata-mata yang akan ditanam di browser target
const JS_TAINT_HOOK = `
(function() {
    window.__gxss_findings = [];
    
    function logFinding(sink, payload) {
        window.__gxss_findings.push({
            sink: sink,
            payload: payload,
            stack: new Error().stack
        });
    }

    const sinks = [
        { obj: window, func: 'eval' },
        { obj: window, func: 'setTimeout' },
        { obj: window, func: 'setInterval' },
        { obj: document, func: 'write' },
        { obj: document, func: 'writeln' }
    ];

    sinks.forEach(s => {
        try {
            const original = s.obj[s.func];
            s.obj[s.func] = function() {
                if (arguments[0] && typeof arguments[0] === 'string' && arguments[0].includes('GXSS_CANARY')) {
                    logFinding(s.func, arguments[0]);
                }
                return original.apply(this, arguments);
            };
        } catch(e) {}
    });

    try {
        const originalInnerHtmlDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (value && typeof value === 'string' && value.includes('GXSS_CANARY')) {
                    logFinding('innerHTML', value);
                }
                return originalInnerHtmlDescriptor.set.call(this, value);
            }
        });
    } catch(e) {}
})();
`

// AnalyzeDOM: Fungsi utama untuk melakukan scanning dinamis
func AnalyzeDOM(parentCtx context.Context, targetURL string) (*TaintResult, error) {
	ctx, cancel := chromedp.NewContext(parentCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var findings []map[string]string

	tasks := chromedp.Tasks{
		runtime.Enable(),
		chromedp.ActionFunc(func(c context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(JS_TAINT_HOOK).Do(c)
			return err
		}),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2 * time.Second),
		chromedp.Evaluate(`window.__gxss_findings`, &findings),
	}

	err := chromedp.Run(ctx, tasks)
	if err != nil {
		return nil, err
	}

	if len(findings) > 0 {
		first := findings[0]
		return &TaintResult{
			IsVulnerable: true,
			Sink:         first["sink"],
			Payload:      first["payload"],
			StackTrace:   first["stack"],
		}, nil
	}

	return &TaintResult{IsVulnerable: false}, nil
}
