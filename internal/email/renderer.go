package email

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// `templates` includes `_base.html` (underscore prefix). Go's default
// //go:embed pattern excludes files whose names start with '_' or '.';
// the `all:` prefix opts every entry in — without it, the shell
// template would be missing at runtime and every render would fail
// with "_base not found in override dir nor embedded set".
//
//go:embed all:templates
var embeddedTemplates embed.FS

// Renderer turns a (template-name, data) pair into a final HTML body
// ready to ship to a provider (SMTP, SendGrid, anything that takes a
// rendered string). Single source of truth — every concrete provider
// reuses this so HTML is identical regardless of transport.
//
// Two-layer lookup:
//
//  1. Filesystem override (EMAIL_TEMPLATES_PATH). If a file with the
//     requested template name exists there, it wins. Lets operators
//     ship a custom-branded variant without rebuilding the binary.
//
//  2. Embedded defaults (internal/email/templates/, baked at compile
//     time via go:embed). The binary always ships with usable
//     templates — no operator-shipped files needed.
//
// Every per-purpose template is rendered INSIDE a `_base.html` shell
// that supplies the brand wrapper + footer. The shell receives:
//
//	{ .Subject, .BodyHTML, .BrandName, .BrandColor, .SupportEmail,
//	  .Year, .PreviewText }
//
// .BodyHTML is the pre-rendered output of the per-purpose template
// — html/template's `template.HTML` type, so the shell doesn't escape
// it.
type Renderer struct {
	brandName    string
	brandColor   string
	supportEmail string
	overrideDir  string // EMAIL_TEMPLATES_PATH; "" = embedded-only.

	// Filesystem-loaded templates take priority over embedded; we lazy-
	// compile per template the first time it's rendered so a typo'd
	// override fails at first-use rather than at boot.
	loaded map[string]*template.Template
}

// RendererConfig is the boot-time inputs the renderer needs. All
// optional; sensible defaults applied for empty fields.
type RendererConfig struct {
	BrandName    string // default "rw3iss"
	BrandColor   string // default "#5b8def"
	SupportEmail string // default "support@ryanweiss.net"
	OverrideDir  string // EMAIL_TEMPLATES_PATH; "" disables filesystem override
}

// NewRenderer wires the renderer. Cheap — defers all template parsing
// until first Render call.
func NewRenderer(cfg RendererConfig) *Renderer {
	r := &Renderer{
		brandName:    cfg.BrandName,
		brandColor:   cfg.BrandColor,
		supportEmail: cfg.SupportEmail,
		overrideDir:  cfg.OverrideDir,
		loaded:       map[string]*template.Template{},
	}
	if r.brandName == "" {
		r.brandName = "CivicGate"
	}
	if r.brandColor == "" {
		// Kept for back-compat with any operator override that still reads
		// {{.BrandColor}}; the CivicGate templates use the palette tokens
		// (ButtonBg etc.) instead. Value = CivicGate primary (dark).
		r.brandColor = "#3f7fff"
	}
	if r.supportEmail == "" {
		r.supportEmail = "support@civicgate.org"
	}
	return r
}

// RenderInput is what gets passed to every per-purpose template. The
// shell consumes BrandName / BrandColor / SupportEmail / Year /
// Subject / PreviewText; the rest is forwarded as template variables
// for the inner body.
type RenderInput struct {
	// Name of the template, without extension — e.g. "verification".
	// The file must exist as `<name>.html` either on the override
	// filesystem or in the embedded set.
	Name string

	// Email subject. Set on the result + passed to the shell.
	Subject string

	// Optional preheader text (the line previewed in inbox lists
	// before opening). Helps deliverability + glance-readability.
	PreviewText string

	// Free-form data passed to the per-purpose template. The shell
	// fields (BrandName, BrandColor, SupportEmail, Year) are injected
	// automatically — caller doesn't need to provide them.
	Data map[string]any

	// ColorMode selects the branded shell + palette variant: "dark"
	// (default) or "light". Any other/empty value resolves to dark. When
	// sending to a known user, callers pass that user's DefaultColorMode
	// (see domain.User.ColorMode); anonymous sends fall back to dark.
	ColorMode string
}

// palette holds the inline hex tokens for one color mode. Values are
// transcribed from CivicGate's DESIGN.md (email clients don't support CSS
// variables, so every color must be a literal hex). Injected into both the
// shell and the per-purpose templates so a single content template renders
// correctly in either mode. Dark is the default CivicGate look.
type palette struct {
	Bg       string // page background
	Surface  string // card surface
	Surface2 string // footer / secondary surface
	Border   string // hairline border
	Text     string // primary text
	Muted    string // secondary text
	Dim      string // tertiary text
	ButtonBg string // primary button background
	ButtonFg string // primary button text
	Link     string // link color
	Accent   string // "Gate" amber accent
}

// darkPalette / lightPalette mirror DESIGN.md's dark (default) + light
// token tables.
var (
	darkPalette = palette{
		Bg:       "#0b0e14",
		Surface:  "#13181f",
		Surface2: "#1a2130",
		Border:   "#232c3b",
		Text:     "#e8ecf2",
		Muted:    "#8896a8",
		Dim:      "#4a5568",
		ButtonBg: "#3f7fff",
		ButtonFg: "#ffffff",
		Link:     "#6f9dff",
		Accent:   "#e8b44a",
	}
	lightPalette = palette{
		Bg:       "#f7f8fa",
		Surface:  "#ffffff",
		Surface2: "#eef1f5",
		Border:   "#dfe4ea",
		Text:     "#16202e",
		Muted:    "#5a6a7d",
		Dim:      "#94a2b3",
		ButtonBg: "#2f6bff",
		ButtonFg: "#ffffff",
		Link:     "#2f6bff",
		Accent:   "#c8901f",
	}
)

// paletteFor resolves a color-mode string to its palette. Unknown/empty
// modes fall back to dark — the CivicGate default.
func paletteFor(mode string) (palette, string) {
	if mode == "light" {
		return lightPalette, "light"
	}
	return darkPalette, "dark"
}

// RenderedEmail is the result of Render — both the subject and the
// final HTML, ready to ship.
type RenderedEmail struct {
	Subject string
	HTML    string
}

// Render produces the final HTML for an email. Inner template is
// rendered first; result is set on Data.BodyHTML; shell template
// renders around it.
//
// On failure, returns (nil, err). Common failure modes:
//   - template name not found in either override dir or embedded set
//   - syntax error in an operator-supplied override (lazy-compile)
//   - data fields the template references that aren't supplied —
//     html/template renders these as empty string, no error, so this
//     is silent. Test renders before deploying a new template.
func (r *Renderer) Render(in RenderInput) (*RenderedEmail, error) {
	innerTmpl, err := r.loadTemplate(in.Name)
	if err != nil {
		return nil, err
	}

	// Resolve the color-mode variant. Dark is the default CivicGate look;
	// the dark shell lives at "_base" (kept as the canonical default so
	// existing operator overrides keep working), light at "_base_light".
	pal, mode := paletteFor(in.ColorMode)
	shellName := "_base"
	if mode == "light" {
		shellName = "_base_light"
	}
	shellTmpl, err := r.loadTemplate(shellName)
	if err != nil {
		return nil, fmt.Errorf("load base shell %q: %w", shellName, err)
	}

	// Merge shell fields + caller data; caller wins on collision so a
	// template can override defaults if it wants. Year is always set
	// fresh.
	data := map[string]any{
		"BrandName":    r.brandName,
		"BrandColor":   r.brandColor,
		"SupportEmail": r.supportEmail,
		"Year":         time.Now().Year(),
		"Subject":      in.Subject,
		"PreviewText":  in.PreviewText,
		// Palette tokens (inline hex) for the resolved color mode. Both the
		// shell and per-purpose templates read these so one content
		// template renders correctly in dark + light.
		"ColorMode":     mode,
		"BgColor":       pal.Bg,
		"SurfaceColor":  pal.Surface,
		"Surface2Color": pal.Surface2,
		"BorderColor":   pal.Border,
		"TextColor":     pal.Text,
		"MutedColor":    pal.Muted,
		"DimColor":      pal.Dim,
		"ButtonBg":      pal.ButtonBg,
		"ButtonFg":      pal.ButtonFg,
		"LinkColor":     pal.Link,
		"AccentColor":   pal.Accent,
	}
	for k, v := range in.Data {
		data[k] = v
	}

	// Render inner body.
	var innerBuf bytes.Buffer
	if err := innerTmpl.Execute(&innerBuf, data); err != nil {
		return nil, fmt.Errorf("render %q: %w", in.Name, err)
	}
	// template.HTML so the shell doesn't escape our trusted HTML.
	data["BodyHTML"] = template.HTML(innerBuf.String())

	// Render shell.
	var shellBuf bytes.Buffer
	if err := shellTmpl.Execute(&shellBuf, data); err != nil {
		return nil, fmt.Errorf("render shell: %w", err)
	}

	return &RenderedEmail{Subject: in.Subject, HTML: shellBuf.String()}, nil
}

// loadTemplate fetches a parsed template, caching after first parse.
// Override-dir files (if set) take priority over embedded.
func (r *Renderer) loadTemplate(name string) (*template.Template, error) {
	if t, ok := r.loaded[name]; ok {
		return t, nil
	}

	filename := name + ".html"

	// 1. Filesystem override.
	if r.overrideDir != "" {
		path := filepath.Join(r.overrideDir, filename)
		if _, err := os.Stat(path); err == nil {
			body, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read override %s: %w", path, err)
			}
			t, err := template.New(name).Parse(string(body))
			if err != nil {
				return nil, fmt.Errorf("parse override %s: %w", path, err)
			}
			r.loaded[name] = t
			return t, nil
		}
	}

	// 2. Embedded default.
	body, err := fs.ReadFile(embeddedTemplates, "templates/"+filename)
	if err != nil {
		return nil, fmt.Errorf("template %q not found in override dir nor embedded set: %w", name, err)
	}
	t, err := template.New(name).Parse(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse embedded %s: %w", filename, err)
	}
	r.loaded[name] = t
	return t, nil
}

// PlainTextFallback returns a minimal text/plain alternative for a
// rendered email. Some clients (and most spam filters) penalize
// HTML-only messages; we strip a tiny synthesised fallback rather
// than letting the renderer emit them itself.
//
// The result is intentionally minimal — a couple of lines, the CTA
// URL (extracted by Subject convention), and the support email.
// Producing pixel-perfect text/plain from HTML is a rabbit hole
// (the html2text problem); we don't go there.
func PlainTextFallback(brandName, subject, ctaURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", subject)
	if ctaURL != "" {
		fmt.Fprintf(&b, "Open this URL: %s\n\n", ctaURL)
	}
	fmt.Fprintf(&b, "— The %s team\n", brandName)
	return b.String()
}
