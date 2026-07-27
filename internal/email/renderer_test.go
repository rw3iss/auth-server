package email

import (
	"strings"
	"testing"
)

// newTestRenderer builds a renderer against the embedded CivicGate
// templates (no filesystem override).
func newTestRenderer() *Renderer {
	return NewRenderer(RendererConfig{
		BrandName:    "CivicGate",
		SupportEmail: "support@civicgate.org",
	})
}

// TestRenderVerificationBothVariants asserts that the verification email
// renders in BOTH the dark and light shells, and that each rendering
// carries the CivicGate wordmark, the verify button, and the raw
// fallback link. It also checks that each variant pulls its mode-specific
// background hex so we know shell selection actually happened.
func TestRenderVerificationBothVariants(t *testing.T) {
	r := newTestRenderer()

	cases := []struct {
		mode      string
		wantBg    string // body background hex unique to the shell variant
		wantOther string // a hex that must NOT appear (the other shell's bg)
	}{
		{mode: "dark", wantBg: "#0b0e14", wantOther: "#f7f8fa"},
		{mode: "light", wantBg: "#f7f8fa", wantOther: "#0b0e14"},
	}

	const verifyURL = "https://app.civicgate.org/auth/verify-email?token=abc123"

	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			out, err := r.Render(RenderInput{
				Name:        "verification",
				Subject:     "Verify your email address",
				PreviewText: "Confirm your email",
				ColorMode:   tc.mode,
				Data: map[string]any{
					"FirstName":       "Ada",
					"VerificationURL": verifyURL,
					"ExpiryHours":     24,
				},
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			html := out.HTML

			// Wordmark: "Civic" + amber "Gate".
			if !strings.Contains(html, ">Civic<") || !strings.Contains(html, ">Gate<") {
				t.Errorf("%s: CivicGate wordmark missing", tc.mode)
			}
			// The verify button label.
			if !strings.Contains(html, "Verify your email") {
				t.Errorf("%s: verify button label missing", tc.mode)
			}
			// The raw fallback link (href) must be present.
			if !strings.Contains(html, verifyURL) {
				t.Errorf("%s: verification URL missing", tc.mode)
			}
			// Greeting personalization.
			if !strings.Contains(html, "Ada") {
				t.Errorf("%s: first name missing", tc.mode)
			}
			// Footer posture line.
			if !strings.Contains(html, "Neutral civic intelligence") {
				t.Errorf("%s: footer posture line missing", tc.mode)
			}
			// Shell variant actually selected: correct bg present, other absent.
			if !strings.Contains(html, tc.wantBg) {
				t.Errorf("%s: expected shell bg %s not found", tc.mode, tc.wantBg)
			}
			if strings.Contains(html, tc.wantOther) {
				t.Errorf("%s: unexpected other-variant bg %s found", tc.mode, tc.wantOther)
			}
		})
	}
}

// TestRenderDefaultsToDark asserts an empty/unknown color mode falls back
// to the dark shell (the CivicGate default).
func TestRenderDefaultsToDark(t *testing.T) {
	r := newTestRenderer()
	for _, mode := range []string{"", "nonsense"} {
		out, err := r.Render(RenderInput{
			Name:      "verification",
			Subject:   "Verify your email address",
			ColorMode: mode,
			Data: map[string]any{
				"VerificationURL": "https://x/verify?token=t",
				"ExpiryHours":     24,
			},
		})
		if err != nil {
			t.Fatalf("render(%q): %v", mode, err)
		}
		if !strings.Contains(out.HTML, "#0b0e14") {
			t.Errorf("mode %q: expected dark shell fallback", mode)
		}
	}
}

// TestRenderPasswordReset covers the second restyled email.
func TestRenderPasswordReset(t *testing.T) {
	r := newTestRenderer()
	const resetURL = "https://app.civicgate.org/auth/reset?token=xyz"
	out, err := r.Render(RenderInput{
		Name:      "password_reset",
		Subject:   "Reset your password",
		ColorMode: "light",
		Data: map[string]any{
			"FirstName":     "Grace",
			"ResetURL":      resetURL,
			"ExpiryMinutes": 60,
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{">Civic<", ">Gate<", "Reset password", resetURL, "Grace"} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("password_reset (light): missing %q", want)
		}
	}
}
