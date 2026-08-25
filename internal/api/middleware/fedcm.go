package middleware

import (
	"net/http"

	"github.com/rw3iss/auth/pkg/shared/errors"
)

// FedCM (Federated Credential Management) middleware primitives.
//
// FedCM moves federated sign-in from "the RP page opens a popup at the IdP" to
// "the browser itself talks to the IdP and mediates the account chooser". That
// inversion is what makes the two helpers here load-bearing rather than cosmetic:
// the requests arrive with no Authorization header (the browser makes them, not
// our JS) and from an origin that is not ours.

// WebIdentityDest is the value the browser sets on Sec-Fetch-Dest for every
// request it makes on FedCM's behalf.
const WebIdentityDest = "webidentity"

// SetLoginHeader is the FedCM Login Status API response header.
const SetLoginHeader = "Set-Login"

// RequireWebIdentity rejects any request that does not carry
// `Sec-Fetch-Dest: webidentity`.
//
// THIS IS THE WHOLE ACCESS CONTROL for the FedCM endpoints, and it works because
// Sec-Fetch-* is a FORBIDDEN header name: page script cannot set it, and fetch()
// silently drops an attempt. So its presence is the browser asserting "I made
// this request as part of a FedCM flow", which is exactly the claim we need.
//
// Without the check, `GET /fedcm/accounts` is an endpoint that returns a signed-in
// person's name and email to any cross-site page that can get the cookie
// attached — a credentialed <img>-shaped read of someone's identity. Every FedCM
// endpoint must be behind this, including the ones that look harmless.
func RequireWebIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Dest") != WebIdentityDest {
			writeError(w, errors.Forbidden("This endpoint is callable only by the browser's FedCM implementation"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IsFirstPartyRequest reports whether a request came from our own site rather
// than from some other page in the user's browser.
//
// WHY THIS EXISTS — login CSRF, which `SameSite=None` makes exploitable.
// `POST /auth/login` is unauthenticated by nature and has no CSRF token, and a
// cross-site `fetch` with a CORS-safelisted content type triggers no preflight. So
// an attacker page can POST **its own** credentials with `cookie_mode: true` and
// `credentials: "include"`. It cannot READ the response — CORS stops that — but it
// does not need to: the `Set-Cookie` lands regardless, and the victim's browser now
// holds a live session for the ATTACKER's account. The next FedCM sign-in anywhere
// then offers, or silently re-authenticates, the wrong person's identity.
//
// With SameSite=Lax the browser refused that cookie by itself. Turning it to None
// removes that brake, so the check has to be made explicitly.
//
// `Sec-Fetch-Site` is the right primitive: it is a forbidden header name, so page
// script cannot set it, and the legitimate case is distinguishable — CivicGate's own
// login at www.civicgate.org calling auth.civicgate.org is `same-site`, while any
// attacker page is `cross-site`.
//
// When the header is absent (an older browser, or a non-browser client) it falls
// back to an exact `Origin` match against the configured allow-list. A request with
// NO Origin at all is a non-browser caller — curl, a server — which carries no
// ambient cookies to fixate, so it is allowed. A literal "*" in the allow-list is
// deliberately NOT honoured: it would turn the fallback into no check at all.
func IsFirstPartyRequest(r *http.Request, allowedOrigins []string) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
		return true
	case "cross-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, o := range allowedOrigins {
		if o != "*" && o == origin {
			return true
		}
	}
	return false
}

// SetLoginStatus writes the FedCM Login Status API header.
//
// The browser keeps a per-IdP-origin bit: "does this user have a session here?"
// It starts UNKNOWN, and while it is `logged-out` the browser will not even call
// the accounts endpoint — it fails the FedCM request immediately. So an IdP that
// never reports its status looks permanently signed-out to FedCM no matter how
// valid the session cookie is, with nothing in any log to say why.
//
// CAVEAT worth knowing before debugging this: the header is honoured on top-level
// navigations and SAME-ORIGIN subresource requests to the IdP. A login POST issued
// from a different origin (www → auth) is cross-origin, so the header may be
// ignored there; the reliable path is `navigator.login.setStatus()` executed on a
// page of the IdP origin, which is what the FedCM login_url page is for.
func SetLoginStatus(w http.ResponseWriter, loggedIn bool) {
	if loggedIn {
		w.Header().Set(SetLoginHeader, "logged-in")
		return
	}
	w.Header().Set(SetLoginHeader, "logged-out")
}
