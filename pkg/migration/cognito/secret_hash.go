package cognito

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// computeSecretHash implements Cognito's SECRET_HASH calculation:
//
//	base64(HMAC-SHA256(client_secret, username + client_id))
//
// Required when the Cognito app client has an associated client secret.
// See the AWS docs on InitiateAuth -> SECRET_HASH.
func computeSecretHash(clientID, clientSecret, username string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username))
	mac.Write([]byte(clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
