// Package cognito provides a LegacyAuthProvider implementation that
// authenticates against an AWS Cognito user pool.
//
// This package is a drop-in: the auth-server core has no dependency on
// it. main.go instantiates a CognitoAdapter only when COGNITO_AUTO_MIGRATE_ENABLED
// is true and the pool config is present. Deployments that don't need
// legacy-Cognito migration get a binary with no AWS SDK reachable code
// at runtime (the import is still there but execution never enters it).
//
// Architecture (SOLID):
//
//   - Adapter implements migration.LegacyAuthProvider — the only contract
//     the auth-server knows about.
//   - The AWS SDK dependency is contained to this file. Swap providers
//     by writing pkg/migration/auth0/, pkg/migration/okta/, etc.
//   - Configuration is passed in via Config struct; no env reads inside
//     the package. main.go owns the env mapping.
package cognito

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/ven/auth/pkg/migration"
)

// Config holds Cognito pool connection details. All required; the
// constructor returns an error rather than silently misconfigure.
type Config struct {
	Region     string
	UserPoolID string
	ClientID   string
	// ClientSecret is optional. Required if the Cognito app client has a
	// secret configured; for app clients with no secret, leave empty.
	ClientSecret string
}

// Adapter is the Cognito-backed LegacyAuthProvider.
type Adapter struct {
	cfg    Config
	client *cip.Client
}

// New constructs an Adapter. Uses the default AWS credential chain (env
// vars, instance profile, etc.) — operators don't pass credentials
// explicitly into auth-server, they configure them at the deployment level.
func New(ctx context.Context, cfg Config) (*Adapter, error) {
	if cfg.Region == "" || cfg.UserPoolID == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("cognito: region, user_pool_id, and client_id are required")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("cognito: load aws config: %w", err)
	}
	return &Adapter{
		cfg:    cfg,
		client: cip.NewFromConfig(awsCfg),
	}, nil
}

// Name implements migration.LegacyAuthProvider.
func (a *Adapter) Name() string { return "cognito" }

// TryLogin authenticates the user against Cognito using the USER_PASSWORD_AUTH
// flow. On success it fetches the user's profile (AdminGetUser) so the
// caller can seed the migrated internal user row with name/email/phone/etc.
//
// Error mapping:
//   - User not found in Cognito → migration.ErrLegacyUserNotFound
//     (only reachable when the app client has PreventUserExistenceErrors
//     disabled; with the default Enabled setting Cognito collapses
//     not-found into NotAuthorizedException to prevent enumeration —
//     see TestCognitoAdapter_UnknownEmail for details.)
//   - Wrong password / disabled / unconfirmed / user-not-found-when-hidden
//     → migration.ErrLegacyLoginFailed
//   - Anything else (network, IAM, throttle) → wrapped Cognito error
//
// The caller (AuthService.Login) treats anything other than
// ErrLegacyUserNotFound as a "transient or auth-failed" outcome and
// returns InvalidCredentials so the response shape never reveals which
// branch failed.
func (a *Adapter) TryLogin(ctx context.Context, email, password string) (*migration.LegacyUser, error) {
	authParams := map[string]string{
		"USERNAME": email,
		"PASSWORD": password,
	}
	if a.cfg.ClientSecret != "" {
		// Cognito requires SECRET_HASH when the app client has a secret.
		authParams["SECRET_HASH"] = secretHash(a.cfg.ClientID, a.cfg.ClientSecret, email)
	}

	_, err := a.client.InitiateAuth(ctx, &cip.InitiateAuthInput{
		AuthFlow:       ciptypes.AuthFlowTypeUserPasswordAuth,
		ClientId:       aws.String(a.cfg.ClientID),
		AuthParameters: authParams,
	})
	if err != nil {
		// Map well-known error shapes. The Cognito SDK returns typed
		// errors we can switch on.
		var userNotFound *ciptypes.UserNotFoundException
		var notAuthorized *ciptypes.NotAuthorizedException
		var userNotConfirmed *ciptypes.UserNotConfirmedException
		switch {
		case errors.As(err, &userNotFound):
			return nil, migration.ErrLegacyUserNotFound
		case errors.As(err, &notAuthorized):
			// Wrong password OR user disabled — Cognito doesn't
			// distinguish from the auth API. Treat as login-failed.
			return nil, migration.ErrLegacyLoginFailed
		case errors.As(err, &userNotConfirmed):
			// User exists but never verified their email. Treat as
			// login-failed so the response shape stays uniform.
			return nil, migration.ErrLegacyLoginFailed
		}
		return nil, fmt.Errorf("cognito initiate auth: %w", err)
	}

	// Login succeeded — fetch the user profile so we can mirror it into
	// the internal store.
	profile, err := a.client.AdminGetUser(ctx, &cip.AdminGetUserInput{
		UserPoolId: aws.String(a.cfg.UserPoolID),
		Username:   aws.String(email),
	})
	if err != nil {
		return nil, fmt.Errorf("cognito admin get user: %w", err)
	}

	groups, err := a.client.AdminListGroupsForUser(ctx, &cip.AdminListGroupsForUserInput{
		UserPoolId: aws.String(a.cfg.UserPoolID),
		Username:   aws.String(email),
	})
	if err != nil {
		// Non-fatal: a user with no groups still migrates. Log via
		// caller's audit channel when we wire that in.
		groups = &cip.AdminListGroupsForUserOutput{}
	}

	user := &migration.LegacyUser{
		Email:      strings.ToLower(strings.TrimSpace(email)),
		Attributes: map[string]string{},
	}
	for _, attr := range profile.UserAttributes {
		key := strings.ToLower(aws.ToString(attr.Name))
		val := aws.ToString(attr.Value)
		switch key {
		case "email_verified":
			user.EmailVerified = strings.EqualFold(val, "true")
		case "given_name":
			user.FirstName = val
		case "family_name":
			user.LastName = val
		case "phone_number":
			user.Phone = val
		default:
			user.Attributes[key] = val
		}
	}
	for _, g := range groups.Groups {
		if g.GroupName != nil {
			user.Roles = append(user.Roles, *g.GroupName)
		}
	}
	return user, nil
}

// secretHash computes the SECRET_HASH that Cognito requires when the app
// client has a client secret. HMAC-SHA256 of (username + client_id) using
// the client secret as key, base64-encoded. Public Cognito contract.
func secretHash(clientID, clientSecret, username string) string {
	return computeSecretHash(clientID, clientSecret, username)
}
