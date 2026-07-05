// Package main provides a database seed script to create a system admin user
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

const (
	adminEmail     = "admin@ryanweiss.net"
	adminFirstName = "Super"
	adminLastName  = "Admin"
	passwordLength = 24
)

func main() {
	// Load config (reuses the same env vars as the auth server)
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := sqlx.Connect("postgres", cfg.Database.DSN())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Delete existing admin user if present (allows re-running)
	res, err := db.ExecContext(ctx, "DELETE FROM users WHERE email = $1", adminEmail)
	if err != nil {
		log.Fatalf("Failed to check/remove existing user: %v", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		fmt.Printf("Removed existing user %s\n", adminEmail)
	}

	// Generate secure password
	password, err := generatePassword(passwordLength)
	if err != nil {
		log.Fatalf("Failed to generate password: %v", err)
	}

	// Hash password — bcrypt cost 12 matches the server's default and
	// the documented policy. This is a one-shot seed CLI so we can't read
	// runtime config; the explicit literal documents the intent.
	hash, err := utils.HashPassword(password, 12)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	// Look up system_admin role
	var roleID string
	err = db.QueryRowContext(ctx, "SELECT id FROM roles WHERE code = 'system_admin' AND deleted_at IS NULL").Scan(&roleID)
	if err != nil {
		log.Fatalf("Failed to find system_admin role. Make sure migrations have been applied: %v", err)
	}

	// Insert user and assign role in a transaction
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Insert all columns to avoid NULLs in non-pointer struct fields (matches repository.Create behavior)
	var userID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO users (
			id, email, email_verified, phone, phone_verified,
			first_name, last_name, display_name, avatar_url, status,
			password_hash, auth_provider, provider_user_id,
			two_factor_enabled, two_factor_secret, failed_login_attempts,
			metadata, created_at, updated_at
		) VALUES (
			uuid_generate_v4(), $1, true, '', false,
			$2, $3, $4, '', 'active',
			$5, 'local', '',
			false, '', 0,
			'{}', NOW(), NOW()
		)
		RETURNING id
	`, adminEmail, adminFirstName, adminLastName, adminFirstName+" "+adminLastName, hash).Scan(&userID)
	if err != nil {
		log.Fatalf("Failed to insert user: %v", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO user_base_roles (user_id, role_id, assigned_at)
		VALUES ($1, $2, NOW())
	`, userID, roleID)
	if err != nil {
		log.Fatalf("Failed to assign system_admin role: %v", err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("Failed to commit transaction: %v", err)
	}

	// Verify the password works against the stored hash
	var storedHash string
	err = db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id = $1", userID).Scan(&storedHash)
	if err != nil {
		log.Fatalf("Failed to read back stored hash: %v", err)
	}
	if !utils.CheckPassword(password, storedHash) {
		log.Fatalf("VERIFICATION FAILED: password does not match stored hash")
	}

	fmt.Println("=== Super Admin User Created ===")
	fmt.Printf("Email:    %s\n", adminEmail)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("User ID:  %s\n", userID)
	fmt.Printf("Role:     system_admin (ID: %s)\n", roleID)
	fmt.Println("Password verified against stored hash: OK")
	fmt.Println("================================")
	fmt.Println("Save this password — it will not be shown again.")
}

// generatePassword creates a cryptographically secure password with mixed character types
func generatePassword(length int) (string, error) {
	const (
		lower   = "abcdefghijkmnopqrstuvwxyz"
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digits  = "23456789"
		special = "!@#$%&*+-="
	)
	all := lower + upper + digits + special

	// Ensure at least one of each type
	password := make([]byte, length)
	charsets := []string{lower, upper, digits, special}
	for i, cs := range charsets {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(cs))))
		if err != nil {
			return "", err
		}
		password[i] = cs[idx.Int64()]
	}

	// Fill remaining with random from all
	for i := len(charsets); i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(all))))
		if err != nil {
			return "", err
		}
		password[i] = all[idx.Int64()]
	}

	// Shuffle (Fisher-Yates)
	for i := length - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return string(password), nil
}
