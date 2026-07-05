// Package models provides shared domain models used across the auction platform
package models

import (
	"time"

	"github.com/rw3iss/auth/pkg/shared/types"
)

// BaseModel contains common fields for all entities
type BaseModel struct {
	ID        types.ID        `json:"id" db:"id"`
	CreatedAt types.Timestamp `json:"created_at" db:"created_at"`
	UpdatedAt types.Timestamp `json:"updated_at" db:"updated_at"`
}

// NewBaseModel creates a new BaseModel with generated ID and timestamps
func NewBaseModel() BaseModel {
	now := types.Now()
	return BaseModel{
		ID:        types.NewID(),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Touch updates the UpdatedAt timestamp
func (b *BaseModel) Touch() {
	b.UpdatedAt = types.Now()
}

// SoftDeletable adds soft delete capability
type SoftDeletable struct {
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// IsDeleted checks if the entity is soft deleted
func (s *SoftDeletable) IsDeleted() bool {
	return s.DeletedAt != nil
}

// Delete soft deletes the entity
func (s *SoftDeletable) Delete() {
	now := types.Now()
	s.DeletedAt = &now
}

// Restore restores a soft deleted entity
func (s *SoftDeletable) Restore() {
	s.DeletedAt = nil
}

// AuditInfo contains audit trail information
type AuditInfo struct {
	CreatedBy *types.ID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *types.ID `json:"updated_by,omitempty" db:"updated_by"`
	DeletedBy *types.ID `json:"deleted_by,omitempty" db:"deleted_by"`
}
