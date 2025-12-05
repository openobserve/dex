package client

import (
	"context"
	"strings"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent/db/signuptoken"
)

// CreateSignupToken saves provided token into the database.
func (d *Database) CreateSignupToken(ctx context.Context, token storage.SignupToken) error {
	_, err := d.client.SignupToken.Create().
		SetEmail(token.Email).
		SetCsrfToken(token.CsrfToken).
		SetValidationToken(token.ValidationToken).
		SetExpiry(token.Expiry).
		Save(ctx)
	if err != nil {
		return convertDBError("create signup token: %w", err)
	}
	return nil
}

// GetToken gets a token from the database by email.
func (d *Database) GetSignupToken(ctx context.Context, email string) (storage.SignupToken, error) {
	email = strings.ToLower(email)
	validationFromStorage, err := d.client.SignupToken.Query().
		Where(signuptoken.Email(email)).
		Only(ctx)
	if err != nil {
		return storage.SignupToken{}, convertDBError("get signup token: %w", err)
	}
	return toStorageSignupToken(validationFromStorage), nil
}

// DeleteToken deletes a token from the database by email.
func (d *Database) DeleteSignupToken(ctx context.Context, email string) error {
	email = strings.ToLower(email)
	_, err := d.client.SignupToken.Delete().
		Where(signuptoken.Email(email)).
		Exec(ctx)
	if err != nil {
		return convertDBError("delete signup token: %w", err)
	}
	return nil
}
