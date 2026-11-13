// Package signout ends a user's sign-ins: it tells relying parties through
// back-channel logout, revokes refresh tokens and deletes the browser sessions.
// The gRPC API and the password-reset flow share it, so ending access means the
// same thing wherever it is asked for.
package signout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dexidp/dex/server/backchannel"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

// Terminator ends sessions and the tokens issued from them.
type Terminator struct {
	Storage storage.Storage
	// Backchannel may be nil, in which case relying parties are not notified.
	Backchannel *backchannel.Notifier
	Refresh     *tokens.RefreshStore
	Logger      *slog.Logger
}

// EndSessions ends every auth session match selects: it notifies the session's
// relying parties, revokes the user's refresh tokens on that connector and
// deletes the session. It returns how many sessions were deleted. A session that
// fails to delete is logged and skipped so one bad row does not stop the rest.
func (t *Terminator) EndSessions(ctx context.Context, match func(storage.AuthSession) bool) (int64, error) {
	sessions, err := t.Storage.ListAuthSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("list auth sessions: %w", err)
	}

	var ended int64
	for _, s := range sessions {
		if !match(s) {
			continue
		}

		if t.Backchannel != nil {
			t.Backchannel.Notify(ctx, &s)
		}
		t.Refresh.RevokeAll(ctx, s.UserID, s.ConnectorID)

		if err := t.Storage.DeleteAuthSession(ctx, s.ID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			t.Logger.ErrorContext(ctx, "failed to delete auth session",
				"session_id", s.ID, "user_id", s.UserID, "err", err)
			continue
		}
		ended++
	}
	return ended, nil
}

// EndUser ends all of one user's access through one connector: every auth
// session, and every refresh token, including tokens issued without a browser
// session (sessions disabled, or the password grant). It returns how many
// sessions were deleted.
func (t *Terminator) EndUser(ctx context.Context, userID, connectorID string) (int64, error) {
	ended, err := t.EndSessions(ctx, func(s storage.AuthSession) bool {
		return s.UserID == userID && s.ConnectorID == connectorID
	})
	// Refresh tokens live in the offline session, not the auth session, so revoke
	// them even when listing sessions failed or found none.
	t.Refresh.RevokeAll(ctx, userID, connectorID)
	return ended, err
}
