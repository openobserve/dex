package client

import (
	"fmt"
	"hash"
	"math/rand"
	"time"

	"github.com/pkg/errors"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent/db"
)

var stdNums = []byte("0123456789")

func rollback(tx *db.Tx, t string, err error) error {
	rerr := tx.Rollback()
	err = convertDBError(t, err)

	if rerr == nil {
		return err
	}
	return errors.Wrapf(err, "rolling back transaction: %v", rerr)
}

func convertDBError(t string, err error) error {
	if db.IsNotFound(err) {
		return storage.ErrNotFound
	}

	if db.IsConstraintError(err) {
		return storage.ErrAlreadyExists
	}

	return fmt.Errorf(t, err)
}

// compose hashed id from user and connection id to use it as primary key
// ent doesn't support multi-key primary yet
// https://github.com/facebook/ent/issues/400
func offlineSessionID(userID string, connID string, hasher func() hash.Hash) string {
	h := hasher()

	h.Write([]byte(userID))
	h.Write([]byte(connID))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// copied from https://github.com/openobserve/casdoor/blob/master/object/verification.go#L357-L367
func getRandomCode(length int) string {
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, stdNums[r.Intn(len(stdNums))])
	}
	return string(result)
}
