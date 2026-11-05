package sql

import (
	"strings"
	"testing"
)

// signupTokensMigration is the 1-based position of the fork's signup_tokens migration. Production
// databases recorded it at this number, so upstream migrations must only ever be appended after it.
const signupTokensMigration = 12

func TestSignupTokensMigrationPosition(t *testing.T) {
	for _, fl := range []struct {
		name   string
		flavor *flavor
	}{{"postgres", &flavorPostgres}, {"sqlite3", &flavorSQLite3}} {
		t.Run(fl.name, func(t *testing.T) {
			var found []int
			n := 0
			for _, m := range migrations {
				if m.flavor != nil && m.flavor != fl.flavor {
					continue
				}
				n++
				for _, stmt := range m.stmts {
					if strings.Contains(stmt, "create table signup_tokens") {
						found = append(found, n)
					}
				}
			}
			if len(found) != 1 || found[0] != signupTokensMigration {
				t.Fatalf("signup_tokens must be created by migration %d only, found at %v", signupTokensMigration, found)
			}
		})
	}
}
