package tokens

import (
	"os"
	"strings"

	"github.com/dexidp/dex/storage"
)

// ApplyResetGroups replaces the groups claim with the comma-separated RESET_GROUPS env var when it is set.
func ApplyResetGroups(c *storage.Claims) {
	if resetGroups := os.Getenv("RESET_GROUPS"); resetGroups != "" {
		c.Groups = strings.Split(resetGroups, ",")
	}
}
