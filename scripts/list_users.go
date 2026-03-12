package scripts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// noLoginShells are shells that indicate a user cannot log in interactively.
var noLoginShells = map[string]bool{
	"/sbin/nologin":     true,
	"/usr/sbin/nologin": true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
}

// ListUsers returns all OS users with a valid login shell.
func ListUsers(logger *logrus.Logger) ProvisioningResult {
	logger.Info("Listing OS users via getent passwd")

	out, err := exec.Command("getent", "passwd").Output()
	if err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to run getent passwd: %v", err),
		}
	}

	var users []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// passwd format: name:password:uid:gid:gecos:home:shell
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 7 {
			continue
		}
		shell := strings.TrimSpace(parts[6])
		if shell != "" && !noLoginShells[shell] {
			users = append(users, parts[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to read getent passwd output: %v", err),
		}
	}

	encoded, err := json.Marshal(users)
	if err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to encode user list: %v", err),
		}
	}

	logger.WithField("count", len(users)).Info("Found OS users")

	return ProvisioningResult{
		Success: true,
		Message: fmt.Sprintf("found %d users", len(users)),
		Output:  string(encoded),
	}
}
