package scripts

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

func isValidUsername(username string) bool {
	pattern := `^[a-z][-a-z0-9_]*$`
	matched, _ := regexp.MatchString(pattern, username)
	return matched
}

func findNextAvailableUID() (int, error) {
	const minUID, maxUID = 65536, 90000

	for uid := minUID; uid <= maxUID; uid++ {
		if _, err := user.LookupId(strconv.Itoa(uid)); err != nil {
			return uid, nil
		}
	}

	return 0, fmt.Errorf("no available UID found in range %d-%d", minUID, maxUID)
}

func commandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

func ensureContentInFile(content, requestID, filePath, permission, owner string, logger *logrus.Logger) ProvisioningResult {
	comment := fmt.Sprintf("# RequestID: %s", requestID)

	logger.WithFields(logrus.Fields{
		"file":       filePath,
		"request_id": requestID,
		"owner":      owner,
	}).Debug("Ensuring content in file")

	dir := filepath.Dir(filePath)
	if err := exec.Command("sudo", "mkdir", "-p", dir).Run(); err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to create directory %s: %v", dir, err),
		}
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if err := exec.Command("sudo", "touch", filePath).Run(); err != nil {
			return ProvisioningResult{
				Success: false,
				Error:   fmt.Sprintf("failed to create file %s: %v", filePath, err),
			}
		}
		if err := exec.Command("sudo", "chmod", permission, filePath).Run(); err != nil {
			return ProvisioningResult{
				Success: false,
				Error:   fmt.Sprintf("failed to set permissions on %s: %v", filePath, err),
			}
		}
	}

	grepCmd := exec.Command("sudo", "grep", "-qF", comment, filePath)
	commentExists := grepCmd.Run() == nil

	grepCmd = exec.Command("sudo", "grep", "-qF", content, filePath)
	contentExists := grepCmd.Run() == nil

	if commentExists && contentExists {
		logger.Debug("Content already exists in file")
		return ProvisioningResult{
			Success: true,
			Message: "Content already exists in file",
		}
	}

	appendCmd := exec.Command("sudo", "tee", "-a", filePath)
	appendCmd.Stdin = strings.NewReader(comment + "\n" + content + "\n")
	if err := appendCmd.Run(); err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to append content to %s: %v", filePath, err),
		}
	}

	if owner != "root" && owner != "" {
		sshDir := filepath.Dir(filePath)
		if err := exec.Command("sudo", "chown", "-R", owner+":"+owner, sshDir).Run(); err != nil {
			logger.WithError(err).Warn("Failed to set ownership, but content was added successfully")
		}
	}

	return ProvisioningResult{
		Success: true,
		Message: fmt.Sprintf("Content added to %s successfully", filePath),
	}
}

func removeContentFromFile(requestID, filePath string, logger *logrus.Logger) ProvisioningResult {
	comment := fmt.Sprintf("# RequestID: %s", requestID)

	logger.WithFields(logrus.Fields{
		"file":       filePath,
		"request_id": requestID,
	}).Debug("Removing content from file")

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return ProvisioningResult{
			Success: true,
			Message: "File does not exist, nothing to remove",
		}
	}

	sedPattern := fmt.Sprintf("/^%s$/,/^$/d", regexp.QuoteMeta(comment))
	cmd := exec.Command("sudo", "sed", "-i", sedPattern, filePath)
	if err := cmd.Run(); err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to remove content from %s: %v", filePath, err),
		}
	}

	return ProvisioningResult{
		Success: true,
		Message: fmt.Sprintf("Content removed from %s successfully", filePath),
	}
}

func ensureLineInFile(line, filePath string, logger *logrus.Logger) ProvisioningResult {
	logger.WithFields(logrus.Fields{
		"file": filePath,
		"line": line,
	}).Debug("Ensuring line in file")

	grepCmd := exec.Command("sudo", "grep", "-qF", line, filePath)
	if grepCmd.Run() == nil {
		return ProvisioningResult{
			Success: true,
			Message: "Line already exists in file",
		}
	}

	appendCmd := exec.Command("sudo", "tee", "-a", filePath)
	appendCmd.Stdin = strings.NewReader(line + "\n")
	if err := appendCmd.Run(); err != nil {
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to append line to %s: %v", filePath, err),
		}
	}

	return ProvisioningResult{
		Success: true,
		Message: fmt.Sprintf("Line added to %s successfully", filePath),
	}
}

func ExecuteScript(command string, data interface{}, dryRun bool, logger *logrus.Logger) ProvisioningResult {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal script data")
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to marshal script data: %v", err),
		}
	}

	var req ProvisioningRequest
	if err := json.Unmarshal(dataBytes, &req); err != nil {
		logger.WithError(err).Error("Failed to unmarshal script data to ProvisioningRequest")
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to unmarshal ProvisioningRequest: %v", err),
		}
	}

	logger.WithFields(logrus.Fields{
		"command":    command,
		"username":   req.UserName,
		"action":     req.Action,
		"request_id": req.RequestID,
		"sudo":       req.Sudo,
		"has_key":    req.PublicKey != "" && req.PublicKey != "N/A",
		"dry_run":    dryRun,
	}).Info("🚀 Executing provisioning script")

	if dryRun {
		logger.WithFields(logrus.Fields{
			"command":  command,
			"username": req.UserName,
			"action":   req.Action,
		}).Info("🔍 DRY-RUN: Would execute provisioning script (no actual changes made)")
		
		return ProvisioningResult{
			Success: true,
			Message: fmt.Sprintf("DRY-RUN: Would execute %s for user %s", command, req.UserName),
		}
	}

	switch Command(command) {
	case CommandRunAudit:
		return RunAudit(logger)
	case CommandProvisionUser:
		return ProvisionUser(req, logger)
	case CommandProvisionAuthorizedKeys:
		return ProvisionAuthorizedKeys(req, logger)
	case CommandProvisionCAKeys:
		return ProvisionCAKeys(req, logger)
	case CommandProvisionSudo:
		return ProvisionSudo(req, logger)
	case CommandProvisionSession:
		return ProvisionSession(req, logger)
	default:
		logger.WithField("command", command).Error("Unknown provisioning command")
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("unknown command: %s", command),
		}
	}
}