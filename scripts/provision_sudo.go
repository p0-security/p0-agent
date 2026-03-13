package scripts

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func ProvisionSudo(req ProvisioningRequest, logger *logrus.Logger) ProvisioningResult {
	logger.WithFields(logrus.Fields{
		"username":   req.UserName,
		"action":     req.Action,
		"request_id": req.RequestID,
		"sudo":       req.Sudo,
		"runAsUser":  req.RunAsUser,
	}).Info("⚡ Provisioning sudo access")

	if !req.Sudo && req.RunAsUser == "" && req.Action == "grant" {
		return ProvisioningResult{
			Success: true,
			Message: "Sudo access not requested, skipping sudo provisioning",
		}
	}

	sudoersFile := "/etc/sudoers-p0"
	runAs := "ALL"
	if req.RunAsUser != "" {
		runAs = req.RunAsUser
	}
	sudoRule := fmt.Sprintf("%s ALL=(%s) NOPASSWD: ALL", req.UserName, runAs)

	switch req.Action {
	case "grant":
		return grantSudoAccess(sudoRule, req.RequestID, sudoersFile, logger)
	case "revoke":
		return revokeSudoAccess(req.RequestID, sudoersFile, logger)
	default:
		return ProvisioningResult{
			Success: false,
			Error:   "invalid action: must be 'grant' or 'revoke'",
		}
	}
}

func grantSudoAccess(sudoRule, requestID, sudoersFile string, logger *logrus.Logger) ProvisioningResult {
	logger.WithFields(logrus.Fields{
		"rule":       sudoRule,
		"request_id": requestID,
		"file":       sudoersFile,
	}).Debug("Granting sudo access")

	result := ensureContentInFile(sudoRule, requestID, sudoersFile, "440", "root", logger)
	if !result.Success {
		return result
	}

	includeResult := ensureLineInFile("#include sudoers-p0", "/etc/sudoers", logger)
	if !includeResult.Success {
		return includeResult
	}

	return ProvisioningResult{
		Success: true,
		Message: fmt.Sprintf("Sudo access granted successfully for rule: %s", sudoRule),
	}
}

func revokeSudoAccess(requestID, sudoersFile string, logger *logrus.Logger) ProvisioningResult {
	logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"file":       sudoersFile,
	}).Debug("Revoking sudo access")

	result := removeContentFromFile(requestID, sudoersFile, logger)
	if !result.Success {
		return result
	}

	return ProvisioningResult{
		Success: true,
		Message: fmt.Sprintf("Sudo access revoked successfully for RequestID: %s", requestID),
	}
}
