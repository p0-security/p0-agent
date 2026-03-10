package scripts

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	retrieveRecordingsScriptPath = "/usr/local/bin/retrieve-recordings.sh"
	recordingsCollectionTimeout  = 2 * time.Minute
)

// CollectSudoshRecordings exports sudosh recordings for a user and optional time range.
func CollectSudoshRecordings(req ProvisioningRequest, logger *logrus.Logger) ProvisioningResult {
	logger.WithFields(logrus.Fields{
		"username":   req.UserName,
		"start_time": req.StartTime,
		"end_time":   req.EndTime,
	}).Info("Collecting sudosh recordings")

	if !isValidUsername(req.UserName) {
		return ProvisioningResult{
			Success: false,
			Error:   "invalid username format: must match ^[a-z][-a-z0-9_]*$",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), recordingsCollectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, retrieveRecordingsScriptPath)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("USERNAME=%s", req.UserName),
		fmt.Sprintf("START_TIME=%s", req.StartTime),
		fmt.Sprintf("END_TIME=%s", req.EndTime),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("Sudosh recordings export timed out")
			return ProvisioningResult{
				Success: false,
				Error:   fmt.Sprintf("recordings export timed out after %s", recordingsCollectionTimeout),
			}
		}

		logger.WithFields(logrus.Fields{
			"error":  err.Error(),
			"stderr": stderr.String(),
		}).Error("Sudosh recordings export failed")

		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("failed to collect sudosh recordings: %v: %s", err, stderr.String()),
		}
	}

	logger.WithField("username", req.UserName).Info("Sudosh recordings collected successfully")
	return ProvisioningResult{
		Success: true,
		Message: "Sudosh recordings collected successfully",
		Output:  stdout.String(),
	}
}
