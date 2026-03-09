package scripts

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

const auditScript = `#!/bin/bash
echo "===SSHD_CONFIG==="
cat /etc/ssh/sshd_config 2>/dev/null
echo "===AUTHORIZED_KEYS==="
for home in /home/* /root; do
  [ -f "$home/.ssh/authorized_keys" ] && echo "USER:$(basename "$home")" && cat "$home/.ssh/authorized_keys"
done
echo "===PASSWD==="
getent passwd
echo "===GROUPS==="
getent group
echo "===SUDOERS==="
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null
echo "===HOST_KEYS==="
for f in /etc/ssh/ssh_host_*_key.pub; do
  ssh-keygen -lf "$f" 2>/dev/null
done
echo "===LAST_LOGIN==="
lastlog 2>/dev/null
`

const auditTimeout = 60 * time.Second

func RunAudit(logger *logrus.Logger) ProvisioningResult {
	logger.Info("Running SSH posture audit")

	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", auditScript)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("Audit script timed out")
			return ProvisioningResult{
				Success: false,
				Error:   fmt.Sprintf("audit script timed out after %s", auditTimeout),
			}
		}
		logger.WithFields(logrus.Fields{
			"error":  err.Error(),
			"stderr": stderr.String(),
		}).Error("Audit script failed")
		return ProvisioningResult{
			Success: false,
			Error:   fmt.Sprintf("audit script failed: %v: %s", err, stderr.String()),
		}
	}

	logger.Info("Audit script completed successfully")
	return ProvisioningResult{
		Success: true,
		Message: "Audit completed successfully",
		Output:  stdout.String(),
	}
}
