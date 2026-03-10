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
	recordingsCollectionTimeout = 2 * time.Minute
)

const collectSudoshRecordingsScript = `#!/bin/bash
set -e

LOG_DIR="/var/log/sudosh"

USERNAME="${USERNAME:-}"
START_TIME="${START_TIME:-}"
END_TIME="${END_TIME:-}"

echo "=== Exporting sudosh session recordings ==="

if [ -z "$USERNAME" ]; then
    echo "ERROR: USERNAME environment variable is required"
    exit 1
fi

if [ ! -d "$LOG_DIR" ]; then
    echo "ERROR: Log directory $LOG_DIR does not exist"
    exit 1
fi

parse_timestamp() {
    local input="$1"

    if [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "$input"
        return
    fi

    if date --version >/dev/null 2>&1; then
        date -d "$input" +%s 2>/dev/null || echo "0"
    else
        date -j -f "%Y-%m-%dT%H:%M:%SZ" "$input" +%s 2>/dev/null || echo "0"
    fi
}

if [ -n "$START_TIME" ]; then
    START_TIMESTAMP=$(parse_timestamp "$START_TIME")
else
    START_TIMESTAMP=0
fi

if [ -n "$END_TIME" ]; then
    END_TIMESTAMP=$(parse_timestamp "$END_TIME")
else
    END_TIMESTAMP=9999999999
fi

echo "Searching for recordings:"
echo "  Username: $USERNAME"
echo "  Start time: $START_TIME (timestamp: $START_TIMESTAMP)"
echo "  End time: $END_TIME (timestamp: $END_TIMESTAMP)"
echo ""

extract_session_timestamp() {
    local filename="$1"
    local prefix="${filename%-script-*}"
    local suffix="${filename#${prefix}-script-}"
    local timestamp=$(echo "$suffix" | cut -d'-' -f1)
    echo "$timestamp"
}

cd "$LOG_DIR"

matching_sessions=()

shopt -s nullglob
for script_file in ${USERNAME}-*-script-*; do
    if [ -f "$script_file" ]; then
        session_id="${script_file%-script-*}"
        suffix="${script_file#*-script-}"
        timing_file="${session_id}-time-${suffix}"

        if [ ! -f "$timing_file" ]; then
            echo "WARNING: Timing file missing for ${session_id}-time-${suffix}, skipping"
            continue
        fi

        file_timestamp=$(extract_session_timestamp "$script_file")

        if [ "$file_timestamp" -ge "$START_TIMESTAMP" ] && [ "$file_timestamp" -le "$END_TIMESTAMP" ]; then
            matching_sessions+=("$script_file")
        fi
    fi
done

echo "Found ${#matching_sessions[@]} matching session(s)"
echo ""

if [ ${#matching_sessions[@]} -eq 0 ]; then
    echo "No recordings found matching criteria"
    exit 0
fi

echo "=== EXPORT_START ==="
echo "SESSIONS_COUNT: ${#matching_sessions[@]}"
echo ""

for script_file in "${matching_sessions[@]}"; do
    session_id="${script_file%-script-*}"
    suffix="${script_file#*-script-}"
    timing_file="${session_id}-time-${suffix}"

    echo "=== SESSION_START ==="
    echo "SESSION_ID: ${script_file}"
    echo "SCRIPT_BASE64:"
    base64 < "$script_file"
    echo "TIMING_BASE64:"
    base64 < "$timing_file"
    echo "=== SESSION_END ==="
    echo ""
done

echo "=== EXPORT_END ==="
echo ""
echo "=== Export Complete ==="
`

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

	cmd := exec.CommandContext(ctx, "bash", "-c", collectSudoshRecordingsScript)
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
