package scripts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	recordingsCollectionTimeout = 2 * time.Minute
)

type auditEventRow struct {
	ID        string      `json:"id"`
	Timestamp string      `json:"timestamp"`
	Action    string      `json:"action,omitempty"`
	Actor     string      `json:"actor,omitempty"`
	Target    string      `json:"target,omitempty"`
	Summary   string      `json:"summary"`
	Details   interface{} `json:"details,omitempty"`
	Severity  string      `json:"severity,omitempty"`
	Raw       interface{} `json:"raw,omitempty"`
}

type sudoshExportSession struct {
	sessionID   string
	scriptLines []string
	timingLines []string
}

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

	augmentedOutput, err := appendAuditEventsToSudoshExport(stdout.String(), req.UserName)
	if err != nil {
		logger.WithError(err).Warn("Failed to derive audit events from sudosh export; returning playback payload only")
		augmentedOutput = stdout.String()
	}

	return ProvisioningResult{
		Success: true,
		Message: "Sudosh recordings collected successfully",
		Output:  augmentedOutput,
	}
}

func appendAuditEventsToSudoshExport(output, username string) (string, error) {
	lines := strings.Split(output, "\n")
	var rebuilt []string

	for index := 0; index < len(lines); index++ {
		line := lines[index]
		if line != "=== SESSION_START ===" {
			rebuilt = append(rebuilt, line)
			continue
		}

		session, nextIndex, err := parseSudoshSessionBlock(lines, index)
		if err != nil {
			return "", err
		}

		events, err := deriveAuditEvents(session, username)
		if err != nil {
			return "", err
		}

		eventsJSON, err := json.Marshal(events)
		if err != nil {
			return "", fmt.Errorf("marshal audit events for %s: %w", session.sessionID, err)
		}

		rebuilt = append(rebuilt, "=== SESSION_START ===")
		rebuilt = append(rebuilt, fmt.Sprintf("SESSION_ID: %s", session.sessionID))
		rebuilt = append(rebuilt, "SCRIPT_BASE64:")
		rebuilt = append(rebuilt, session.scriptLines...)
		rebuilt = append(rebuilt, "TIMING_BASE64:")
		rebuilt = append(rebuilt, session.timingLines...)
		rebuilt = append(rebuilt, "AUDIT_EVENTS_JSON:")
		rebuilt = append(rebuilt, string(eventsJSON))
		rebuilt = append(rebuilt, "=== SESSION_END ===")

		index = nextIndex
	}

	return strings.Join(rebuilt, "\n"), nil
}

func parseSudoshSessionBlock(lines []string, start int) (sudoshExportSession, int, error) {
	session := sudoshExportSession{}
	state := ""

	for index := start + 1; index < len(lines); index++ {
		line := lines[index]

		switch {
		case strings.HasPrefix(line, "SESSION_ID: "):
			session.sessionID = strings.TrimPrefix(line, "SESSION_ID: ")
		case line == "SCRIPT_BASE64:":
			state = "script"
		case line == "TIMING_BASE64:":
			state = "timing"
		case line == "=== SESSION_END ===":
			if session.sessionID == "" {
				return sudoshExportSession{}, 0, fmt.Errorf("missing SESSION_ID in sudosh export")
			}
			return session, index, nil
		default:
			switch state {
			case "script":
				if line != "" {
					session.scriptLines = append(session.scriptLines, line)
				}
			case "timing":
				if line != "" {
					session.timingLines = append(session.timingLines, line)
				}
			}
		}
	}

	return sudoshExportSession{}, 0, fmt.Errorf("unterminated session block in sudosh export")
}

func deriveAuditEvents(session sudoshExportSession, username string) ([]auditEventRow, error) {
	scriptBytes, err := base64.StdEncoding.DecodeString(strings.Join(session.scriptLines, ""))
	if err != nil {
		return nil, fmt.Errorf("decode script for %s: %w", session.sessionID, err)
	}

	timingBytes, err := base64.StdEncoding.DecodeString(strings.Join(session.timingLines, ""))
	if err != nil {
		return nil, fmt.Errorf("decode timing for %s: %w", session.sessionID, err)
	}

	startTime := parseSessionStartTime(session.sessionID)
	duration := parseSessionDuration(string(timingBytes))
	endTime := startTime.Add(duration)

	var events []auditEventRow
	events = append(events, auditEventRow{
		ID:        fmt.Sprintf("%s-start", session.sessionID),
		Timestamp: startTime.Format(time.RFC3339),
		Action:    "session.started",
		Actor:     username,
		Target:    session.sessionID,
		Summary:   "SSH session recording started",
		Details: map[string]interface{}{
			"sessionId": session.sessionID,
		},
		Severity: "info",
		Raw: map[string]interface{}{
			"sessionId": session.sessionID,
		},
	})

	commandLines := extractCommandLines(string(scriptBytes))
	commandCount := len(commandLines)
	for index, commandLine := range commandLines {
		commandTimestamp := startTime
		if duration > 0 && commandCount > 0 {
			offset := time.Duration(float64(duration) * float64(index+1) / float64(commandCount+1))
			commandTimestamp = startTime.Add(offset)
		}

		events = append(events, auditEventRow{
			ID:        fmt.Sprintf("%s-command-%d", session.sessionID, index),
			Timestamp: commandTimestamp.Format(time.RFC3339),
			Action:    "terminal.command",
			Actor:     username,
			Target:    session.sessionID,
			Summary:   fmt.Sprintf("Command executed: %s", commandLine),
			Details: map[string]interface{}{
				"command":   commandLine,
				"sessionId": session.sessionID,
				"index":     index,
			},
			Severity: "info",
			Raw: map[string]interface{}{
				"line": commandLine,
			},
		})
	}

	events = append(events, auditEventRow{
		ID:        fmt.Sprintf("%s-end", session.sessionID),
		Timestamp: endTime.Format(time.RFC3339),
		Action:    "session.ended",
		Actor:     username,
		Target:    session.sessionID,
		Summary:   "SSH session recording ended",
		Details: map[string]interface{}{
			"sessionId":       session.sessionID,
			"durationSeconds": duration.Seconds(),
		},
		Severity: "info",
		Raw: map[string]interface{}{
			"sessionId": session.sessionID,
		},
	})

	return events, nil
}

func parseSessionStartTime(sessionID string) time.Time {
	marker := strings.LastIndex(sessionID, "-script-")
	if marker == -1 {
		return time.Now().UTC()
	}

	suffix := sessionID[marker+len("-script-"):]
	timestampToken := strings.SplitN(suffix, "-", 2)[0]
	seconds, err := strconv.ParseInt(timestampToken, 10, 64)
	if err != nil {
		return time.Now().UTC()
	}

	return time.Unix(seconds, 0).UTC()
}

func parseSessionDuration(timingOutput string) time.Duration {
	var totalSeconds float64
	for _, line := range strings.Split(timingOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		delaySeconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		totalSeconds += delaySeconds
	}

	return time.Duration(totalSeconds * float64(time.Second))
}

func extractCommandLines(scriptOutput string) []string {
	var commands []string

	for _, line := range strings.Split(strings.ReplaceAll(scriptOutput, "\r", ""), "\n") {
		cleanedLine := strings.TrimSpace(line)
		if cleanedLine == "" {
			continue
		}

		if marker := strings.LastIndex(cleanedLine, "$ "); marker != -1 {
			command := strings.TrimSpace(cleanedLine[marker+2:])
			if command != "" {
				commands = append(commands, command)
			}
			continue
		}

		if marker := strings.LastIndex(cleanedLine, "# "); marker != -1 {
			command := strings.TrimSpace(cleanedLine[marker+2:])
			if command != "" {
				commands = append(commands, command)
			}
		}
	}

	return commands
}
