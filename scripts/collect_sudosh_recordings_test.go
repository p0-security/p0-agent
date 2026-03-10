package scripts

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAppendAuditEventsToSudoshExport(t *testing.T) {
	t.Parallel()

	sessionID := "alice-alice-script-1710000000-testsession"
	scriptOutput := strings.Join([]string{
		"Aarons-MacBook-Pro:~ alice$ echo hello",
		"hello",
		"Aarons-MacBook-Pro:~ alice$ pwd",
		"/Users/alice",
	}, "\r\n")
	timingOutput := strings.Join([]string{
		"1.0 10",
		"1.0 10",
	}, "\n")

	exportPayload := strings.Join([]string{
		"=== Exporting sudosh session recordings ===",
		"=== EXPORT_START ===",
		"SESSIONS_COUNT: 1",
		"",
		"=== SESSION_START ===",
		"SESSION_ID: " + sessionID,
		"SCRIPT_BASE64:",
		base64.StdEncoding.EncodeToString([]byte(scriptOutput)),
		"TIMING_BASE64:",
		base64.StdEncoding.EncodeToString([]byte(timingOutput)),
		"=== SESSION_END ===",
		"",
		"=== EXPORT_END ===",
	}, "\n")

	augmentedOutput, err := appendAuditEventsToSudoshExport(exportPayload, "alice")
	if err != nil {
		t.Fatalf("appendAuditEventsToSudoshExport returned error: %v", err)
	}

	if !strings.Contains(augmentedOutput, "AUDIT_EVENTS_JSON:") {
		t.Fatalf("expected augmented output to contain AUDIT_EVENTS_JSON section, got:\n%s", augmentedOutput)
	}

	eventsJSON := lineAfterMarker(t, augmentedOutput, "AUDIT_EVENTS_JSON:")

	var events []auditEventRow
	if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
		t.Fatalf("failed to unmarshal audit events JSON: %v", err)
	}

	if len(events) != 4 {
		t.Fatalf("expected 4 audit events, got %d", len(events))
	}

	if events[0].Action != "session.started" {
		t.Fatalf("expected first event to be session.started, got %q", events[0].Action)
	}
	if events[1].Action != "terminal.command" || events[1].Summary != "Command executed: echo hello" {
		t.Fatalf("unexpected first command event: %#v", events[1])
	}
	if events[2].Action != "terminal.command" || events[2].Summary != "Command executed: pwd" {
		t.Fatalf("unexpected second command event: %#v", events[2])
	}
	if events[3].Action != "session.ended" {
		t.Fatalf("expected final event to be session.ended, got %q", events[3].Action)
	}

	expectedStart := time.Unix(1710000000, 0).UTC().Format(time.RFC3339)
	expectedEnd := time.Unix(1710000000, 0).UTC().Add(2 * time.Second).Format(time.RFC3339)

	if events[0].Timestamp != expectedStart {
		t.Fatalf("expected session start timestamp %q, got %q", expectedStart, events[0].Timestamp)
	}
	if events[3].Timestamp != expectedEnd {
		t.Fatalf("expected session end timestamp %q, got %q", expectedEnd, events[3].Timestamp)
	}

	if !strings.Contains(augmentedOutput, base64.StdEncoding.EncodeToString([]byte(scriptOutput))) {
		t.Fatal("expected script playback payload to be preserved in augmented output")
	}
	if !strings.Contains(augmentedOutput, base64.StdEncoding.EncodeToString([]byte(timingOutput))) {
		t.Fatal("expected timing playback payload to be preserved in augmented output")
	}
}

func lineAfterMarker(t *testing.T, body, marker string) string {
	t.Helper()

	lines := strings.Split(body, "\n")
	for index, line := range lines {
		if line == marker {
			if index+1 >= len(lines) {
				t.Fatalf("marker %q found without following line", marker)
			}
			return lines[index+1]
		}
	}

	t.Fatalf("marker %q not found in body", marker)
	return ""
}
