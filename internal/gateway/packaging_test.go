package gateway

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// accounts defines recent_ack window as 5 minutes in internal/overlay/service.go:37
const ackRecentWindow = 5 * time.Minute

func parseSystemdDuration(val string) (time.Duration, error) {
	val = strings.TrimSpace(val)
	if strings.HasSuffix(val, "min") {
		numStr := strings.TrimSuffix(val, "min")
		d, err := time.ParseDuration(numStr + "m")
		if err != nil {
			return 0, err
		}
		return d, nil
	}
	return time.ParseDuration(val)
}

func TestGatewaySyncTimerIntervalWithinAckWindow(t *testing.T) {
	timerPath := filepath.Join("..", "..", "packaging", "systemd", "xconnect-gateway-sync.timer")
	file, err := os.Open(timerPath)
	if err != nil {
		t.Fatalf("failed to open timer file %s: %v", timerPath, err)
	}
	defer file.Close()

	var onUnitActiveSec time.Duration
	var accuracySec time.Duration

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "OnUnitActiveSec":
			d, err := parseSystemdDuration(val)
			if err != nil {
				t.Fatalf("failed to parse OnUnitActiveSec %q: %v", val, err)
			}
			onUnitActiveSec = d
		case "AccuracySec":
			d, err := parseSystemdDuration(val)
			if err != nil {
				t.Fatalf("failed to parse AccuracySec %q: %v", val, err)
			}
			accuracySec = d
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed reading timer file: %v", err)
	}

	if onUnitActiveSec == 0 {
		t.Fatal("OnUnitActiveSec not found or zero in timer file")
	}

	maxAllowed := ackRecentWindow / 3 // <= 100s
	totalInterval := onUnitActiveSec + accuracySec

	if totalInterval > maxAllowed {
		t.Fatalf("timer interval (%v) + accuracy (%v) = %v exceeds max allowed %v (1/3 of accounts ack window %v)",
			onUnitActiveSec, accuracySec, totalInterval, maxAllowed, ackRecentWindow)
	}
}
