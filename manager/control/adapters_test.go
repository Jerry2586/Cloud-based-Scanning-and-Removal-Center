package control

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeExec struct {
	call func(string, []string) CommandResult
}

func (f fakeExec) Execute(_ context.Context, p string, a []string) CommandResult { return f.call(p, a) }
func TestTrivyUsesFixedLocalTargetsAndSeparatesVulnerabilities(t *testing.T) {
	q := requestFixture()
	e := Trivy{Database: freshTrivyDB, Exec: fakeExec{func(p string, a []string) CommandResult {
		if p != "/usr/local/bin/trivy" || a[len(a)-1] != q.Images[0] {
			t.Fatal(p, a)
		}
		joined := strings.Join(a, " ")
		for _, flag := range []string{"--image-src docker", "--scanners vuln", "--offline-scan", "--skip-db-update", "--disable-telemetry", "--skip-version-check", "--ignorefile /dev/null"} {
			if !strings.Contains(joined, flag) {
				t.Fatal("missing fixed constraint", flag)
			}
		}
		b, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": q.Images[0], "Results": []any{map[string]any{"Vulnerabilities": []any{map[string]string{"VulnerabilityID": "CVE-2026-0001", "PkgName": "example", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}}}}})
		return CommandResult{Output: b}
	}}}
	r := e.Run(context.Background(), q, func(Result) {})
	if r.State != "complete" || r.Completed != 1 || len(r.Findings) != 1 || r.Findings[0].Kind != "vulnerability" {
		t.Fatal(r)
	}
}
func TestTrivyDoesNotTreatErrorsOrUnknownImagesAsClean(t *testing.T) {
	q := requestFixture()
	wrong, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": "other", "Results": []any{}})
	for _, c := range []CommandResult{{Code: -1, Err: errors.New("absent")}, {Output: wrong}, {Output: []byte("not-json")}} {
		r := (Trivy{Database: freshTrivyDB, Exec: fakeExec{func(string, []string) CommandResult { return c }}}).Run(context.Background(), q, func(Result) {})
		if r.State == "complete" || r.Completed != 0 {
			t.Fatal(r)
		}
	}
	q.DiscoveryComplete = false
	clean, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": q.Images[0], "Results": []any{}})
	r := (Trivy{Database: freshTrivyDB, Exec: fakeExec{func(string, []string) CommandResult { return CommandResult{Output: clean} }}}).Run(context.Background(), q, func(Result) {})
	if r.State != "partial" {
		t.Fatal("incomplete discovery silently passed")
	}
}
func TestOsqueryAssetReportIsNeverMalwareVerdict(t *testing.T) {
	b, _ := json.Marshal([]map[string]string{{"pid": "42", "port": "443", "protocol": "6", "address": "0.0.0.0", "name": "caddy"}})
	r := (Osquery{fakeExec{func(p string, a []string) CommandResult {
		if p != "/usr/bin/osqueryi" || a[len(a)-1] != portSQL || !reflect.DeepEqual(a[:4], []string{"--json", "--disable_extensions", "--config_plugin=filesystem", "--config_path=/dev/null"}) {
			t.Fatal(p, a)
		}
		return CommandResult{Output: b}
	}}}).Run(context.Background(), requestFixture(), func(Result) {})
	if r.State != "complete" || r.Findings[0].Kind != "asset" || r.Findings[0].Severity != "info" {
		t.Fatal(r)
	}
	invalid, _ := json.Marshal([]map[string]string{{"pid": "1", "port": "70000", "address": "host"}})
	r = (Osquery{fakeExec{func(string, []string) CommandResult { return CommandResult{Output: invalid} }}}).Run(context.Background(), requestFixture(), func(Result) {})
	if r.State != "failed" {
		t.Fatal(r)
	}
}
func TestFalcoDoesNotClaimLiveCoverageOrLeakRawOutput(t *testing.T) {
	now := time.Now()
	makeEvent := func(at time.Time) []byte {
		b, _ := json.Marshal(map[string]string{"time": at.UTC().Format(time.RFC3339Nano), "rule": "Privilege escalation", "priority": "Critical", "output": "SECRET_ENV=do-not-display"})
		return b
	}
	r := parseFalco(makeEvent(now), now)
	if r.State != "partial" || r.FindingTotal != 1 || r.Findings[0].Kind != "behavior" || strings.Contains(r.Findings[0].Detail, "SECRET_ENV") {
		t.Fatal(r)
	}
	if r = parseFalco(makeEvent(now.Add(-time.Hour)), now); r.State != "unavailable" {
		t.Fatal("stale probe treated as healthy")
	}
	if r = parseFalco(makeEvent(now.Add(time.Hour)), now); r.State != "failed" {
		t.Fatal("future event accepted")
	}
}
func TestClamAVRejectsImpossibleCountsAndUnsafeEvidence(t *testing.T) {
	r := base("clamav", "complete", "完成")
	r.Total = 2
	r.Completed = 1
	if validResult(r) {
		t.Fatal("false completion")
	}
	r.State = "partial"
	if !validResult(r) {
		t.Fatal("partial report rejected")
	}
	r.FindingTotal = 1
	r.Findings = []Finding{{Kind: "vulnerability", Severity: "high", Target: "a", Rule: "x", Detail: "d"}}
	if validResult(r) {
		t.Fatal("CVE treated as malware")
	}
	r.Findings[0].Kind = "malware"
	r.Findings[0].Target = "a\nb"
	if validResult(r) {
		t.Fatal("control characters accepted")
	}
}
func TestStreamFragmentationAndOutputBudget(t *testing.T) {
	var rows []string
	cancelled := false
	w := lineWriter{consume: func(b []byte) error { rows = append(rows, string(b)); return nil }, cancel: func() { cancelled = true }}
	for _, s := range []string{"a", "b\ncd", "\n"} {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(rows, []string{"ab", "cd"}) {
		t.Fatal(rows)
	}
	if _, err := w.Write([]byte(strings.Repeat("x", 32769))); !errors.Is(err, ErrOutputLimit) || !cancelled {
		t.Fatal("oversized line did not cancel")
	}
	b := cappedBuffer{limit: 3, cancel: func() { cancelled = true }}
	cancelled = false
	if _, err := b.Write([]byte("1234")); !errors.Is(err, ErrOutputLimit) || b.b.Len() != 3 || !cancelled {
		t.Fatal("output budget failed")
	}
}

func TestMalformedLaterAssetsPreserveEarlierObservations(t *testing.T) {
	b, _ := json.Marshal([]map[string]string{{"pid": "42", "port": "443", "protocol": "6", "address": "0.0.0.0", "name": "caddy"}, {"pid": "1", "port": "70000", "address": "host"}})
	r := (Osquery{fakeExec{func(string, []string) CommandResult { return CommandResult{Output: b} }}}).Run(context.Background(), requestFixture(), func(Result) {})
	if r.State != "partial" || r.Completed != 1 || r.Total != 2 || r.FindingTotal != 1 || len(r.Findings) != 1 || r.EvidenceDigest == "" {
		t.Fatal(r)
	}
}
func TestMalformedLaterFalcoEventsPreserveBehaviorEvidence(t *testing.T) {
	now := time.Now()
	b, _ := json.Marshal(map[string]string{"time": now.UTC().Format(time.RFC3339Nano), "rule": "Privilege escalation", "priority": "Critical"})
	for _, suffix := range []string{"not-json", "{\"time\":\"invalid\",\"rule\":\"Later\"}"} {
		r := parseFalco(append(append([]byte{}, b...), []byte("\n"+suffix)...), now)
		if r.State != "partial" || r.FindingTotal != 1 || len(r.Findings) != 1 || r.EvidenceDigest == "" {
			t.Fatal(r)
		}
	}
}

func freshTrivyDB() EngineReadiness {
	return EngineReadiness{ID: "trivy", State: "ready", Detail: "test verified dependency"}
}
