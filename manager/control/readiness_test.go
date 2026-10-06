package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func metadataFixture(now time.Time) dbMetadata {
	return dbMetadata{Version: 2, UpdatedAt: now.Add(-time.Hour), DownloadedAt: now.Add(-30 * time.Minute), NextUpdate: now.Add(time.Hour)}
}
func TestTrivyMetadataRejectsMissingMalformedExpiredAndFutureData(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	good := metadataFixture(now)
	b, _ := json.Marshal(good)
	if r := parseTrivyMetadata(b, now); r.State != "ready" {
		t.Fatal(r)
	}
	cases := []struct {
		name, state string
		edit        func(*dbMetadata)
	}{
		{"old-format", "unavailable", func(m *dbMetadata) { m.Version = 1 }},
		{"missing-download", "unavailable", func(m *dbMetadata) { m.DownloadedAt = time.Time{} }},
		{"future", "unavailable", func(m *dbMetadata) { m.UpdatedAt = now.Add(time.Hour) }},
		{"download-before-publish", "unavailable", func(m *dbMetadata) { m.DownloadedAt = now.Add(-2 * time.Hour) }},
		{"unbounded-expiry", "unavailable", func(m *dbMetadata) { m.NextUpdate = now.Add(49 * time.Hour) }},
		{"expiry-before-publish", "unavailable", func(m *dbMetadata) { m.NextUpdate = m.UpdatedAt }},
		{"expired", "stale", func(m *dbMetadata) { m.NextUpdate = now }},
		{"old", "stale", func(m *dbMetadata) {
			m.UpdatedAt = now.Add(-49 * time.Hour)
			m.DownloadedAt = m.UpdatedAt
			m.NextUpdate = now.Add(-time.Hour)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := good
			c.edit(&m)
			b, _ := json.Marshal(m)
			if r := parseTrivyMetadata(b, now); r.State != c.state {
				t.Fatal(r)
			}
		})
	}
	for _, bad := range []string{string(b) + " {}", strings.Repeat(" ", 4097), "null", "{}", strings.TrimSuffix(string(b), "}") + ",\"unknown\":true}"} {
		if r := parseTrivyMetadata([]byte(bad), now); r.State != "unavailable" {
			t.Fatal("invalid metadata accepted", r)
		}
	}
}
func TestTrivyUnavailableDatabaseNeverInvokesScanner(t *testing.T) {
	for _, state := range []string{"unavailable", "stale"} {
		calls := 0
		f := fakeExec{call: func(string, []string) CommandResult { calls++; return CommandResult{} }}
		r := (Trivy{Exec: f, Database: func() EngineReadiness { return EngineReadiness{State: state, Detail: "DB not ready"} }}).Run(context.Background(), requestFixture(), func(Result) {})
		if r.State != "unavailable" || calls != 0 {
			t.Fatal(r, calls)
		}
	}
}
func TestTrivyExpiresBetweenImagesAndPreservesObservedResults(t *testing.T) {
	q := requestFixture()
	q.Images = append(q.Images, "sha256:"+strings.Repeat("b", 64))
	executions := 0
	f := fakeExec{call: func(string, []string) CommandResult {
		executions++
		b, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": q.Images[0], "Results": []any{}})
		return CommandResult{Output: b}
	}}
	calls := 0
	probe := func() EngineReadiness {
		calls++
		if calls >= 3 {
			return EngineReadiness{State: "stale"}
		}
		return EngineReadiness{State: "ready"}
	}
	r := (Trivy{Exec: f, Database: probe}).Run(context.Background(), q, func(Result) {})
	if r.State != "partial" || r.Completed != 1 || r.Total != 2 || executions != 1 || r.EvidenceDigest == "" {
		t.Fatal(r, calls)
	}
}
func TestVersionOutputIsBoundedAndCannotInjectDetail(t *testing.T) {
	if trivyVersion([]byte("Version: 0.65.0\n")) != "0.65.0" {
		t.Fatal("valid version rejected")
	}
	for _, s := range []string{"Version: $(shell)", "Version: 0.65.0 SECRET=token", strings.Repeat("x", 4097)} {
		if trivyVersion([]byte(s)) != "" {
			t.Fatal("unsafe version accepted")
		}
	}
}
