package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testEngine struct {
	id  string
	run func(context.Context, Request, func(Result)) Result
}

func (e testEngine) ID() string                                              { return e.id }
func (e testEngine) Run(c context.Context, q Request, p func(Result)) Result { return e.run(c, q, p) }
func requestFixture() Request {
	return Request{JobID: strings.Repeat("a", 64), ProfileDigest: strings.Repeat("b", 64), ProfileFile: "/etc/ironcurtain/local/profile.json", StateDir: "/var/lib/ironcurtain/local", WorkerFile: "/opt/ironcurtain/local/current/src/host/clamav-worker.py", Images: []string{"sha256:" + strings.Repeat("c", 64)}, DiscoveryComplete: true}
}
func TestDecodeRejectsUnmanagedTargets(t *testing.T) {
	q := requestFixture()
	b, _ := json.Marshal(q)
	if _, err := DecodeRequest(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(b) + "{}", strings.Replace(string(b), "/var/lib/ironcurtain/local", "/var/../etc", 1), strings.Replace(string(b), "sha256:", "latest:", 1), strings.TrimSuffix(string(b), "}") + ",\"shell\":\"sh\"}", strings.Repeat(" ", 32769)} {
		if _, err := DecodeRequest(strings.NewReader(bad)); err == nil {
			t.Fatal("accepted uncontrolled request")
		}
	}
	q.Images = append(q.Images, q.Images[0])
	b, _ = json.Marshal(q)
	if _, err := DecodeRequest(strings.NewReader(string(b))); err == nil {
		t.Fatal("duplicate image accepted")
	}
}
func TestSchedulerConcurrencyAndAtomicSnapshots(t *testing.T) {
	var active, maxActive atomic.Int32
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	engines := []Engine{}
	for _, id := range IDs {
		id := id
		engines = append(engines, testEngine{id, func(ctx context.Context, q Request, p func(Result)) Result {
			n := active.Add(1)
			defer active.Add(-1)
			for {
				m := maxActive.Load()
				if n <= m || maxActive.CompareAndSwap(m, n) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			r := base(id, "complete", "完成")
			r.Completed = 1
			r.Total = 1
			p(r)
			return r
		}})
	}
	var reports []Job
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), requestFixture(), engines, func(j Job) error { reports = append(reports, j); return nil })
	}()
	for n := 0; n < 2; n++ {
		select {
		case <-started:
		case <-time.After(time.Second * 3):
			t.Fatal("engines did not start")
		}
	}
	if active.Load() != 2 {
		t.Fatal("concurrency not bounded to two")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maxActive.Load() != 2 {
		t.Fatal("too many concurrent engines")
	}
	for _, j := range reports {
		count, coverage := 0, 0
		for _, r := range j.Engines {
			if terminal(r.State) {
				count++
			}
			if r.State == "complete" {
				coverage++
			}
		}
		if j.Completed != count || j.Coverage != coverage {
			t.Fatal("non-atomic terminal counters")
		}
	}
	final := reports[len(reports)-1]
	if final.State != "finished" || final.Completed != 4 || final.Coverage != 4 {
		t.Fatal(final)
	}
	if reports[0].Engines[0].State != "queued" {
		t.Fatal("snapshot mutated after delivery")
	}
}
func TestPartialFailureAndCancelPreserveFindings(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		engines := []Engine{}
		for _, id := range IDs {
			id := id
			engines = append(engines, testEngine{id, func(ctx context.Context, q Request, p func(Result)) Result {
				r := base(id, "partial", "部分证据")
				r.FindingTotal = 1
				r.Findings = []Finding{{Kind: "asset", Severity: "info", Target: "host", Rule: "test", Detail: "证据"}}
				return r
			}})
		}
		var last Job
		var once sync.Once
		if err := Run(ctx, requestFixture(), engines, func(j Job) error {
			last = j
			if cancelled && j.Completed > 0 {
				once.Do(cancel)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		cancel()
		expected := "partial"
		if cancelled {
			expected = "cancelled"
		}
		observed := 0
		for _, r := range last.Engines {
			observed += len(r.Findings)
		}
		if last.State != expected || last.Coverage != 0 || last.Completed != 4 || observed == 0 {
			t.Fatal(last)
		}
	}
}
func TestPublishFailureStopsDelivery(t *testing.T) {
	want := errors.New("sink closed")
	calls := 0
	err := Run(context.Background(), requestFixture(), nil, func(Job) error { calls++; return want })
	if !errors.Is(err, want) || calls != 1 {
		t.Fatal(err, calls)
	}
}
func TestLargeResultsStayBoundedAndTerminalImmutable(t *testing.T) {
	engines := []Engine{}
	for _, id := range IDs {
		id := id
		engines = append(engines, testEngine{id, func(context.Context, Request, func(Result)) Result {
			r := base(id, "complete", strings.Repeat("界", 180))
			r.Total = 20
			r.Completed = 20
			r.FindingTotal = 20
			r.EvidenceDigest = strings.Repeat("e", 64)
			for n := 0; n < 16; n++ {
				r.Findings = append(r.Findings, Finding{Kind: "malware", Severity: "high", Target: strings.Repeat("界", 256), Rule: strings.Repeat("界", 160), Detail: strings.Repeat("界", 180)})
			}
			return r
		}})
	}
	terminalBytes := map[string]string{}
	if err := Run(context.Background(), requestFixture(), engines, func(j Job) error {
		b, _ := json.Marshal(j)
		if len(b) > 60000 {
			t.Fatalf("report exceeds bridge: %d", len(b))
		}
		for _, r := range j.Engines {
			if !terminal(r.State) {
				continue
			}
			b, _ := json.Marshal(r)
			if old, ok := terminalBytes[r.ID]; ok && old != string(b) {
				t.Fatal("terminal evidence changed")
			}
			terminalBytes[r.ID] = string(b)
			if r.FindingTotal != 20 || r.EvidenceDigest != strings.Repeat("e", 64) {
				t.Fatal("full report identity lost")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
