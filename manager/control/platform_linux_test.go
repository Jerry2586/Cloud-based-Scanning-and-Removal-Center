//go:build linux

package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func rootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root to verify host trust boundary")
	}
	dir, err := os.MkdirTemp("/root", "ironcurtain-manager-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func TestTrustedFileRejectsWritableAncestorsAndNonRegularFiles(t *testing.T) {
	dir := rootFixture(t)
	file := filepath.Join(dir, "engine")
	if err := os.WriteFile(file, []byte("fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := trustedPath(file, true); err != nil {
		t.Fatal(err)
	}
	os.Chmod(file, 0777)
	if trustedPath(file, true) == nil {
		t.Fatal("accepted writable executable")
	}
	os.Chmod(file, 0755)
	os.Chmod(dir, 0777)
	if trustedPath(file, false) == nil {
		t.Fatal("accepted writable ancestor")
	}
	os.Chmod(dir, 0700)
	if trustedPath(dir, false) == nil {
		t.Fatal("accepted directory as report")
	}
	link := filepath.Join(dir, "engine-link")
	os.Symlink(file, link)
	f, err := trustedOpen(link, true)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Remove(link)
	os.Symlink("/dev/null", link)
	b := make([]byte, 7)
	if _, err = f.Read(b); err != nil || string(b) != "fixture" {
		t.Fatal("open descriptor changed with link", err)
	}
	if trustedPath(link, false) == nil {
		t.Fatal("accepted device")
	}
}

type interruptedStream struct{}

func (interruptedStream) Execute(context.Context, string, []string) CommandResult {
	return CommandResult{Code: -1}
}
func (interruptedStream) ExecuteStream(_ context.Context, _ string, args []string, consume func([]byte) error) CommandResult {
	if len(args) != 6 || args[0] != "-I" || args[5] != requestFixture().JobID {
		return CommandResult{Code: -1, Err: errors.New("bad worker args")}
	}
	r := base("clamav", "running", "observed")
	r.Total = 2
	r.Completed = 1
	r.FindingTotal = 1
	r.Findings = []Finding{{Kind: "malware", Severity: "high", Target: "/site/test", Rule: "EICAR", Detail: "fixture"}}
	b, _ := json.Marshal(r)
	consume(b)
	return CommandResult{Code: 9, Err: errors.New("worker interrupted")}
}
func TestClamAVInterruptedWorkerKeepsPreviouslyObservedEvidence(t *testing.T) {
	dir := rootFixture(t)
	q := requestFixture()
	q.ProfileFile = filepath.Join(dir, "profile.json")
	q.WorkerFile = filepath.Join(dir, "worker.py")
	os.WriteFile(q.ProfileFile, []byte("{}"), 0600)
	os.WriteFile(q.WorkerFile, []byte("# fixture"), 0600)
	r := (ClamAV{interruptedStream{}}).Run(context.Background(), q, func(Result) {})
	if r.State != "partial" || r.FindingTotal != 1 || len(r.Findings) != 1 || r.Completed != 1 {
		t.Fatal(r)
	}
}
func TestCancellationKillsEngineProcessGroup(t *testing.T) {
	rootFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	c := (RuntimeExecutor{}).Execute(ctx, "/bin/sh", []string{"-c", "sleep 30 & echo $!; wait"})
	if c.Err == nil {
		t.Fatal("timeout not reported")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(c.Output)))
	if err != nil {
		t.Fatal("missing child pid", err)
	}
	// A killed adopted child may briefly remain a zombie; it must never execute.
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err == nil && !strings.Contains(string(stat), ") Z ") && !strings.Contains(string(stat), ") X ") {
		t.Fatal("child still running", string(stat))
	}
}

func TestTrustedDataRejectsLinksAndWritableComponents(t *testing.T) {
	dir := rootFixture(t)
	file := filepath.Join(dir, "metadata.json")
	os.WriteFile(file, []byte("fixed"), 0600)
	f, err := trustedDataOpen(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	link := filepath.Join(dir, "link")
	os.Symlink(file, link)
	if x, err := trustedDataOpen(link); err == nil {
		x.Close()
		t.Fatal("leaf symlink accepted")
	}
	parent := dir + "-link"
	os.Symlink(dir, parent)
	t.Cleanup(func() { os.Remove(parent) })
	if x, err := trustedDataOpen(filepath.Join(parent, "metadata.json")); err == nil {
		x.Close()
		t.Fatal("parent symlink accepted")
	}
	os.Chmod(file, 0666)
	if x, err := trustedDataOpen(file); err == nil {
		x.Close()
		t.Fatal("writable data accepted")
	}
	os.Chmod(file, 0600)
	os.Chmod(dir, 0777)
	if x, err := trustedDataOpen(file); err == nil {
		x.Close()
		t.Fatal("writable parent accepted")
	}
	os.Chmod(dir, 0700)
	if x, err := trustedDataOpen(dir); err == nil {
		x.Close()
		t.Fatal("directory as data accepted")
	}
	os.Remove(file)
	os.Symlink("/dev/null", file)
	b := make([]byte, 5)
	if _, err = f.Read(b); err != nil || string(b) != "fixed" {
		t.Fatal("opened descriptor changed", err)
	}
}
