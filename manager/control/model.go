package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
)

const Schema = "ironcurtain-multi-engine/v1"
const MaxFindings = 16

var IDs = []string{"clamav", "trivy", "osquery", "falco"}
var hexID = regexp.MustCompile("^[a-f0-9]{64}$")
var imageID = regexp.MustCompile("^sha256:[a-f0-9]{64}$")

type Request struct {
	JobID             string   `json:"job_id"`
	ProfileDigest     string   `json:"profile_digest"`
	ProfileFile       string   `json:"profile_file"`
	StateDir          string   `json:"state_dir"`
	WorkerFile        string   `json:"worker_file"`
	Images            []string `json:"images"`
	DiscoveryComplete bool     `json:"discovery_complete"`
}

func DecodeRequest(r io.Reader) (Request, error) {
	var q Request
	data, err := io.ReadAll(io.LimitReader(r, 32769))
	if err != nil || len(data) > 32768 {
		return q, errors.New("request exceeds limit")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err = d.Decode(&q); err != nil {
		return q, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return q, errors.New("trailing input")
	}
	if !hexID.MatchString(q.JobID) || !hexID.MatchString(q.ProfileDigest) || len(q.Images) > 32 {
		return q, errors.New("invalid task identity")
	}
	for _, p := range []string{q.ProfileFile, q.StateDir, q.WorkerFile} {
		if !path.IsAbs(p) || path.Clean(p) != p || len(p) > 1024 || strings.ContainsAny(p, "\x00\r\n") {
			return q, errors.New("invalid managed path")
		}
	}
	seen := map[string]bool{}
	for _, p := range q.Images {
		if !imageID.MatchString(p) || seen[p] {
			return q, errors.New("invalid image target")
		}
		seen[p] = true
	}
	return q, nil
}

type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Rule     string `json:"rule"`
	Detail   string `json:"detail"`
}
type Result struct {
	ID             string    `json:"id"`
	State          string    `json:"state"`
	Detail         string    `json:"detail"`
	Completed      int       `json:"completed"`
	Total          int       `json:"total"`
	FindingTotal   int       `json:"finding_total"`
	Findings       []Finding `json:"findings"`
	EvidenceDigest string    `json:"evidence_digest,omitempty"`
}
type Job struct {
	Schema        string   `json:"schema"`
	JobID         string   `json:"job_id"`
	ProfileDigest string   `json:"profile_digest"`
	State         string   `json:"state"`
	StartedAt     string   `json:"started_at"`
	UpdatedAt     string   `json:"updated_at"`
	FinishedAt    string   `json:"finished_at,omitempty"`
	Completed     int      `json:"completed"`
	Total         int      `json:"total"`
	Coverage      int      `json:"coverage"`
	Engines       []Result `json:"engines"`
}

// Engine adapters are read-only detectors. Remediation is a separate capability.
type Engine interface {
	ID() string
	Run(context.Context, Request, func(Result)) Result
}
type CommandResult struct {
	Code   int
	Output []byte
	Err    error
}
type Executor interface {
	Execute(context.Context, string, []string) CommandResult
}

func stamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }
func text(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func base(id, state, detail string) Result {
	return Result{ID: id, State: state, Detail: detail, Findings: []Finding{}}
}

func safeText(s string, n int) bool {
	if len([]rune(s)) > n {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// Bound each engine independently so terminal evidence remains stable when
// other engines publish later; counts and digest always refer to the full report.
func displayResult(r Result) Result {
	r.Findings = append([]Finding{}, r.Findings...)
	for {
		b, err := json.Marshal(r)
		if err == nil && len(b) <= 12000 {
			return r
		}
		if len(r.Findings) == 0 {
			return base(r.ID, "failed", "引擎报告超过展示预算")
		}
		r.Findings = r.Findings[:len(r.Findings)-1]
	}
}
