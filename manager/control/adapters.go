package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

func evidence(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func commandFailure(id string, c CommandResult) Result {
	state := "failed"
	if c.Code == -1 {
		state = "unavailable"
	}
	return base(id, state, "引擎未安装、权限不足、数据未就绪或执行失败；请核对主机日志")
}
func add(r *Result, f Finding) {
	r.FindingTotal++
	if len(r.Findings) < MaxFindings {
		r.Findings = append(r.Findings, f)
	}
}

type ClamAV struct{ Exec Executor }

func (ClamAV) ID() string { return "clamav" }
func (e ClamAV) Run(ctx context.Context, q Request, progress func(Result)) Result {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if trustedPath(q.WorkerFile, false) != nil || trustedPath(q.ProfileFile, false) != nil {
		return base(e.ID(), "unavailable", "受保护扫描配置或桥接程序不可用")
	}
	var r Result
	seen := false
	consume := func(b []byte) error {
		var next Result
		if json.Unmarshal(b, &next) != nil || next.ID != "clamav" || !validResult(next) || seen && (terminal(r.State) || next.Completed < r.Completed || next.Total < r.Total || next.FindingTotal < r.FindingTotal) {
			return errors.New("invalid ClamAV bridge report")
		}
		r = next
		seen = true
		progress(r)
		return nil
	}
	args := []string{"-I", q.WorkerFile, q.ProfileFile, q.StateDir, q.ProfileDigest}
	var c CommandResult
	if s, ok := e.Exec.(StreamingExecutor); ok {
		c = s.ExecuteStream(ctx, "/usr/bin/python3", args, consume)
	} else {
		c = e.Exec.Execute(ctx, "/usr/bin/python3", args)
		if consume(c.Output) != nil {
			return base(e.ID(), "failed", "文件扫描报告无效")
		}
	}
	if c.Err != nil || c.Code != 0 || !seen || !terminal(r.State) {
		if seen {
			r.State = "partial"
			r.Detail = "文件扫描中断；已观测证据保留，剩余范围未核验"
			return r
		}
		return commandFailure(e.ID(), c)
	}
	return r
}
func validResult(r Result) bool {
	if r.Completed < 0 || r.State == "complete" && r.Completed != r.Total || r.Total < r.Completed || r.Total > 200000 || r.FindingTotal < len(r.Findings) || r.FindingTotal > 200000 || len(r.Findings) > MaxFindings || !safeText(r.Detail, 180) || r.EvidenceDigest != "" && !hexID.MatchString(r.EvidenceDigest) {
		return false
	}
	if !terminal(r.State) && r.State != "running" {
		return false
	}
	for _, f := range r.Findings {
		if f.Kind != "malware" || f.Severity != "high" || !safeText(f.Target, 256) || !safeText(f.Rule, 160) || !safeText(f.Detail, 180) {
			return false
		}
	}
	return true
}
func terminal(s string) bool {
	return s == "complete" || s == "partial" || s == "unavailable" || s == "failed" || s == "cancelled"
}

type Trivy struct {
	Exec     Executor
	Database func() EngineReadiness
}

func (Trivy) ID() string { return "trivy" }
func (e Trivy) Run(ctx context.Context, q Request, progress func(Result)) Result {
	if len(q.Images) == 0 {
		return base(e.ID(), "unavailable", "未发现可扫描镜像；不能据此判定容器安全")
	}
	probe := e.Database
	if probe == nil {
		probe = checkTrivyDatabase
	}
	if db := probe(); db.State != "ready" {
		return base(e.ID(), "unavailable", db.Detail)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	r := base(e.ID(), "running", "扫描本机不可变镜像 ID；仅检测漏洞")
	r.Total = len(q.Images)
	incomplete := !q.DiscoveryComplete
	var digests []string
	for _, image := range q.Images {
		if db := probe(); db.State != "ready" {
			incomplete = true
			break
		}
		if ctx.Err() != nil {
			incomplete = true
			break
		}
		c := e.Exec.Execute(ctx, "/usr/local/bin/trivy", []string{"image", "--config", "/dev/null", "--ignorefile", "/dev/null", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--image-src", "docker", "--scanners", "vuln", "--format", "json", "--timeout", "90s", "--cache-dir", "/var/lib/ironcurtain/local/trivy-cache", "--docker-host", "unix:///var/run/docker.sock", "--disable-telemetry", "--skip-version-check", image})
		if c.Err != nil || c.Code != 0 {
			if c.Code == -1 && r.Completed == 0 {
				return commandFailure(e.ID(), c)
			}
			incomplete = true
			r.Detail = "部分镜像扫描失败；核对 Trivy 和本机漏洞库"
			progress(r)
			continue
		}
		var report struct {
			SchemaVersion int
			ArtifactName  string
			Results       []struct {
				Target          string
				Vulnerabilities []struct {
					VulnerabilityID  string
					PkgName          string
					InstalledVersion string
					FixedVersion     string
					Severity         string
				}
			}
		}
		if json.Unmarshal(c.Output, &report) != nil || report.SchemaVersion != 2 || report.ArtifactName != image || report.Results == nil {
			incomplete = true
			continue
		}
		for _, target := range report.Results {
			for _, v := range target.Vulnerabilities {
				if v.VulnerabilityID == "" {
					incomplete = true
					continue
				}
				severity := "info"
				switch v.Severity {
				case "CRITICAL":
					severity = "critical"
				case "HIGH":
					severity = "high"
				case "MEDIUM":
					severity = "medium"
				case "LOW":
					severity = "low"
				}
				add(&r, Finding{Kind: "vulnerability", Severity: severity, Target: text(image, 256), Rule: text(v.VulnerabilityID, 160), Detail: text(v.PkgName+" "+v.InstalledVersion+" → "+v.FixedVersion, 180)})
			}
		}
		digests = append(digests, evidence(c.Output))
		r.Completed++
		progress(r)
	}
	b, _ := json.Marshal(digests)
	r.EvidenceDigest = evidence(b)
	r.State = "complete"
	r.Detail = "已检查本机镜像漏洞；运行时行为与文件病毒另行核验"
	if db := probe(); db.State != "ready" {
		incomplete = true
	}
	if incomplete || r.Completed != r.Total {
		r.State = "partial"
		r.Detail = "镜像漏洞扫描有覆盖缺口；核对引擎、漏洞库及容器发现"
	}
	return r
}

type Osquery struct{ Exec Executor }

func (Osquery) ID() string { return "osquery" }

const portSQL = "SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name FROM listening_ports AS lp LEFT JOIN processes AS p ON lp.pid=p.pid LIMIT 513;"

func (e Osquery) Run(ctx context.Context, q Request, _ func(Result)) Result {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c := e.Exec.Execute(ctx, "/usr/bin/osqueryi", []string{"--json", "--disable_extensions", "--config_plugin=filesystem", "--config_path=/dev/null", portSQL})
	if c.Err != nil || c.Code != 0 {
		return commandFailure(e.ID(), c)
	}
	var rows []struct {
		PID      string `json:"pid"`
		Port     string `json:"port"`
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Name     string `json:"name"`
	}
	if json.Unmarshal(c.Output, &rows) != nil || rows == nil || len(rows) > 513 {
		return base(e.ID(), "failed", "端口资产报告无效")
	}
	r := base(e.ID(), "complete", "已读取监听端口与进程归属；未配置白名单时不判定后门")
	r.Total = len(rows)
	r.EvidenceDigest = evidence(c.Output)
	if len(rows) > 512 {
		r.State = "partial"
		r.Detail = "监听端口超出 512 项，资产覆盖不完整"
	}
	for _, p := range rows {
		port, err := strconv.Atoi(p.Port)
		pid, pe := strconv.Atoi(p.PID)
		if err != nil || pe != nil || port < 0 || port > 65535 || pid < 0 || p.Address == "" {
			r.State = "failed"
			if r.Completed > 0 {
				r.State = "partial"
			}
			r.Detail = "端口资产字段无效；保留之前观测，剩余资产未核验"
			return r
		}
		r.Completed++
		add(&r, Finding{Kind: "asset", Severity: "info", Target: text(p.Address+":"+p.Port, 256), Rule: "listening-port", Detail: text("pid="+p.PID+" "+p.Name+" protocol="+p.Protocol, 180)})
	}
	return r
}

type Falco struct{ Path string }

func (Falco) ID() string { return "falco" }
func (e Falco) Run(ctx context.Context, _ Request, _ func(Result)) Result {
	if ctx.Err() != nil {
		return base(e.ID(), "cancelled", "任务取消")
	}
	f, err := trustedOpen(e.Path, false)
	if err != nil {
		return base(e.ID(), "unavailable", "Falco 事件源不可读取")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > 1024*1024 {
		return base(e.ID(), "unavailable", "Falco 事件源超过读取预算，请配置轮转")
	}
	b := make([]byte, st.Size())
	if _, err = f.ReadAt(b, 0); err != nil && len(b) > 0 {
		return base(e.ID(), "failed", "Falco 事件源读取失败")
	}
	return parseFalco(b, time.Now())
}
func parseFalco(b []byte, now time.Time) Result {
	r := base("falco", "partial", "仅核验最近事件；无法单凭事件文件证明探针健康或持续防护")
	recent := 0
	r.EvidenceDigest = evidence(b)
	invalid := func(detail string) Result {
		r.State = "failed"
		if recent > 0 {
			r.State = "partial"
		}
		r.Total, r.Completed = recent, recent
		r.Detail = detail + "；保留之前观测，事件覆盖不完整"
		return r
	}
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var event struct {
			Time     string `json:"time"`
			Rule     string `json:"rule"`
			Priority string `json:"priority"`
			Output   string `json:"output"`
		}
		if json.Unmarshal(line, &event) != nil || event.Rule == "" {
			return invalid("Falco 事件格式无效")
		}
		t, err := time.Parse(time.RFC3339Nano, event.Time)
		if err != nil || t.After(now.Add(time.Minute)) {
			return invalid("Falco 事件时间无效")
		}
		if now.Sub(t) > 15*time.Minute {
			continue
		}
		recent++
		severity := "info"
		switch event.Priority {
		case "Emergency", "Alert", "Critical":
			severity = "critical"
		case "Error":
			severity = "high"
		case "Warning":
			severity = "medium"
		case "Notice":
			severity = "low"
		}
		add(&r, Finding{Kind: "behavior", Severity: severity, Target: "host", Rule: text(event.Rule, 160), Detail: "Falco 检测到行为事件；原始证据仅保存在本机"})
	}
	r.Total = recent
	r.Completed = recent
	r.EvidenceDigest = evidence(b)
	if recent == 0 {
		r.State = "unavailable"
		r.Detail = "最近 15 分钟无有效事件；探针健康未知"
	}
	return r
}
func splitLines(b []byte) [][]byte {
	var rows [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			rows = append(rows, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		rows = append(rows, b[start:])
	}
	return rows
}
func DefaultEngines() []Engine {
	e := RuntimeExecutor{}
	return []Engine{ClamAV{e}, Trivy{Exec: e}, Osquery{e}, Falco{Path: "/var/log/falco/ironcurtain-events.jsonl"}}
}
