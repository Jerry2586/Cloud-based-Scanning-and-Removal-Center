package control

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
)

const trivyCache = "/var/lib/ironcurtain/local/trivy-cache/db/"
const readinessSchema = "ironcurtain-engine-readiness/v1"

type EngineReadiness struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Detail     string `json:"detail"`
	Version    string `json:"version,omitempty"`
	DatabaseAt string `json:"database_at,omitempty"`
	NextUpdate string `json:"next_update,omitempty"`
}
type ReadinessReport struct {
	Schema    string            `json:"schema"`
	CheckedAt string            `json:"checked_at"`
	Engines   []EngineReadiness `json:"engines"`
}
type dbMetadata struct {
	Version                             int
	UpdatedAt, NextUpdate, DownloadedAt time.Time
}

// Freshness is a local policy. It is not an authentication of DB publisher identity.
func parseTrivyMetadata(b []byte, now time.Time) EngineReadiness {
	r := EngineReadiness{ID: "trivy", State: "unavailable", Detail: "漏洞库元数据无效；在可信终端修复本机缓存"}
	if len(b) > 4096 {
		return r
	}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	var m dbMetadata
	if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF || m.Version != 2 || m.UpdatedAt.IsZero() || m.NextUpdate.IsZero() || m.DownloadedAt.IsZero() {
		return r
	}
	if m.UpdatedAt.After(now.Add(5*time.Minute)) || m.DownloadedAt.After(now.Add(5*time.Minute)) || m.DownloadedAt.Before(m.UpdatedAt.Add(-5*time.Minute)) || !m.NextUpdate.After(m.UpdatedAt) || m.NextUpdate.Sub(m.UpdatedAt) > 48*time.Hour {
		return r
	}
	r.DatabaseAt = m.UpdatedAt.UTC().Format(time.RFC3339Nano)
	r.NextUpdate = m.NextUpdate.UTC().Format(time.RFC3339Nano)
	if !now.Before(m.NextUpdate) || now.Sub(m.UpdatedAt) > 48*time.Hour || now.Sub(m.DownloadedAt) > 48*time.Hour {
		r.State = "stale"
		r.Detail = "漏洞库已到更新期限；本次镜像扫描暂停，需维护本机 Trivy 缓存"
		return r
	}
	r.State = "ready"
	r.Detail = "本机漏洞库在有效期内；数据库来源仍由主机管理员负责"
	return r
}
func checkTrivyDatabase() EngineReadiness {
	r := EngineReadiness{ID: "trivy", State: "unavailable", Detail: "可信本机漏洞库缺失或权限不安全；请在 Linux 终端维护 Trivy"}
	meta, err := trustedDataOpen(trivyCache + "metadata.json")
	if err != nil {
		return r
	}
	defer meta.Close()
	b, err := io.ReadAll(io.LimitReader(meta, 4097))
	if err != nil {
		return r
	}
	r = parseTrivyMetadata(b, time.Now())
	if r.State != "ready" {
		return r
	}
	db, err := trustedDataOpen(trivyCache + "trivy.db")
	if err != nil {
		r.State = "unavailable"
		r.Detail = "漏洞数据库缺失或权限不安全"
		return r
	}
	defer db.Close()
	header := make([]byte, 16)
	if _, err = io.ReadFull(db, header); err != nil || string(header) != "SQLite format 3\x00" {
		r.State = "unavailable"
		r.Detail = "本机漏洞数据库格式无效"
	}
	return r
}

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)

func trivyVersion(b []byte) string {
	if len(b) > 4096 {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Version: ") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
			if len(v) <= 64 && versionPattern.MatchString(v) {
				return v
			}
		}
	}
	return ""
}
func Readiness(ctx context.Context, executor Executor) ReadinessReport {
	report := ReadinessReport{Schema: readinessSchema, Engines: []EngineReadiness{}}
	trivy := checkTrivyDatabase()
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	c := executor.Execute(short, "/usr/local/bin/trivy", []string{"--config", "/dev/null", "--cache-dir", "/var/lib/ironcurtain/local/trivy-cache", "--version"})
	cancel()
	trivy.Version = trivyVersion(c.Output)
	if c.Err != nil || c.Code != 0 || trivy.Version == "" {
		trivy.State = "unavailable"
		trivy.Detail = "Trivy 程序未安装、执行失败或版本输出无法核验"
	}
	report.Engines = append(report.Engines, trivy)
	osquery := EngineReadiness{ID: "osquery", State: "unavailable", Detail: "Osquery 未安装或固定资产查询无法执行"}
	short, cancel = context.WithTimeout(ctx, 5*time.Second)
	c = executor.Execute(short, "/usr/bin/osqueryi", []string{"--json", "--disable_extensions", "--config_plugin=filesystem", "--config_path=/dev/null", "SELECT version FROM osquery_info;"})
	cancel()
	var rows []struct {
		Version string `json:"version"`
	}
	if c.Err == nil && c.Code == 0 && len(c.Output) <= 4096 && json.Unmarshal(c.Output, &rows) == nil && len(rows) == 1 && len(rows[0].Version) <= 64 && versionPattern.MatchString(rows[0].Version) {
		osquery.State = "ready"
		osquery.Version = rows[0].Version
		osquery.Detail = "固定资产查询可用；监听端口白名单与风险判定另行核验"
	}
	report.Engines = append(report.Engines, osquery)
	falco := (Falco{Path: "/var/log/falco/ironcurtain-events.jsonl"}).Run(ctx, Request{}, func(Result) {})
	state := "unavailable"
	if falco.State == "partial" {
		state = "partial"
	}
	report.Engines = append(report.Engines, EngineReadiness{ID: "falco", State: state, Detail: falco.Detail})
	report.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return report
}
