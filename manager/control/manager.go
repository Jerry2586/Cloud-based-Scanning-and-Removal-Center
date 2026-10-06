package control

import (
	"context"
	"sync"
)

// Run emits immutable snapshots. Terminal counters and engine states change
// together; delivery failure cancels pending and active work.
func Run(parent context.Context, q Request, engines []Engine, publish func(Job) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	j := Job{Schema: Schema, JobID: q.JobID, ProfileDigest: q.ProfileDigest, State: "running", StartedAt: stamp(), Total: len(engines), Engines: []Result{}}
	for _, e := range engines {
		j.Engines = append(j.Engines, base(e.ID(), "queued", "等待执行"))
	}
	var mu sync.Mutex
	var first error
	emit := func() {
		j.UpdatedAt = stamp()
		if first == nil {
			if err := publish(clone(j)); err != nil {
				first = err
				cancel()
			}
		}
	}
	emit()
	if first != nil {
		return first
	}
	slots := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for i, e := range engines {
		wg.Add(1)
		go func(i int, e Engine) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				j.Engines[i] = base(e.ID(), "cancelled", "任务已取消或超时")
				j.Completed++
				emit()
				mu.Unlock()
				return
			}
			defer func() { <-slots }()
			update := func(r Result) {
				// Adapters may emit their final sample before returning it. The scheduler
				// commits terminal states exactly once, together with completion counts.
				if terminal(r.State) {
					return
				}
				r.ID = e.ID()
				mu.Lock()
				j.Engines[i] = displayResult(r)
				emit()
				mu.Unlock()
			}
			update(base(e.ID(), "running", "正在读取本机证据"))
			r := e.Run(ctx, q, update)
			r.ID = e.ID()
			if !terminal(r.State) {
				r = base(e.ID(), "failed", "引擎未返回结束报告")
			}
			if ctx.Err() != nil {
				r.State = "cancelled"
				r.Detail = "任务已取消或超时；保留已读取证据"
			}
			mu.Lock()
			j.Engines[i] = displayResult(r)
			j.Completed++
			if r.State == "complete" {
				j.Coverage++
			}
			emit()
			mu.Unlock()
		}(i, e)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	j.State = "finished"
	if j.Coverage != j.Total {
		j.State = "partial"
	}
	if ctx.Err() != nil {
		j.State = "cancelled"
	}
	j.FinishedAt = stamp()
	emit()
	return first
}
func clone(j Job) Job {
	j.Engines = append([]Result{}, j.Engines...)
	for i := range j.Engines {
		j.Engines[i].Findings = append([]Finding{}, j.Engines[i].Findings...)
	}
	return j
}
