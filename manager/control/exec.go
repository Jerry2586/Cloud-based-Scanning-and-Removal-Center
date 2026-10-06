package control

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

const outputLimit = 4 * 1024 * 1024

var ErrOutputLimit = errors.New("engine output exceeds limit")

type cappedBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.b.Len()+n > b.limit {
		b.overflow = true
		if b.cancel != nil {
			b.cancel()
		}
		remaining := b.limit - b.b.Len()
		if remaining > 0 {
			b.b.Write(p[:remaining])
		}
		return n, ErrOutputLimit
	}
	return b.b.Write(p)
}

type lineWriter struct {
	pending []byte
	size    int
	consume func([]byte) error
	cancel  context.CancelFunc
	err     error
}

func (w *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	defer func() {
		if w.err != nil && w.cancel != nil {
			w.cancel()
		}
	}()
	w.size += n
	if w.size > outputLimit {
		w.err = ErrOutputLimit
		return n, w.err
	}
	w.pending = append(w.pending, p...)
	for {
		at := bytes.IndexByte(w.pending, '\n')
		if at < 0 {
			break
		}
		if at > 32768 {
			w.err = ErrOutputLimit
			return n, w.err
		}
		if err := w.consume(w.pending[:at]); err != nil {
			w.err = err
			return n, err
		}
		w.pending = append([]byte{}, w.pending[at+1:]...)
	}
	if len(w.pending) > 32768 {
		w.err = ErrOutputLimit
		return n, w.err
	}
	return n, nil
}

type RuntimeExecutor struct{}
type StreamingExecutor interface {
	ExecuteStream(context.Context, string, []string, func([]byte) error) CommandResult
}

func (RuntimeExecutor) Execute(ctx context.Context, path string, args []string) CommandResult {
	return execute(ctx, path, args, nil)
}
func (RuntimeExecutor) ExecuteStream(ctx context.Context, path string, args []string, consume func([]byte) error) CommandResult {
	return execute(ctx, path, args, consume)
}
func execute(ctx context.Context, path string, args []string, consume func([]byte) error) CommandResult {
	resolved, err := resolveExecutable(path)
	if err != nil {
		return CommandResult{Code: -1, Err: err}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/var/lib/ironcurtain/local"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	out := &cappedBuffer{limit: outputLimit, cancel: cancel}
	stderr := &cappedBuffer{limit: 32768, cancel: cancel}
	var lines *lineWriter
	if consume != nil {
		lines = &lineWriter{consume: consume, cancel: cancel}
		cmd.Stdout = lines
	} else {
		cmd.Stdout = out
	}
	cmd.Stderr = stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if out.overflow || stderr.overflow {
		err = ErrOutputLimit
	}
	if lines != nil && lines.err != nil {
		err = lines.err
	}
	if lines != nil && lines.err == nil && len(lines.pending) > 0 {
		err = errors.New("incomplete engine stream")
	}
	return CommandResult{Code: code, Output: out.b.Bytes(), Err: err}
}
