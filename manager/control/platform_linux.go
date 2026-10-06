//go:build linux

package control

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Open first and inspect the same descriptor used by the event reader.
func trustedOpen(path string, executable bool) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute trusted path required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return fail(errors.New("regular root-owned file required"))
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return fail(errors.New("untrusted root file"))
	}
	for p := filepath.Dir(resolved); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return fail(err)
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fail(errors.New("untrusted root path"))
		}
		if p == "/" {
			break
		}
	}
	if executable && st.Mode().Perm()&0111 == 0 {
		return fail(errors.New("engine not executable"))
	}
	return f, nil
}
func trustedPath(p string, executable bool) error {
	f, err := trustedOpen(p, executable)
	if err == nil {
		f.Close()
	}
	return err
}
func resolveExecutable(p string) (string, error) {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if err = trustedPath(resolved, true); err != nil {
		return "", err
	}
	return resolved, nil
}
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
}

// Data paths are walked with directory FDs. No component, including the leaf,
// may be a symlink; checking and opening use the same pinned ancestors.
func trustedDataOpen(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("canonical absolute data path required")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return nil, errors.New("invalid data path")
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, e := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st syscall.Stat_t
		if e = syscall.Fstat(fd, &st); e != nil || st.Uid != 0 || st.Mode&0022 != 0 || (i == len(parts)-1 && st.Mode&syscall.S_IFMT != syscall.S_IFREG) || (i < len(parts)-1 && st.Mode&syscall.S_IFMT != syscall.S_IFDIR) {
			syscall.Close(fd)
			return nil, errors.New("root controlled data path required")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
