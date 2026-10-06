//go:build !linux

package control

import (
	"errors"
	"os"
	"os/exec"
)

func trustedOpen(string, bool) (*os.File, error) { return nil, errors.New("Linux host required") }
func trustedPath(string, bool) error             { return errors.New("Linux host required") }
func resolveExecutable(string) (string, error)   { return "", errors.New("Linux host required") }
func configureProcess(*exec.Cmd)                 {}

func trustedDataOpen(string) (*os.File, error) { return nil, errors.New("Linux host required") }
