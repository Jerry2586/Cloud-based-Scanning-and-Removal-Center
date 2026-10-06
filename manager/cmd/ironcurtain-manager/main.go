package main

import (
	"context"
	"encoding/json"
	"fmt"
	"ironcurtain/manager/control"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--readiness" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if json.NewEncoder(os.Stdout).Encode(control.Readiness(ctx, control.RuntimeExecutor{})) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "manager accepts one bounded JSON request on stdin")
		os.Exit(2)
	}
	q, err := control.DecodeRequest(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid managed request")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 32*time.Minute)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	if err = control.Run(ctx, q, control.DefaultEngines(), func(j control.Job) error {
		b, err := json.Marshal(j)
		if err != nil {
			return err
		}
		if len(b) > 60000 {
			return fmt.Errorf("report exceeds delivery budget")
		}
		return encoder.Encode(j)
	}); err != nil {
		fmt.Fprintln(os.Stderr, "task report delivery failed")
		os.Exit(1)
	}
}
