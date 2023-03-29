// Copyright 2023 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	flag "github.com/spf13/pflag"
)

type app struct {
	topLevelFlags *flag.FlagSet
	subcommands   []*flag.FlagSet
}

type subcommand interface {
	Name() string
	Description() string
	SetFlags(*flag.FlagSet)
	Execute(context.Context, *flag.FlagSet) error
}

func Main(args []string) error {
	ctx := context.Background()

	if len(args) < 2 {
		// TODO(maruel): Print help.
		return fmt.Errorf("subcommand required")
	}

	subcommands := []subcommand{
		&checkCmd{},
	}

	name := args[1]
	for _, s := range subcommands {
		if s.Name() != name {
			continue
		}
		fs := flag.NewFlagSet(s.Name(), flag.ContinueOnError)
		fs.Usage = func() {
			// fs.out() is inaccessible.
			fmt.Fprintf(os.Stderr, "Usage of shac %s:\n", s.Name())
			fs.PrintDefaults()
		}
		verbose := fs.BoolP("verbose", "v", false, "Verbose output")
		s.SetFlags(fs)
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if !*verbose {
			log.SetOutput(io.Discard)
		}
		return s.Execute(ctx, fs)
	}
	return fmt.Errorf("no such command %q", name)
}