// Copyright 2023 The Shac Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reporting

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"go.fuchsia.dev/shac-project/shac/internal/engine"
)

// Get returns the right reporting implementation based on the current
// environment.
func Get() engine.Report {
	// On LUCI/Swarming. ResultDB!
	if os.Getenv("SWARMING_TASK_ID") != "" {
		// TODO(maruel): Emits LUCI_CONTEXT.
		return &basic{out: os.Stdout}
	}

	// On GitHub Actions.
	if os.Getenv("GITHUB_RUN_ID") != "" {
		// Emits GitHub Workflows commands.
		return &github{out: os.Stdout}
	}

	// Active terminal. Colors! This includes VSCode's integrated terminal.
	if os.Getenv("TERM") != "dumb" && isatty.IsTerminal(os.Stderr.Fd()) {
		return &interactive{
			out: colorable.NewColorableStdout(),
		}
	}

	// VSCode extension.
	if os.Getenv("VSCODE_GIT_IPC_HANDLE") != "" {
		// TODO(maruel): Return SARIF.
		return &basic{out: os.Stdout}
	}

	// Anything else, e.g. redirected output.
	return &basic{out: os.Stdout}
}

type basic struct {
	out io.Writer
}

func (b *basic) EmitAnnotation(ctx context.Context, check, level, message, file string, s engine.Span, replacements []string) error {
	// TODO(maruel): Do not drop span and replacements!
	_, err := fmt.Fprintf(b.out, "[%s/%s] %s(%d): %s\n", check, level, file, s.Start.Line, message)
	return err
}

func (b *basic) Print(ctx context.Context, file string, line int, message string) {
	fmt.Fprintf(b.out, "[%s:%d] %s\n", file, line, message)
}

// github is the Report implementation when running inside a GitHub Actions
// Workflow.
//
// See https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
type github struct {
	out io.Writer
}

func (g *github) EmitAnnotation(ctx context.Context, check, level, message, file string, s engine.Span, replacements []string) error {
	// TODO(maruel): Do not drop replacements!
	_, err := fmt.Fprintf(g.out, "::%s ::file=%s,line=%d,col=%d,endLine=%d,endCol=%d,title=%s::%s\n",
		level, file, s.Start.Line, s.Start.Col, s.End.Line, s.End.Col, check, message)
	return err
}

func (g *github) Print(ctx context.Context, file string, line int, message string) {
	// Use debug here instead of notice since the file/line reference comes from
	// starlark, which will likely not be in the delta or even in your source
	// tree for load()'ed packages. This means GitHub may not be able to
	// reference it anyway.
	fmt.Fprintf(g.out, "::debug::[%s:%d] %s\n", file, line, message)
}

type interactive struct {
	out io.Writer
}

func (i *interactive) EmitAnnotation(ctx context.Context, check, level, message, file string, s engine.Span, replacements []string) error {
	// TODO(maruel): Do not drop span and replacements!
	l := ""
	switch level {
	case "notice":
		l = fgGreen.String() + "Notice"
	case "warning":
		l = fgYellow.String() + "Warning"
	case "error":
		l = fgRed.String() + "Error"
	}
	_, err := fmt.Fprintf(i.out, "%s[%s%s%s/%s%s] %s(%d): %s\n", reset, fgHiCyan, check, reset, l, reset, file, s.Start.Line, message)
	return err
}

func (i *interactive) Print(ctx context.Context, file string, line int, message string) {
	fmt.Fprintf(i.out, "%s[%s%s:%d%s] %s%s%s\n", reset, fgHiBlue, file, line, reset, bold, message, reset)
}
