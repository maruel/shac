// Copyright 2023 The Shac Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reporting

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"go.fuchsia.dev/shac-project/shac/internal/engine"
)

// Report is a closable engine.Report.
type Report interface {
	io.Closer
	engine.Report
}

// Get returns the right reporting implementation based on the current
// environment.
func Get(ctx context.Context) (Report, error) {
	// On LUCI/Swarming. ResultDB!
	if os.Getenv("LUCI_CONTEXT") != "" {
		l := &luci{basic: basic{out: os.Stdout}}
		if err := l.init(ctx); err != nil {
			return nil, err
		}
		return l, nil
	}

	// On GitHub Actions.
	if os.Getenv("GITHUB_RUN_ID") != "" {
		// Emits GitHub Workflows commands.
		return &github{out: os.Stdout}, nil
	}

	// Active terminal. Colors! This includes VSCode's integrated terminal.
	if os.Getenv("TERM") != "dumb" && isatty.IsTerminal(os.Stderr.Fd()) {
		return &interactive{
			out: colorable.NewColorableStdout(),
		}, nil
	}

	// VSCode extension.
	if os.Getenv("VSCODE_GIT_IPC_HANDLE") != "" {
		// TODO(maruel): Return SARIF.
		return &basic{out: os.Stdout}, nil
	}

	// Anything else, e.g. redirected output.
	return &basic{out: os.Stdout}, nil
}

type basic struct {
	out io.Writer
}

func (b *basic) Close() error {
	return nil
}

func (b *basic) EmitAnnotation(ctx context.Context, check string, level engine.Level, message, root, file string, s engine.Span, replacements []string) error {
	if file != "" {
		// TODO(maruel): Do not drop span and replacements!
		if s.Start.Line > 0 {
			_, err := fmt.Fprintf(b.out, "[%s/%s] %s(%d): %s\n", check, level, file, s.Start.Line, message)
			return err
		}
		_, err := fmt.Fprintf(b.out, "[%s/%s] %s: %s\n", check, level, file, message)
		return err
	}
	_, err := fmt.Fprintf(b.out, "[%s/%s] %s\n", check, level, message)
	return err
}

func (b *basic) EmitArtifact(ctx context.Context, check, root, file string, content []byte) error {
	return errors.New("not implemented")
}

func (b *basic) CheckCompleted(ctx context.Context, check string, start time.Time, d time.Duration, level engine.Level, err error) {
	l := string(level)
	if level == "" || level == engine.Notice {
		l = "Success"
	}
	if err != nil {
		fmt.Fprintf(b.out, "- %s (%s in %s): %s\n", check, l, d.Round(time.Millisecond), err)
	} else {
		fmt.Fprintf(b.out, "- %s (%s in %s)\n", check, l, d.Round(time.Millisecond))
	}
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

func (g *github) Close() error {
	return nil
}

func (g *github) EmitAnnotation(ctx context.Context, check string, level engine.Level, message, root, file string, s engine.Span, replacements []string) error {
	if file != "" {
		// TODO(maruel): Do not drop replacements!
		if s.Start.Line > 0 {
			if s.End.Line > 0 {
				if s.End.Col > 0 {
					_, err := fmt.Fprintf(g.out, "::%s ::file=%s,line=%d,col=%d,endLine=%d,endCol=%d,title=%s::%s\n",
						level, file, s.Start.Line, s.Start.Col, s.End.Line, s.End.Col, check, message)
					return err
				}
				_, err := fmt.Fprintf(g.out, "::%s ::file=%s,line=%d,endLine=%d,title=%s::%s\n",
					level, file, s.Start.Line, s.End.Line, check, message)
				return err
			}
			if s.Start.Col > 0 {
				_, err := fmt.Fprintf(g.out, "::%s ::file=%s,line=%d,col=%d,title=%s::%s\n",
					level, file, s.Start.Line, s.Start.Col, check, message)
				return err
			}
			_, err := fmt.Fprintf(g.out, "::%s ::file=%s,line=%d,title=%s::%s\n",
				level, file, s.Start.Line, check, message)
			return err
		}
		_, err := fmt.Fprintf(g.out, "::%s ::file=%stitle=%s::%s\n", level, file, check, message)
		return err
	}
	_, err := fmt.Fprintf(g.out, "::%s ::title=%s::%s\n", level, check, message)
	return err
}

func (g *github) EmitArtifact(ctx context.Context, check, root, file string, content []byte) error {
	return errors.New("not implemented")
}

func (g *github) CheckCompleted(ctx context.Context, check string, start time.Time, d time.Duration, l engine.Level, err error) {
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

func (i *interactive) Close() error {
	return nil
}

func (i *interactive) EmitAnnotation(ctx context.Context, check string, level engine.Level, message, root, file string, s engine.Span, replacements []string) error {
	c := levelColor[level]
	if file != "" {
		// TODO(maruel): Do not drop span and replacements!
		if s.Start.Line > 0 {
			_, err := fmt.Fprintf(i.out, "%s[%s%s%s/%s%s%s] %s(%d): %s\n", reset, fgHiCyan, check, reset, c, level, reset, file, s.Start.Line, message)
			return err
		}
		_, err := fmt.Fprintf(i.out, "%s[%s%s%s/%s%s%s] %s: %s\n", reset, fgHiCyan, check, reset, c, level, reset, file, message)
		return err
	}
	_, err := fmt.Fprintf(i.out, "%s[%s%s%s/%s%s%s] %s\n", reset, fgHiCyan, check, reset, c, level, reset, message)
	return err
}

func (i *interactive) EmitArtifact(ctx context.Context, root, check, file string, content []byte) error {
	return errors.New("not implemented")
}

func (i *interactive) CheckCompleted(ctx context.Context, check string, start time.Time, d time.Duration, level engine.Level, err error) {
	c := levelColor[level]
	l := string(level)
	if level == "" || level == engine.Notice {
		l = "Success"
	}
	if err != nil {
		fmt.Fprintf(i.out, "- %s%s%s%s (%s in %s): %s\n", reset, c, check, reset, l, d.Round(time.Millisecond), err)
	} else {
		fmt.Fprintf(i.out, "- %s%s%s%s (%s in %s)\n", reset, c, check, reset, l, d.Round(time.Millisecond))
	}
}

func (i *interactive) Print(ctx context.Context, file string, line int, message string) {
	fmt.Fprintf(i.out, "%s[%s%s:%d%s] %s%s%s\n", reset, fgHiBlue, file, line, reset, bold, message, reset)
}

var levelColor = map[engine.Level]ansiCode{
	engine.Notice:  fgGreen,
	engine.Warning: fgYellow,
	engine.Error:   fgRed,
	engine.Nothing: fgGreen,
}
