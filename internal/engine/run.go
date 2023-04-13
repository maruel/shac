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

package engine

//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0
//go:generate protoc --go_out=. --go_opt=paths=source_relative shac.proto

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.chromium.org/luci/starlark/interpreter"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/prototext"
)

func init() {
	// Enable not-yet-standard Starlark features.
	resolve.AllowRecursion = true
	resolve.AllowSet = true
}

// Cursor represents a point in a content; generally a source file but it can
// also be a change description.
type Cursor struct {
	Line int
	Col  int

	// Require keyed arguments.
	_ struct{}
}

// Span represents a section in a source file or a change description.
type Span struct {
	// Start is the beginning of the span. If Col is specified, Line must be
	// specified.
	Start Cursor
	// End is the end of the span. If not specified, the span has only one line.
	// If Col is specified, Start.Col must be specified too. It is inclusive.
	// That is, it is impossible to do a 0 width span.
	End Cursor

	// Require keyed arguments.
	_ struct{}
}

// Level is one of "notice", "warning" or "error".
//
// A check is only considered failed if it emits at least one annotation with
// level "error".
type Level string

// Valid Level values.
const (
	Notice  Level = "notice"
	Warning Level = "warning"
	Error   Level = "error"
	Nothing Level = ""
)

func (l Level) isValid() bool {
	switch l {
	case Notice, Warning, Error:
		return true
	default:
		return false
	}
}

// Report exposes callbacks that the engine calls for everything generated by
// the starlark code.
type Report interface {
	// EmitAnnotation emits an annotation by a check for a specific file. This is
	// not a failure by itself, unless level "error" is used.
	EmitAnnotation(ctx context.Context, check string, level Level, message, root, file string, s Span, replacements []string) error
	// EmitArtifact emits an artifact by a check.
	//
	// Only one of root or content can be specified. If root is specified, it is
	// a file on disk. The file may disappear after this function is called. If
	// root is not specified, content is the artifact. Either way, file is the
	// display name of the artifact.
	EmitArtifact(ctx context.Context, check, root, file string, content []byte) error
	// CheckCompleted is called when a check is completed.
	//
	// It is called with the start time, wall clock duration, the highest level emitted and an error
	// if an abnormal error occurred.
	CheckCompleted(ctx context.Context, check string, start time.Time, d time.Duration, r Level, err error)
	// Print is called when print() starlark function is called.
	Print(ctx context.Context, file string, line int, message string)
}

// Options is the options for Run().
type Options struct {
	// Report gets all the emitted annotations and artifacts from the checks.
	//
	// This is the only required argument. It is recommended to use
	// reporting.Get() which returns the right implementation based on the
	// environment (CI, interactive, etc).
	Report Report
	// Root directory. Defaults to the current working directory.
	Root string
	// Main source file to run. Defaults to shac.star.
	Main string
	// Configuration file. Defaults to shac.textproto.
	Config string
	// AllFiles tells to consider all files as affected.
	AllFiles bool
	// Recurse tells the engine to run all Main files found in subdirectories.
	Recurse bool

	// Require keyed arguments.
	_ struct{}
}

// Run loads a main shac.star file from a root directory and runs it.
func Run(ctx context.Context, o *Options) error {
	root := o.Root
	if root == "" {
		root = "."
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	main := o.Main
	if main == "" {
		main = "shac.star"
	}
	if filepath.IsAbs(main) {
		return errors.New("main file must not be an absolute path")
	}
	config := o.Config
	if config == "" {
		config = "shac.textproto"
	}
	allowNetwork := false
	p := filepath.Join(root, config)
	var b []byte
	if b, err = os.ReadFile(p); err == nil {
		doc := Document{}
		if err = prototext.Unmarshal(b, &doc); err != nil {
			return err
		}
		if doc.MinShacVersion != "" {
			v := parseVersion(doc.MinShacVersion)
			if v == nil || len(v) > len(version) {
				return errors.New("invalid min_shac_version")
			}
			for i := range v {
				if v[i] > version[i] {
					return fmt.Errorf("unsupported min_shac_version %q, running %d.%d.%d", doc.MinShacVersion, version[0], version[1], version[2])
				}
				if v[i] < version[i] {
					break
				}
			}
		}
		allowNetwork = doc.AllowNetwork
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	scm, err := getSCM(ctx, root, o.AllFiles)
	if err != nil {
		return err
	}

	// Each found shac.star is run in its own interpreter for maximum
	// parallelism.
	shacStates := []*shacState{
		{
			code:         interpreter.FileSystemLoader(root),
			r:            o.Report,
			allowNetwork: allowNetwork,
			main:         main,
			root:         root,
			scm:          scm,
		},
	}

	if o.Recurse {
		// Discover all the main files via the SCM. This enables us to not walk
		// ignored files.
		files, err := scm.allFiles(ctx)
		if err != nil {
			return err
		}
		for i := range files {
			n := files[i].path
			if filepath.Base(n) == main {
				d := filepath.Dir(n)
				if d == "." {
					continue
				}
				nr := filepath.Join(root, d)
				shacStates = append(shacStates,
					&shacState{
						code:         interpreter.FileSystemLoader(nr),
						r:            o.Report,
						allowNetwork: allowNetwork,
						main:         main,
						root:         nr,
						scm:          &subdirSCM{s: scm, subdir: d + "/"},
					})
			}
		}
	}

	// Parse the starlark files.
	// TODO(maruel): Run in parallel.
	for _, s := range shacStates {
		if err := s.parseAndRun(ctx); err != nil {
			return err
		}
	}
	return nil
}

// shacState represents a parsing state of one shac.star.
type shacState struct {
	code         interpreter.Loader
	intr         *interpreter.Interpreter
	r            Report
	allowNetwork bool
	main         string
	// root is the root for this shac.star.
	root string
	// scm is a filtered view of runState.scm.
	scm scmCheckout
	// checks is the list of registered checks callbacks via
	// shac.register_check().
	//
	// Checks are added serially, so no lock is needed.
	//
	// Checks are executed sequentially after all Starlark code is loaded and not
	// mutated. They run checks and emit results (results and comments).
	checks []check

	// Set when fail() is called. This happens only during the first phase, thus
	// no mutex is needed.
	failErr *failure

	// Set when the first phase of starlark interpretation is complete. This
	// complete the serial part, after which execution becomes concurrent.
	doneLoading bool

	mu          sync.Mutex
	printCalled bool
}

// ctxShacState pulls out *runState from the context.
//
// Panics if not there.
func ctxShacState(ctx context.Context) *shacState {
	return ctx.Value(&shacStateCtxKey).(*shacState)
}

var shacStateCtxKey = "shac.shacState"

// parseAndRun parses and run a single shac.star file.
func (s *shacState) parseAndRun(ctx context.Context) error {
	ctx = context.WithValue(ctx, &shacStateCtxKey, s)
	if err := s.parse(ctx); err != nil {
		return err
	}
	if len(s.checks) == 0 && !s.printCalled {
		return errors.New("did you forget to call shac.register_check?")
	}
	// Last phase where checks are called.
	if err := s.callAllChecks(ctx); err != nil {
		return err
	}
	// If any check failed, return an error.
	for i := range s.checks {
		if s.checks[i].highestLevel == Error {
			return ErrCheckFailed
		}
	}
	return nil
}

// parse parses a single shac.star file.
func (s *shacState) parse(ctx context.Context) error {
	s.intr = &interpreter.Interpreter{
		Predeclared: getPredeclared(),
		Packages:    map[string]interpreter.Loader{interpreter.MainPkg: s.code},
		Logger: func(file string, line int, message string) {
			s.mu.Lock()
			s.printCalled = true
			s.mu.Unlock()
			s.r.Print(ctx, file, line, message)
		},
	}

	var err error
	if err = s.intr.Init(ctx); err == nil {
		_, err = s.intr.ExecModule(ctx, interpreter.MainPkg, s.main)
	}
	if err != nil {
		if s.failErr != nil {
			// We got a fail() call, use this instead.
			return s.failErr
		}
		var evalErr *starlark.EvalError
		if errors.As(err, &evalErr) {
			return &evalError{evalErr}
		}
		return err
	}
	s.doneLoading = true
	return nil
}

// callAllChecks calls all the checks.
//
// It creates a separate thread per check, limited by the number of CPU cores +
// 2. This permits to run them concurrently.
func (s *shacState) callAllChecks(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.NumCPU() + 2)
	args := starlark.Tuple{getCtx(s.root)}
	args.Freeze()
	for i := range s.checks {
		i := i
		eg.Go(func() error {
			start := time.Now()
			err := s.checks[i].call(ctx, s.intr, args)
			s.r.CheckCompleted(ctx, s.checks[i].name, start, time.Since(start), s.checks[i].highestLevel, err)
			return err
		})
	}
	return eg.Wait()
}

// check represents one check added via shac.register_check().
type check struct {
	cb           starlark.Callable
	name         string
	failErr      *failure // set when fail() is called from within the check, an abnormal failure.
	highestLevel Level    // highest level emitted by EmitAnnotation.
}

var checkCtxKey = "shac.check"

// ctxCheck pulls out *check from the context.
//
// Returns nil when not run inside a check.
func ctxCheck(ctx context.Context) *check {
	c, _ := ctx.Value(&checkCtxKey).(*check)
	return c
}

// call calls the check callback and returns an error if an abnormal error happened.
//
// A "normal" error will still have this function return nil.
func (c *check) call(ctx context.Context, intr *interpreter.Interpreter, args starlark.Tuple) error {
	ctx = context.WithValue(ctx, &checkCtxKey, c)
	th := intr.Thread(ctx)
	th.Name = c.name
	if r, err := starlark.Call(th, c.cb, args, nil); err != nil {
		if c.failErr != nil {
			// fail() was called, return this error since this is an abnormal failure.
			return c.failErr
		}
		var evalErr *starlark.EvalError
		if errors.As(err, &evalErr) {
			return &evalError{evalErr}
		}
	} else if r != starlark.None {
		return fmt.Errorf("check %q returned an object of type %s, expected None", c.name, r.Type())
	}
	return nil
}

func parseVersion(s string) []int {
	var out []int
	for _, x := range strings.Split(s, ".") {
		i, err := strconv.Atoi(x)
		if err != nil {
			return nil
		}
		out = append(out, i)
	}
	return out
}
