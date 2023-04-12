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
	Start Cursor
	End   Cursor

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
	// It returns the wallclock duration, the highest level emitted and an error
	// if an abnormal error occurred.
	CheckCompleted(ctx context.Context, check string, d time.Duration, r Level, err error)
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

	s := &state{
		inputs: &inputs{
			code:     interpreter.FileSystemLoader(root),
			root:     root,
			main:     main,
			allFiles: o.AllFiles,
		},
		r:            o.Report,
		allowNetwork: allowNetwork,
	}
	s.scm, err = getSCM(ctx, root)
	if err != nil {
		return err
	}

	// Parse the starlark file.
	ctx = context.WithValue(ctx, &stateCtxKey, s)
	if err = s.parse(ctx); err != nil {
		return err
	}
	if len(s.checks) == 0 && !s.printCalled {
		return errors.New("did you forget to call shac.register_check?")
	}
	// Last phase where checks are called.
	if err = s.callAllChecks(ctx); err != nil {
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

// inputs represents a starlark package.
type inputs struct {
	code     interpreter.Loader
	root     string
	main     string
	allFiles bool
}

// state represents the parsing and running state of an execution tree.
type state struct {
	inputs       *inputs
	r            Report
	scm          scmCheckout
	allowNetwork bool

	// TODO(maruel): There will be one shacState per shac.star found in
	// subdirectories.
	shacState
}

// ctxState pulls out *state from the context.
//
// Panics if not there.
func ctxState(ctx context.Context) *state {
	return ctx.Value(&stateCtxKey).(*state)
}

var stateCtxKey = "shac.state"

// parse parses a single shac.star file.
//
// TODO(maruel): Returns one new shacState for the input.
func (s *state) parse(ctx context.Context) error {
	s.intr = &interpreter.Interpreter{
		Predeclared: getPredeclared(),
		Packages: map[string]interpreter.Loader{
			interpreter.MainPkg: s.inputs.code,
		},
		Logger: func(file string, line int, message string) {
			s.mu.Lock()
			s.printCalled = true
			s.mu.Unlock()
			s.r.Print(ctx, file, line, message)
		},
	}

	var err error
	if err = s.intr.Init(ctx); err == nil {
		_, err = s.intr.ExecModule(ctx, interpreter.MainPkg, s.inputs.main)
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

// shacState represents a parsing state of one shac.star.
type shacState struct {
	intr *interpreter.Interpreter
	// checks is the list of registered checks callbacks via shac.register_check().
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

// callAllChecks calls all the checks.
//
// It creates a separate thread per check, limited by the number of CPU cores +
// 2. This permits to run them concurrently.
func (s *shacState) callAllChecks(ctx context.Context) error {
	st := ctxState(ctx)
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.NumCPU() + 2)
	for i := range s.checks {
		i := i
		eg.Go(func() error {
			start := time.Now()
			err := s.checks[i].call(ctx, s.intr)
			st.r.CheckCompleted(ctx, s.checks[i].name, time.Since(start), s.checks[i].highestLevel, err)
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
func (c *check) call(ctx context.Context, intr *interpreter.Interpreter) error {
	ctx = context.WithValue(ctx, &checkCtxKey, c)
	th := intr.Thread(ctx)
	th.Name = c.name
	args := starlark.Tuple{getCtx()}
	args.Freeze()
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
