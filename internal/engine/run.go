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
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/plumbing/format/gitignore"
	"go.fuchsia.dev/shac-project/shac/internal/sandbox"
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

var errEmptyIgnore = errors.New("ignore fields cannot be empty strings")

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

// CheckFilter controls which checks get run by `Run`. It returns true for
// checks that should be run, false for checks that should be skipped.
type CheckFilter func(registeredCheck) bool

// OnlyFormatters causes only checks marked with `formatter = True` to be run.
func OnlyFormatters(c registeredCheck) bool {
	return c.formatter
}

// OnlyNonFormatters causes only checks *not* marked with `formatter = True` to
// be run.
func OnlyNonFormatters(c registeredCheck) bool {
	return !c.formatter
}

// Level is one of "notice", "warning" or "error".
//
// A check is only considered failed if it emits at least one finding with
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
	// EmitFinding emits a finding by a check for a specific file. This is not a
	// failure by itself, unless level "error" is used.
	EmitFinding(ctx context.Context, check string, level Level, message, root, file string, s Span, replacements []string) error
	// EmitArtifact emits an artifact by a check.
	//
	// Only one of root or content can be specified. If root is specified, it is
	// a file on disk. The file may disappear after this function is called. If
	// root is not specified, content is the artifact. Either way, file is the
	// display name of the artifact.
	//
	// content must not be modified.
	EmitArtifact(ctx context.Context, check, root, file string, content []byte) error
	// CheckCompleted is called when a check is completed.
	//
	// It is called with the start time, wall clock duration, the highest level emitted and an error
	// if an abnormal error occurred.
	CheckCompleted(ctx context.Context, check string, start time.Time, d time.Duration, r Level, err error)
	// Print is called when print() starlark function is called.
	Print(ctx context.Context, check, file string, line int, message string)
}

// Options is the options for Run().
type Options struct {
	// Report gets all the emitted findings and artifacts from the checks.
	//
	// This is the only required argument. It is recommended to use
	// reporting.Get() which returns the right implementation based on the
	// environment (CI, interactive, etc).
	Report Report
	// Root directory. Defaults to the current working directory.
	Root string
	// AllFiles tells to consider all files as affected.
	AllFiles bool
	// Recurse tells the engine to run all Main files found in subdirectories.
	Recurse bool
	// Filter controls which checks run.
	Filter CheckFilter

	// main source file to run. Defaults to shac.star. Only used in unit tests.
	main string
	// config is the configuration file. Defaults to shac.textproto. Only used in
	// unit tests.
	config string
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
	main := o.main
	if main == "" {
		main = "shac.star"
	}
	if filepath.IsAbs(main) {
		return errors.New("main file must not be an absolute path")
	}
	config := o.config
	if config == "" {
		config = "shac.textproto"
	}
	p := filepath.Join(root, config)
	var b []byte
	doc := Document{}
	if b, err = os.ReadFile(p); err == nil {
		if err = prototext.Unmarshal(b, &doc); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err = doc.Validate(); err != nil {
		return err
	}
	scm, err := getSCM(ctx, root, o.AllFiles)
	if err != nil {
		return err
	}
	var patterns []gitignore.Pattern
	for _, p := range doc.Ignore {
		if p == "" {
			return errEmptyIgnore
		}
		patterns = append(patterns, gitignore.ParsePattern(p, nil))
	}
	scm = &cachingSCM{
		scm: &filteredSCM{
			matcher: gitignore.NewMatcher(patterns),
			scm:     scm,
		},
	}

	tmpdir, err := os.MkdirTemp("", "shac")
	if err != nil {
		return nil
	}
	pkgMgr := PackageManager{Root: tmpdir}
	packages, err := pkgMgr.RetrievePackages(ctx, root, &doc)
	if err != nil {
		return err
	}
	err = runInner(ctx, root, tmpdir, main, o.Report, doc.AllowNetwork, doc.WritableRoot, o.Recurse, o.Filter, scm, packages)
	if err2 := os.RemoveAll(tmpdir); err == nil {
		err = err2
	}
	return err
}

func runInner(ctx context.Context, root, tmpdir, main string, r Report, allowNetwork, writableRoot, recurse bool, filter CheckFilter, scm scmCheckout, packages map[string]fs.FS) error {
	sb, err := sandbox.New(tmpdir)
	if err != nil {
		return err
	}
	env := starlarkEnv{
		globals:  getPredeclared(),
		sources:  map[string]*loadedSource{},
		packages: packages,
	}

	newState := func(scm scmCheckout, subdir string, idx int) *shacState {
		if subdir != "" {
			normalized := subdir + "/"
			if subdir == "." {
				subdir = ""
				normalized = ""
			}
			scm = &subdirSCM{s: scm, subdir: normalized}
		}
		return &shacState{
			allowNetwork: allowNetwork,
			env:          &env,
			filter:       filter,
			main:         main,
			r:            r,
			root:         root,
			sandbox:      sb,
			scm:          scm,
			subdir:       subdir,
			tmpdir:       filepath.Join(tmpdir, strconv.Itoa(idx)),
			writableRoot: writableRoot,
		}
	}
	var shacStates []*shacState
	if recurse {
		// Each found shac.star is run in its own interpreter for maximum
		// parallelism.
		// Discover all the main files via the SCM. This enables us to not walk
		// ignored files.
		files, err := scm.allFiles(ctx, false)
		if err != nil {
			return err
		}
		for i, f := range files {
			n := f.rootedpath()
			if filepath.Base(n) == main {
				subdir := strings.ReplaceAll(filepath.Dir(n), "\\", "/")
				shacStates = append(shacStates, newState(scm, subdir, i))
			}
		}
		if len(shacStates) == 0 {
			return fmt.Errorf("no %s files found", main)
		}
	} else {
		shacStates = []*shacState{newState(scm, "", 0)}
	}

	// Parse the starlark files. Run everything from our errgroup.
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.NumCPU() + 2)
	// Make it so each shac can submit at least one item.
	ch := make(chan func() error, len(shacStates))
	done := make(chan struct{})
	for _, s := range shacStates {
		s := s
		eg.Go(func() error {
			err := s.parseAndBuffer(ctx, ch)
			done <- struct{}{}
			return err
		})
	}
	count := len(shacStates)
	for loop := true; loop; {
		select {
		case cb := <-ch:
			if cb == nil {
				loop = false
			} else {
				eg.Go(cb)
			}
		case <-done:
			count--
			if count == 0 {
				// All shac.star processing is done, we can now send a nil to the
				// channel to tell it to stop.
				// Since we are pushing from the same loop that we are pulling, this is
				// blocking. Instead of making the channel buffered, which would slow
				// it down, use a one time goroutine. It's kind of a gross hack but
				// it'll work just fine.
				go func() {
					ch <- nil
				}()
			}
		}
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	// If any check failed, return an error.
	for _, s := range shacStates {
		for i := range s.checks {
			if s.checks[i].highestLevel == Error {
				return ErrCheckFailed
			}
		}
	}
	return nil
}

// shacState represents a parsing state of one shac.star.
type shacState struct {
	env          *starlarkEnv
	r            Report
	allowNetwork bool
	writableRoot bool
	main         string
	// root is the root for the root shac.star that was executed. Native path
	// style.
	root string
	// subdir is the directory into which this shac.star is located. Only set
	// when Options.Recurse is set to true. POSIX path style.
	subdir string
	tmpdir string
	// scm is a filtered view of runState.scm.
	scm scmCheckout
	// sandbox is the object that can be used for sandboxing subprocesses.
	sandbox sandbox.Sandbox
	// checks is the list of registered checks callbacks via
	// shac.register_check().
	//
	// Checks are added serially, so no lock is needed.
	//
	// Checks are executed sequentially after all Starlark code is loaded and not
	// mutated. They run checks and emit results (results and comments).
	checks []registeredCheck
	// filter controls which checks run. If nil, all checks will run.
	filter CheckFilter

	// Set when fail() is called. This happens only during the first phase, thus
	// no mutex is needed.
	failErr *failure

	// Set when the first phase of starlark interpretation is complete. This
	// complete the serial part, after which execution becomes concurrent.
	doneLoading bool

	mu          sync.Mutex
	printCalled bool
	tmpdirIndex int
}

// ctxShacState pulls out *runState from the context.
//
// Panics if not there.
func ctxShacState(ctx context.Context) *shacState {
	return ctx.Value(&shacStateCtxKey).(*shacState)
}

var shacStateCtxKey = "shac.shacState"

// parseAndBuffer parses and run a single shac.star file, then buffer all its checks.
func (s *shacState) parseAndBuffer(ctx context.Context, ch chan<- func() error) error {
	ctx = context.WithValue(ctx, &shacStateCtxKey, s)
	if err := s.parse(ctx); err != nil {
		return err
	}
	if len(s.checks) == 0 && !s.printCalled {
		return errors.New("did you forget to call shac.register_check?")
	}
	// Last phase where checks are called.
	s.bufferAllChecks(ctx, ch)
	return nil
}

// parse parses a single shac.star file.
func (s *shacState) parse(ctx context.Context) error {
	pi := func(th *starlark.Thread, msg string) {
		// Detect if print() was called while loading. Calling either print() or
		// shac.register_check() makes a shac.star valid.
		s.mu.Lock()
		s.printCalled = true
		s.mu.Unlock()
		pos := th.CallFrame(1).Pos
		s.r.Print(ctx, "", pos.Filename(), int(pos.Line), msg)
	}
	p := path.Join(s.subdir, s.main)
	if _, err := s.env.load(ctx, sourceKey{orig: p, pkg: "__main__", relpath: p}, pi); err != nil {
		var evalErr *starlark.EvalError
		if errors.As(err, &evalErr) {
			return &evalError{evalErr}
		}
		return err
	}
	s.doneLoading = true
	return nil
}

// bufferAllChecks adds all the checks to the channel for execution.
func (s *shacState) bufferAllChecks(ctx context.Context, ch chan<- func() error) {
	args := starlark.Tuple{getCtx(path.Join(s.root, s.subdir))}
	args.Freeze()
	for i := range s.checks {
		if s.filter != nil && !s.filter(s.checks[i]) {
			continue
		}
		i := i
		ch <- func() error {
			start := time.Now()
			pi := func(th *starlark.Thread, msg string) {
				pos := th.CallFrame(1).Pos
				s.r.Print(ctx, s.checks[i].name, pos.Filename(), int(pos.Line), msg)
			}
			err := s.checks[i].call(ctx, s.env, args, pi)
			if err != nil && ctx.Err() != nil {
				// Don't report the check completion if the context was
				// canceled. The error was probably caused by the context being
				// canceled as a side effect of another check failing. Only the
				// original check failure should be reported, not the canceled
				// check failures.
				return ctx.Err()
			}
			s.r.CheckCompleted(ctx, s.checks[i].name, start, time.Since(start), s.checks[i].highestLevel, err)
			return err
		}
	}
}

func (s *shacState) newTempDir() (string, error) {
	var err error
	s.mu.Lock()
	i := s.tmpdirIndex
	s.tmpdirIndex++
	if i == 0 {
		// First use, lazy create the temporary directory.
		err = os.Mkdir(s.tmpdir, 0o700)
	}
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	if i >= 1000000 {
		return "", errors.New("too many temporary directories requested")
	}
	p := filepath.Join(s.tmpdir, strconv.Itoa(i))
	if err = os.Mkdir(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

// registeredCheck represents one check that has been registered by
// shac.register_check().
type registeredCheck struct {
	*check
	failErr      *failure // set when fail() is called from within the check, an abnormal failure.
	highestLevel Level    // highest level emitted by EmitFinding.
	subprocesses []*subprocess
}

var checkCtxKey = "shac.check"

// ctxCheck pulls out *registeredCheck from the context.
//
// Returns nil when not run inside a check.
func ctxCheck(ctx context.Context) *registeredCheck {
	c, _ := ctx.Value(&checkCtxKey).(*registeredCheck)
	return c
}

// call calls the check callback and returns an error if an abnormal error happened.
//
// A "normal" error will still have this function return nil.
func (c *registeredCheck) call(ctx context.Context, env *starlarkEnv, args starlark.Tuple, pi printImpl) error {
	ctx = context.WithValue(ctx, &checkCtxKey, c)
	th := env.thread(ctx, c.name, pi)
	if r, err := starlark.Call(th, c.impl, args, nil); err != nil {
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
	var err error
	for _, proc := range c.subprocesses {
		if !proc.waitCalled {
			proc.cleanup()
			if err == nil {
				err = fmt.Errorf("wait() was not called on %s", proc.String())
			}
		}
	}
	return err
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
