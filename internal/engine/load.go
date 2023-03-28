// Copyright 2023 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package engine

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"

	"go.chromium.org/luci/common/data/stringset"
	"go.chromium.org/luci/common/errors"
	"go.chromium.org/luci/starlark/builtins"
	"go.chromium.org/luci/starlark/interpreter"
	"go.starlark.net/lib/json"
	"go.starlark.net/starlark"
)

// Load loads a main shac.star file from a root directory.
//
// main is normally shac.star.
func Load(ctx context.Context, root, main string) error {
	if filepath.IsAbs(main) {
		return errors.New("main file must not be an absolute path")
	}
	var err error
	if root, err = filepath.Abs(root); err != nil {
		return err
	}
	s, err := parse(ctx, &inputs{
		code: interpreter.FileSystemLoader(root),
		root: root,
		main: main,
	})
	if err != nil {
		return err
	}
	if len(s.checks.c) == 0 && !s.printCalled {
		return errors.New("did you forget to call register_check?")
	}
	ctx = context.WithValue(ctx, stateCtxKey, s)
	if errs := s.checks.callAll(ctx, s.intr.Thread(ctx)); len(errs) != 0 {
		return dedupeErrs(errs)
	}
	return nil
}

// inputs represents a starlark package.
type inputs struct {
	code interpreter.Loader
	root string
	main string
}

// state represents a parsing state of the main starlark tree.
type state struct {
	intr     *interpreter.Interpreter
	inputs   *inputs
	allFiles bool
	scm      scmCheckout

	checks      checks
	doneLoading bool

	mu          sync.Mutex
	printCalled bool
}

// ctxState pulls out *state from the context.
//
// Panics if not there.
func ctxState(ctx context.Context) *state {
	return ctx.Value(stateCtxKey).(*state)
}

// dedupeErrs returns a list of merged errors as a MultiError, deduplicating
// errors with the same backtrace.
func dedupeErrs(err ...error) error {
	// TODO(maruel): Require go1.20 and use the new stdlib native multierror
	// support.
	var errs errors.MultiError
	seenErrs := stringset.New(len(err))
	for _, e := range err {
		var bt BacktracableError
		if !errors.As(e, &bt) || seenErrs.Add(bt.Backtrace()) {
			errs = append(errs, e)
		}
	}
	return errs
}

const stateCtxKey = "shac.State"

var (
	// stderrPrint is where print() calls are sent.
	stderrPrint io.Writer = os.Stderr
	// version is the current tool version.
	//
	// TODO(maruel): Add proper version, preferably from git tag.
	version = [...]int{0, 0, 1}
)

func parse(ctx context.Context, inputs *inputs) (*state, error) {
	failures := builtins.FailureCollector{}
	s := &state{
		inputs: inputs,
	}
	s.intr = &interpreter.Interpreter{
		Predeclared: getPredeclared(),
		Packages: map[string]interpreter.Loader{
			interpreter.MainPkg: inputs.code,
		},
		Logger: func(file string, line int, message string) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.printCalled = true
			fmt.Fprintf(stderrPrint, "[%s:%d] %s\n", file, line, message)
		},
		ThreadModifier: func(th *starlark.Thread) {
			failures.Install(th)
		},
	}
	ctx = context.WithValue(ctx, stateCtxKey, s)

	s.scm = getSCM(ctx, inputs.root)

	var err error
	if err = s.intr.Init(ctx); err == nil {
		_, err = s.intr.ExecModule(ctx, interpreter.MainPkg, s.inputs.main)
	}
	if err != nil {
		if f := failures.LatestFailure(); f != nil {
			// Prefer the collected error if any, it will have a collected trace.
			err = f
		}
		return nil, dedupeErrs(err)
	}
	// TODO(maruel): Error if there are unconsumed variables once variables are
	// added.
	s.doneLoading = true
	return s, nil
}

// getPredeclared returns the predeclared starlark symbols in the runtime.
func getPredeclared() starlark.StringDict {
	// TODO(maruel): Add more native symbols.
	native := starlark.StringDict{
		"commitHash": starlark.String(getCommitHash()),
		"version": starlark.Tuple{
			starlark.MakeInt(version[0]), starlark.MakeInt(version[1]), starlark.MakeInt(version[2]),
		},
	}
	// The upstream starlark interpreter includes all the symbols described at
	// https://github.com/google/starlark-go/blob/HEAD/doc/spec.md#built-in-constants-and-functions
	// See https://pkg.go.dev/go.starlark.net/starlark#Universe for the default list.
	return starlark.StringDict{
		// register_check is the only function that is exposed by the runtime that
		// is specific to shac. The rest is hidden inside the __native__ struct.
		"register_check": starlark.NewBuiltin("register_check", registerCheck),
		"__native__":     toValue("__native__", native),

		// Add https://bazel.build/rules/lib/json so it feels more natural to bazel
		// users.
		"json": json.Module,

		// luci-go's starlark additional features.
		// Override fail to include additional functionality.
		"fail":       builtins.Fail,
		"stacktrace": builtins.Stacktrace,
		"struct":     builtins.Struct,
	}
}

// getCommitHash return the git commit hash that was used to build this
// executable.
func getCommitHash() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}
