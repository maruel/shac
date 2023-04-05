// Copyright 2023 The Shac Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"go.chromium.org/luci/starlark/builtins"
	"go.chromium.org/luci/starlark/interpreter"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"golang.org/x/sync/errgroup"
)

// checks is a list of registered checks callbacks.
//
// It lives in state. Checks are executed sequentially after all Starlark
// code is loaded. They run checks and emit results (results and comments).
type checks struct {
	c []check
}

type check struct {
	cb starlark.Callable
}

// add registers a new callback.
func (c *checks) add(cb starlark.Callable) error {
	c.c = append(c.c, check{cb: cb})
	return nil
}

func (c *check) name() string {
	return strings.TrimPrefix(c.cb.Name(), "_")
}

// callAll calls all the checks.
//
// It creates a separate thread per check, limited by the number of CPU cores +
// 2. This permits to run them concurrently.
func (c *checks) callAll(ctx context.Context, intr *interpreter.Interpreter) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.NumCPU() + 2)
	for i := range c.c {
		i := i
		eg.Go(func() error {
			n := c.c[i].name()
			th := intr.Thread(ctx)
			th.Name = n
			fc := builtins.GetFailureCollector(th)
			if fc != nil {
				fc.Clear()
			}
			// TODO(maruel): Set a context for the subdirectory.
			args := starlark.Tuple{getCtx()}
			args.Freeze()
			if r, err := starlark.Call(th, c.c[i].cb, args, nil); err != nil {
				if fc != nil && fc.LatestFailure() != nil {
					// Prefer this error, it has custom stack trace.
					return fc.LatestFailure()
				}
				return err
			} else if r != starlark.None {
				return fmt.Errorf("check %q returned an object of type %s, expected None", n, r.Type())
			}
			return nil
		})
	}
	return eg.Wait()
}

// getCtx returns the ctx object to pass to a registered check callback.
//
// Make sure to update stdlib.star whenever this object is modified.
func getCtx() starlark.Value {
	return toValue("ctx", starlark.StringDict{
		"io": toValue("io", starlark.StringDict{
			"read_file": starlark.NewBuiltin("read_file", ctxIoReadFile),
		}),
		"os": toValue("os", starlark.StringDict{
			"exec": starlark.NewBuiltin("exec", ctxOsExec),
		}),
		"re": toValue("re", starlark.StringDict{
			"match":      starlark.NewBuiltin("match", ctxReMatch),
			"allmatches": starlark.NewBuiltin("allmatches", ctxReAllMatches),
		}),
		"result": toValue("result", starlark.StringDict{
			"emit_comment":  builtins.Fail,
			"emit_row":      builtins.Fail,
			"emit_artifact": builtins.Fail,
		}),
		"scm": toValue("scm", starlark.StringDict{
			"affected_files": starlark.NewBuiltin("affected_files", ctxScmAffectedFiles),
			"all_files":      starlark.NewBuiltin("all_files", ctxScmAllFiles),
		}),
	})
}

// toValue converts a StringDict to a Value.
func toValue(name string, d starlark.StringDict) starlark.Value {
	return starlarkstruct.FromStringDict(starlark.String(name), d)
}

// registerCheck implements native function shac.register_check().
//
// Make sure to update stdlib.star whenever this function is modified.
func registerCheck(th *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var cb starlark.Callable
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"cb", &cb,
	); err != nil {
		return nil, err
	}
	// TODO(maruel): Inspect cb to verify that it accepts one argument.
	ctx := interpreter.Context(th)
	s := ctxState(ctx)
	if s.doneLoading {
		return nil, errors.New("can't register checks after done loading")
	}
	return starlark.None, s.checks.add(cb)
}

// ctxIoReadFile implements native function ctx.io.read_file().
//
// Use POSIX style relative path. "..", "\" and absolute paths are denied.
//
// Make sure to update stdlib.star whenever this function is modified.
func ctxIoReadFile(th *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var argpath starlark.String
	var argsize starlark.Int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"path", &argpath,
		"size?", &argsize,
	); err != nil {
		return nil, err
	}
	size, ok := argsize.Int64()
	if !ok {
		return nil, errors.New("invalid size")
	}
	ctx := interpreter.Context(th)
	s := ctxState(ctx)
	dst, err := absPath(string(argpath), s.inputs.root)
	if err != nil {
		return starlark.None, err
	}
	b, err := readFile(dst, size)
	if err != nil {
		return starlark.None, err
	}
	// TODO(maruel): Use unsafe conversion to save a memory copy.
	return starlark.Bytes(b), nil
}

// readFile is similar to os.ReadFile() albeit it limits the amount of data
// returned to max bytes when specified.
//
// On 32 bits, max defaults to 128Mib. On 64 bits, max defaults to 4Gib.
func readFile(name string, max int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	//#nosec G307
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if max > 0 && size > max {
		size = max
	}
	if uintSize := 32 << (^uint(0) >> 63); uintSize == 32 {
		if hardMax := int64(128 * 1024 * 1024); size > hardMax {
			size = hardMax
		}
	} else if hardMax := int64(4 * 1024 * 1024 * 1024); size > hardMax {
		size = hardMax
	}
	for data := make([]byte, 0, int(size)); ; {
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil || len(data) == cap(data) {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

// absPath makes a source-relative path absolute, validating it along the way.
//
// TODO(maruel): Make it work on Windows.
func absPath(rel, rootDir string) (string, error) {
	if strings.Contains(rel, "\\") {
		return "", errors.New("use POSIX style path")
	}
	// Package path use POSIX style even on Windows, unlike path/filepath.
	if path.IsAbs(rel) {
		return "", errors.New("do not use absolute path")
	}
	// This is overly zealous. Revisit if it is too much.
	if path.Clean(rel) != rel {
		return "", errors.New("pass cleaned path")
	}
	pathParts := append([]string{rootDir}, strings.Split(rel, "/")...)
	res := path.Join(pathParts...)
	if !strings.HasPrefix(res, rootDir) {
		return "", errors.New("cannot escape root")
	}
	return res, nil
}

// ctxOsExec implements the native function ctx.os.exec().
//
// TODO(olivernewman): Return a struct with stdout and stderr in addition to the
// exit code.
//
// Make sure to update stdlib.star whenever this function is modified.
func ctxOsExec(th *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rawCmd *starlark.List
	var cwd starlark.String
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"cmd", &rawCmd,
		"cwd?", &cwd,
	); err != nil {
		return nil, err
	}
	if rawCmd.Len() == 0 {
		return starlark.None, errors.New("cmdline must not be an empty list")
	}

	var parsedCmd []string
	var val starlark.Value
	iter := rawCmd.Iterate()
	defer iter.Done()
	for iter.Next(&val) {
		str, ok := val.(starlark.String)
		if !ok {
			return starlark.None, errors.New("command args must be strings")
		}
		parsedCmd = append(parsedCmd, str.GoString())
	}

	ctx := interpreter.Context(th)
	s := ctxState(ctx)

	// TODO(olivernewman): Wrap with nsjail on linux.
	//#nosec G204
	cmd := exec.CommandContext(ctx, parsedCmd[0], parsedCmd[1:]...)

	if cwd.GoString() != "" {
		var err error
		cmd.Dir, err = absPath(cwd.GoString(), s.inputs.root)
		if err != nil {
			return starlark.None, err
		}
	} else {
		cmd.Dir = s.inputs.root
	}

	if err := cmd.Run(); err != nil {
		if errExit := (&exec.ExitError{}); errors.As(err, &errExit) {
			return starlark.MakeInt(errExit.ExitCode()), nil
		}
		return starlark.None, err
	}
	return starlark.MakeInt(0), nil
}
