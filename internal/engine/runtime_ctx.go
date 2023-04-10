// Copyright 2023 The Shac Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package engine

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	"go.chromium.org/luci/starlark/builtins"
	"go.chromium.org/luci/starlark/interpreter"
	"go.starlark.net/starlark"
)

// getCtx returns the ctx object to pass to a registered check callback.
//
// Make sure to update //doc/stdlib.star whenever this function is modified.
func getCtx() starlark.Value {
	return toValue("ctx", starlark.StringDict{
		"emit": toValue("emit", starlark.StringDict{
			"annotation": starlark.NewBuiltin("annotation", ctxEmitAnnotation),
			"artifact":   builtins.Fail,
			"result":     builtins.Fail,
		}),
		"io": toValue("io", starlark.StringDict{
			"read_file": starlark.NewBuiltin("read_file", ctxIoReadFile),
		}),
		"os": toValue("os", starlark.StringDict{
			"exec": starlark.NewBuiltin("exec", ctxOsExec),
		}),
		// Implemented in runtime_ctx_re.go
		"re": toValue("re", starlark.StringDict{
			"match":      starlark.NewBuiltin("match", ctxReMatch),
			"allmatches": starlark.NewBuiltin("allmatches", ctxReAllMatches),
		}),
		// Implemented in runtime_ctx_scm.go
		"scm": toValue("scm", starlark.StringDict{
			"affected_files": starlark.NewBuiltin("affected_files", ctxScmAffectedFiles),
			"all_files":      starlark.NewBuiltin("all_files", ctxScmAllFiles),
		}),
	})
}

// ctxIoReadFile implements native function ctx.io.read_file().
//
// Use POSIX style relative path. "..", "\" and absolute paths are denied.
//
// Make sure to update //doc/stdlib.star whenever this function is modified.
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

// ctxOsExec implements the native function ctx.os.exec().
//
// TODO(olivernewman): Return a struct with stdout and stderr in addition to the
// exit code.
//
// Make sure to update //doc/stdlib.star whenever this function is modified.
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

// Support functions.

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
