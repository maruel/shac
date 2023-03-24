// Copyright 2023 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package engine

import (
	"go.chromium.org/luci/starlark/builtins"
	"go.starlark.net/starlark"
)

// BacktracableError is an error that has a starlark backtrace attached to it.
//
// Implemented by Error here and by starlark.EvalError.
type BacktracableError interface {
	error
	// Backtrace returns a user-friendly error message describing the stack
	// of calls that led to this error, along with the error message itself.
	Backtrace() string
}

var (
	_ BacktracableError = (*starlark.EvalError)(nil)
	_ BacktracableError = (*builtins.Failure)(nil)
	_ BacktracableError = (*configError)(nil)
)

// configError is a single error message emitted by the config generator.
//
// It holds a stack trace responsible for the error.
type configError struct {
	msg   string
	stack *builtins.CapturedStacktrace
}

// Error is part of 'error' interface.
func (e *configError) Error() string {
	return e.msg
}

// Backtrace is part of BacktracableError interface.
func (e *configError) Backtrace() string {
	if e.stack == nil {
		return e.msg
	}
	return e.stack.String() + "Error: " + e.msg
}
