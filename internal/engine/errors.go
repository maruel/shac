// Copyright 2023 The Shac Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package engine

import (
	"go.starlark.net/starlark"
)

// BacktracableError is an error that has a starlark backtrace attached to it.
type BacktracableError interface {
	error
	// Backtrace returns a user-friendly error message describing the stack
	// of calls that led to this error, along with the error message itself.
	Backtrace() string
}

// failure is an error emitted by fail(...).
type failure struct {
	Message string             // the error message, as passed to fail(...)
	Stack   starlark.CallStack // where 'fail' itself was called
}

// Error is the short error message, as passed to fail(...).
func (f *failure) Error() string {
	return f.Message
}

// Backtrace returns a user-friendly error message describing the stack of
// calls that led to this error.
//
// The trace of where fail(...) happened is used.
func (f *failure) Backtrace() string {
	return f.Stack.String() + "Error: " + f.Message
}

var (
	_ BacktracableError = (*starlark.EvalError)(nil)
	_ BacktracableError = (*failure)(nil)
)
