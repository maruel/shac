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

package cli

import (
	flag "github.com/spf13/pflag"
	"go.fuchsia.dev/shac-project/shac/internal/engine"
)

type commandBase struct {
	root      string
	allFiles  bool
	noRecurse bool
}

func (c *commandBase) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.root, "root", ".", "path to the root of the tree to analyse")
	f.BoolVar(&c.allFiles, "all", false, "checks all the files instead of guess the upstream to diff against")
	f.BoolVar(&c.noRecurse, "no-recurse", false, "do not look for shac.star files recursively")
}

func (c *commandBase) options() engine.Options {
	return engine.Options{
		Root:     c.root,
		AllFiles: c.allFiles,
		Recurse:  !c.noRecurse,
	}
}