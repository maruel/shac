// Copyright 2023 The Shac Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.chromium.org/luci/lucicfg/docgen"
)

func TestDocStdlib(t *testing.T) {
	// This is a state change detector.
	got, err := Doc("stdlib")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "doc", "stdlib.md"))
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(b), got); diff != "" {
		t.Fatalf("mismatch (+want -got):\n%s", diff)
	}
}

func TestDocTemplate(t *testing.T) {
	data := []struct {
		in   string
		want string
	}{
		{
			"def foo():\n  pass\n",
			"# main.star\n\n## Table of contents\n\n- [foo](#foo)\n\n## foo\n",
		},
		{
			"\n",
			// TODO(maruel): Unexpected LF placement.
			"\n# main.star",
		},
		{
			"foo = True\n",
			// TODO(maruel): Too many trailing spaces.
			"# main.star\n\n## Table of contents\n\n- [foo](#foo)\n\n\n",
		},
		{
			"foo = struct()\n",
			// TODO(maruel): Too many trailing spaces.
			"# main.star\n\n## Table of contents\n\n- [foo](#foo)\n\n## foo\n\n\n",
		},
	}
	for i, line := range data {
		line := line
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, err := genDoc("main.star", line.in)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(line.want, got); diff != "" {
				t.Fatalf("mismatch (+want -got):\n%s\n%s", line.in, diff)
			}
		})
	}
}

func TestDocgenGenerator(t *testing.T) {
	// It's not really a unit test, it's more to document parts of what is
	// available in the template engine.
	t.Parallel()
	g := docgen.Generator{
		Starlark: func(m string) (string, error) {
			if m != "main.star" {
				t.Fatal(m)
			}
			// See https://pkg.go.dev/go.chromium.org/luci/lucicfg/docgen/docstring for
			// the parsing algorithm.
			src := `
# This is a comment.
def _affected_files():
  """Returns affected files.

  When --all is passed, all files are returned.

  Args:
    glob: A glob to filter returned filed.

  Returns:
    A map of {path: file(...)} where the struct has a string field action and a
    function new_line().
  """
  pass

ctx = struct(
  scm = struct(
    affected_files = _affected_files,
  ),
)

file = struct(
  action = "A",
)
`
			return src, nil
		},
	}
	common := `{{ $af := Symbol "main.star" "ctx.scm.affected_files" }}` +
		`{{- $file := Symbol "main.star" "file" }}` +
		`{{- $ctx := Symbol "main.star" "ctx" }}`
	data := []struct {
		in   string
		want string
	}{
		{"{{ $af.Name }}", "affected_files"},
		{"{{ $af.Def.Name }}", "_affected_files"},
		{"{{ $af.Def.Doc }}",
			// The original unparsed docstring as-is.
			"Returns affected files.\n\n" +
				"  When --all is passed, all files are returned.\n\n" +
				"  Args:\n" +
				"    glob: A glob to filter returned filed.\n\n" +
				"  Returns:\n" +
				"    A map of {path: file(...)} where the struct has a string field action and a\n" +
				"    function new_line().\n" +
				"  ",
		},
		{"{{ $af.Def.Comments }}", "This is a comment."},
		{"{{ $af.Doc.Description }}",
			"Returns affected files.\n\n" +
				"When --all is passed, all files are returned.",
		},
		{"{{ $af.Doc.Fields }}", "[{Args [{glob A glob to filter returned filed.}]}]"},
		{"{{ $af.Doc.Remarks }}",
			"[{Returns A map of {path: file(...)} where the struct has a string field action and a\n" +
				"function new_line().}]",
		},
		{"{{ $af.Doc.Args }}", "[{glob A glob to filter returned filed.}]"},
		{"{{ $af.Doc.Returns }}",
			"A map of {path: file(...)} where the struct has a string field action and a\n" +
				"function new_line().",
		},
		{"{{ $af.Doc.Returns | LinkifySymbols }}",
			// TODO(maruel): file(...) should have become a link.
			"A map of {path: file(...)} where the struct has a string field action and a\n" +
				"function new_line().",
		},
		{"{{ $af.Module }}", "main.star"},
		{"{{ $af.FullName }}", "ctx.scm.affected_files"},
		{"{{ $af.Anchor }}", "ctx.scm.affected-files"},
		{"{{ $af.Flavor }}", "func"},
		{"{{ $af.InvocationSnippet }}", "ctx.scm.affected_files(glob = None)"},
		{"{{ $ctx.Flavor }}", "struct"},
		{"{{ range $ctx.Symbols }}{{ .Name }}\n{{ end }}", "scm\n"},
	}
	for i, line := range data {
		line := line
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			b, err := g.Render(common + line.in)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(line.want, string(b)); diff != "" {
				t.Fatalf("mismatch (+want -got):\n%s\n%s", line.in, diff)
			}
		})
	}
}
