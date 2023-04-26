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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	flag "github.com/spf13/pflag"
	"go.fuchsia.dev/shac-project/shac/internal/engine"
	"google.golang.org/protobuf/encoding/prototext"
)

type modCmd struct {
	root string
}

func (*modCmd) Name() string {
	return "mod"
}

func (*modCmd) Description() string {
	return "Tidy, add or update a shac.textproto file with regards to dependencies.\n" +
		"Valid subcommands are:\n" +
		"  shac mod add <url> <version>  Add a dependency\n" +
		"  shac mod remove <url>         Remove a dependency"
}

func (m *modCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&m.root, "root", ".", "path to the root of the tree to analyse")
}

func (m *modCmd) Execute(ctx context.Context, args []string) error {
	root, err := filepath.Abs(m.root)
	if err != nil {
		return err
	}
	m.root = root
	p := filepath.Join(m.root, "shac.textproto")
	doc := engine.Document{}
	b, err := os.ReadFile(p)
	if err == nil {
		if err = prototext.Unmarshal(b, &doc); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if doc.Requirements == nil {
		doc.Requirements = &engine.Requirements{}
	}
	// The configuration is validated but hashes are not verified at this stage.
	if err = doc.Validate(); err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("unsupported arguments, try shac mod --help")
	}
	switch args[0] {
	case "add":
		if len(args) != 3 {
			return errors.New("unsupported arguments, try shac mod --help")
		}
	case "remove":
		if len(args) != 2 {
			return errors.New("unsupported arguments, try shac mod --help")
		}
	default:
		return errors.New("unsupported arguments, try shac mod --help")
	}
	tmp, err := os.MkdirTemp("", "shac")
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		err = m.modAdd(ctx, tmp, args[1], args[2], &doc)
	case "remove":
		err = m.modRemove(ctx, tmp, args[1], &doc)
	}
	if err2 := os.RemoveAll(tmp); err == nil {
		err = err2
	}
	if err != nil {
		return err
	}
	if b, err = (prototext.MarshalOptions{Multiline: true}).Marshal(&doc); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o666)
}

func (m *modCmd) modAdd(ctx context.Context, tmp string, url, version string, doc *engine.Document) error {
	found := false
	for _, d := range doc.Requirements.Direct {
		if d.Url == url {
			found = true
			d.Version = version
			break
		}
	}
	if !found {
		for i, d := range doc.Requirements.Indirect {
			if d.Url == url {
				// Remove it from here, since it becomes a direct dependency.
				copy(doc.Requirements.Indirect[i:], doc.Requirements.Indirect[i+1:])
				doc.Requirements.Indirect = doc.Requirements.Indirect[:len(doc.Requirements.Indirect)-1]
				break
			}
		}
	}
	if !found {
		doc.Requirements.Direct = append(doc.Requirements.Direct, &engine.Dependency{Url: url, Version: version})
	}

	// Now fetch the package to calculate the hash.
	tmpdoc := engine.Document{Requirements: &engine.Requirements{}, Sum: &engine.Sum{}}
	tmpdoc.Requirements.Direct = []*engine.Dependency{{Url: url, Version: version}}
	tmpdoc.Sum.Known = []*engine.Known{
		{
			Url:  url,
			Seen: []*engine.VersionDigest{{Version: version, Digest: ""}},
		},
	}
	pkgMgr := engine.NewPackageManager(tmp)
	_, err := pkgMgr.RetrievePackages(ctx, m.root, &tmpdoc)
	if err != nil {
		return err
	}

	// Update the hash.
	/*
		digest := doc.Sum.Digest(url, version)
		doc.Sum.Known = append(
			doc.Sum.Known,
			&engine.Known{
				Url:  url,
				Seen: []*engine.VersionDigest{&engine.VersionDigest{Version: version, Digest: digest}},
			})
	*/
	return nil
}

func (m *modCmd) modRemove(ctx context.Context, tmp string, url string, doc *engine.Document) error {
	found := false
	for i, d := range doc.Requirements.Direct {
		if d.Url == url {
			found = true
			copy(doc.Requirements.Direct[i:], doc.Requirements.Direct[i+1:])
			doc.Requirements.Direct = doc.Requirements.Direct[:len(doc.Requirements.Direct)-1]
			break
		}
	}
	if !found {
		for i, d := range doc.Requirements.Indirect {
			if d.Url == url {
				found = true
				copy(doc.Requirements.Indirect[i:], doc.Requirements.Indirect[i+1:])
				doc.Requirements.Indirect = doc.Requirements.Indirect[:len(doc.Requirements.Indirect)-1]
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("dependency %s not found", url)
	}
	for i, s := range doc.Sum.Known {
		if s.Url == url {
			copy(doc.Sum.Known[i:], doc.Sum.Known[i+1:])
			doc.Sum.Known = doc.Sum.Known[:len(doc.Sum.Known)-1]
			break
		}
	}
	return nil
}
