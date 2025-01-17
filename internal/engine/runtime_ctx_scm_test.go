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

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGitConfigEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		gitConfig map[string]string
		want      []string
	}{
		{
			"empty config",
			nil,
			[]string{"GIT_CONFIG_COUNT=0"},
		},
		{
			"one variable",
			map[string]string{
				"foo.bar": "baz",
			},
			[]string{
				"GIT_CONFIG_COUNT=1",
				"GIT_CONFIG_KEY_0=foo.bar",
				"GIT_CONFIG_VALUE_0=baz",
			},
		},
		{
			"multiple variables",
			map[string]string{
				"foo.bar":          "baz",
				"a_variable":       "a_value",
				"another_variable": "another_value",
			},
			[]string{
				"GIT_CONFIG_COUNT=3",
				"GIT_CONFIG_KEY_0=a_variable",
				"GIT_CONFIG_VALUE_0=a_value",
				"GIT_CONFIG_KEY_1=another_variable",
				"GIT_CONFIG_VALUE_1=another_value",
				"GIT_CONFIG_KEY_2=foo.bar",
				"GIT_CONFIG_VALUE_2=baz",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := gitConfigEnv(tt.gitConfig)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("gitConfigEnv() diff (-want +got):\n%s", diff)
			}
		})
	}
}
