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

module go.fuchsia.dev/shac-project/shac

go 1.21

require (
	github.com/go-git/go-git v4.7.0+incompatible
	github.com/google/go-cmp v0.5.9
	github.com/mattn/go-colorable v0.1.13
	github.com/mattn/go-isatty v0.0.19
	github.com/spf13/pflag v1.0.5
	go.starlark.net v0.0.0-20230807144010-2aa75752d1da
	golang.org/x/mod v0.13.0
	golang.org/x/sync v0.4.0
	golang.org/x/tools v0.14.0
	// Pinned to a non-tagged version to get commit
	// https://github.com/protocolbuffers/protobuf-go/commit/6352deccdb59bcc074db0ab49f4d8ba8f3cdb7ee
	// TODO(olivernewman): Switch back to using a tagged version after the first
	// release containing 6352deccdb59bcc074db0ab49f4d8ba8f3cdb7ee.
	google.golang.org/protobuf v1.31.1-0.20230927161544-6352deccdb59
)

require go.chromium.org/luci v0.0.0-20231012044737-639b0ba8e396

require (
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/src-d/gcfg v1.4.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20231009173412-8bfb1ae86b6c // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231009173412-8bfb1ae86b6c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231009173412-8bfb1ae86b6c // indirect
	google.golang.org/grpc v1.58.3 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/src-d/go-billy.v4 v4.3.2 // indirect
	gopkg.in/src-d/go-git.v4 v4.13.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)
