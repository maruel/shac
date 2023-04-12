# Copyright 2023 The Shac Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def cb(ctx):
  ctx.emit.annotation(
      level="warning",
      message="please fix",
      filepath="file.txt",
      line=1,
      col=1,
      end_line=10,
      end_col=1,
      replacements=("a", "tuple"))
  ctx.emit.annotation(level="notice", line=100, col=2, message="great code")
  ctx.emit.annotation(
      level="warning",
      message="please fix",
      filepath="file.txt",
      line=1,
      col=1,
      end_line=10,
      end_col=1,
      replacements=["a", "list"])
  ctx.emit.annotation(
      level="warning",
      message="weird",
      line=1,
      end_line=10,
      replacements={"a": True, "dict": 42})

shac.register_check(cb)
