# Copyright 2023 The Shac Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

def cb(ctx):
  ctx.os.exec(["echo", "hello world"], cwd = "../foo")

register_check(cb)
