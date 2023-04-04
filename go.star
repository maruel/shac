# Copyright 2023 The Shac Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


def gosec(ctx, version = "v2.15.0"):
  """Runs gosec on a Go code base.

  See https://github.com/securego/gosec for more details.

  Args:
    ctx: A ctx instance.
    version: gosec version to install. Defaults to a recent version, that will
      be rolled from time to time.
  """
  # TODO(maruel): Always install locally with GOBIN=.tools
  if ctx.exec(["go", "install", "github.com/securego/gosec/v2/cmd/gosec@" + version]):
    fail("failed to install")
  if ctx.exec(["gosec", "-fmt=golint", "-quiet", "-exclude=G304", "-exclude-dir=.tools", "./..."]):
    # TODO(maruel): Emits lines.
    fail("failed gosec")