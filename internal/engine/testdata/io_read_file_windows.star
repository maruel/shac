# Copyright 2023 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

def cb(shac):
  shac.io.read_file("test\\data.txt")

register_check(cb)
