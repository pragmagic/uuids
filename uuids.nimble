[Package]
name: "uuids"
version: "0.1.13"
author: "Xored Software, Inc."
description: "UUID library"
license: "MIT"

[Deps]
requires: "isaac >= 0.1.3"

task test, "Run the test suite":
  exec "nim c -r --hints:off -o:nimcache/tuuids tests/tuuids.nim"
