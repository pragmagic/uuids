# Copyright 2026 Uyuz-ux
# Licensed under the MIT License.

import std/[unittest, sequtils]
import uuids

suite "UUID basics":
  test "zero UUID":
    let u = initUUID(0, 0)
    check(u.isZero)
    check($u == "00000000-0000-0000-0000-000000000000")

  test "bit accessors and equality":
    let u = initUUID(0x123456789ABCDEF'i64, 0xFEDCBA9876543210'i64)
    check(u.mostSigBits == 0x123456789ABCDEF'i64)
    check(u.leastSigBits == 0xFEDCBA9876543210'i64)
    check(u == initUUID(0x123456789ABCDEF'i64, 0xFEDCBA9876543210'i64))
    check(u != initUUID(0, 0))

  test "hash is consistent":
    let a = initUUID(42, 43)
    let b = initUUID(42, 43)
    check(hash(a) == hash(b))

suite "genUUID (version 4)":
  test "version and variant bits are set correctly":
    for i in 1 .. 100:
      let u = genUUID()
      let s = $u
      check(s.len == 36)
      check(s[14] == '4')                      # version nibble
      check(s[19] in {'8', '9', 'a', 'b'})     # IETF variant

  test "generated UUIDs are distinct":
    var seen: seq[UUID]
    for i in 1 .. 1000:
      seen.add(genUUID())
    check(seen.deduplicate().len == seen.len)

suite "parseUUID":
  test "roundtrip preserves all bits":
    for i in 1 .. 100:
      let u = genUUID()
      check(parseUUID($u) == u)

  test "parses uppercase hex":
    let lower = parseUUID("de305d54-75b4-431b-adb2-eb6b9e546014")
    let upper = parseUUID("DE305D54-75B4-431B-ADB2-EB6B9E546014")
    check(lower == upper)

  test "rejects wrong number of parts":
    expect ValueError:
      discard parseUUID("not a uuid")
    expect ValueError:
      discard parseUUID("de305d54-75b4-431b-adb2-eb6b9e546014-extra")

  test "rejects invalid hex":
    expect ValueError:
      discard parseUUID("de305d54-75b4-431b-adb2-eb6b9e54601g")

  test "rejects empty and too long parts":
    expect ValueError:
      discard parseUUID("-75b4-431b-adb2-eb6b9e546014")
    expect ValueError:
      discard parseUUID("de305d541-75b4-431b-adb2-eb6b9e546014")
