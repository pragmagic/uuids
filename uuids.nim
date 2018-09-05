import strutils, hashes
import isaac
import uuids/urandom

type
  UUID* = object
    ## 128-bit UUID compliant with RFC-4122
    mostSigBits: int64
    leastSigBits: int64

template toHex(s: string, start: Natural,
               x: BiggestInt, len: Positive) =
  const HexChars = ['0', '1', '2', '3', '4', '5', '6', '7', '8',
                    '9', 'a', 'b', 'c', 'd', 'e', 'f']
  var n = x
  for j in countdown(len - 1, 0):
    s[start + j] = HexChars[int(n and 0xF)]
    n = n shr 4
    # handle negative overflow
    if n == 0 and x < 0: n = -1

proc uuidsParseHexInt(s: string, maxLen: int): int64 =
  if s.len == 0:
    raise newException(ValueError, "UUID part is empty")
  if s.len > maxLen or s.len > sizeof(result) * 2:
    raise newException(ValueError, "UUID part is longer than expected")
  for c in s:
    case c
    of '0'..'9':
      result = result shl 4 or (ord(c) - ord('0'))
    of 'a'..'f':
      result = result shl 4 or (ord(c) - ord('a') + 10)
    of 'A'..'F':
      result = result shl 4 or (ord(c) - ord('A') + 10)
    else: raise newException(ValueError, "Invalid hex string: " & s)

proc initUUID*(mostSigBits, leastSigBits: int64): UUID =
  ## Initializes UUID with the specified most and least significant bits
  result.mostSigBits = mostSigBits
  result.leastSigBits = leastSigBits

proc leastSigBits*(uuid: UUID): int64 {.inline.} =
  ## Returns 64 least significant bits of the ``uuid``
  uuid.leastSigBits

proc mostSigBits*(uuid: UUID): int64 {.inline.} =
  ## Returns 64 most significant bits of the ``uuid``
  uuid.mostSigBits

proc `$`*(uuid: UUID): string =
  ## Returns a string representation of the ``uuid`` in canonical form.
  result = newString(36)
  toHex(result, 0, uuid.mostSigBits shr 32, 8)
  result[8] = '-'
  toHex(result, 9, uuid.mostSigBits shr 16, 4)
  result[13] = '-'
  toHex(result, 14, uuid.mostSigBits, 4)
  result[18] = '-'
  toHex(result, 19, uuid.leastSigBits shr 48, 4)
  result[23] = '-'
  toHex(result, 24, uuid.leastSigBits, 12)

proc hash*(uuid: UUID): Hash =
  ## Computes hash of the specified ``uuid``.
  result = uuid.mostSigBits.hash() !& uuid.leastSigBits.hash()
  result = !$result

proc `==`*(x, y: UUID): bool =
  ## Returns ``true`` when the specified UUIDs are equal, ``false`` otherwise.
  x.mostSigBits == y.mostSigBits and x.leastSigBits == y.leastSigBits

proc isZero*(uuid: UUID): bool =
  ## Returns ``true`` when the ``uuid`` is zero (not set), ``false`` otherwise.
  uuid.mostSigBits == 0'i64 and uuid.leastSigBits == 0'i64

var rand {.threadvar.}: IsaacGenerator
proc genUUID*(): UUID =
  ## Returns a random (v4) UUID.
  ## Uses a thread-local cryptographically secure PRNG (ISAAC) seeded with
  ## true random values obtained from OS.
  if rand == nil:
    var seed = cast[array[256, uint32]](urandom(1024))
    rand = newIsaacGenerator(seed)
  result.mostSigBits = cast[int64]((rand.nextU32().uint64 shl 32) or rand.nextU32())
  result.leastSigBits = cast[int64]((rand.nextU32().uint64 shl 32) or rand.nextU32())

  # set version to 4
  result.mostSigBits = (result.mostSigBits and 0xFFFFFFFFFFFF0FFF'i64) or
                       0x0000000000004000'i64
  # set IETF variant
  result.leastSigBits = (result.leastSigBits and 0x3FFFFFFFFFFFFFFF'i64) or
                        0x8000000000000000'i64

proc parseUUID*(s: string): UUID {.raises: [ValueError].} =
  ## Converts string representation of an UUID to UUID object.
  ## Raises ``ValueError`` if invalid format is provided.
  let parts = s.split('-')
  if parts.len != 5:
    raise newException(ValueError,
                       "UUID must consist of 5 parts separated with `-`")
  var mostSigBits: int64 = uuidsParseHexInt(parts[0], 8)
  mostSigBits = mostSigBits shl 16
  mostSigBits = mostSigBits or uuidsParseHexInt(parts[1], 4)
  mostSigBits = mostSigBits shl 16
  mostSigBits = mostSigBits or uuidsParseHexInt(parts[2], 4)

  var leastSigBits: int64 = uuidsParseHexInt(parts[3], 4)
  leastSigBits = leastSigBits shl 48
  leastSigBits = leastSigBits or uuidsParseHexInt(parts[4], 12)

  result = UUID(mostSigBits: mostSigBits, leastSigBits: leastSigBits)

when isMainModule:
  var uuid: UUID
  assert(uuid.isZero())
  for i in 1..100:
    uuid = genUUID()
    let uuidStr = $uuid
    assert(uuidStr.len == 36)
    assert(uuidStr[14] == '4') # version
    assert(uuidStr[19] in {'8', '9', 'a', 'b'}) # variant (2 bits)

    let parsedUUID = uuidStr.parseUUID()
    assert(parsedUUID == uuid)
    assert(parsedUUID.hash() == uuid.hash())
    assert(mostSigBits(parsedUUID) == mostSigBits(uuid))
    assert(leastSigBits(parsedUUID) == leastSigBits(uuid))

    let newUUID = initUUID(mostSigBits(uuid), leastSigBits(uuid))
    assert(newUUID == uuid)
    assert(newUUID.hash() == uuid.hash())
    assert(mostSigBits(newUUID) == mostSigBits(uuid))
    assert(leastSigBits(newUUID) == leastSigBits(uuid))
