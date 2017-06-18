# uuids

UUID library for Nim.

API:
```nim
type UUID* = object
  ## 128-bit UUID compliant with RFC-4122

proc initUUID*(mostSigBits, leastSigBits: int64): UUID =
  ## Initializes UUID with the specified most and least significant bits

proc leastSigBits*(uuid: UUID): int64 {.inline.}
  ## Returns 64 least significant bits of the ``uuid``

proc mostSigBits*(uuid: UUID): int64 {.inline.}
  ## Returns 64 most significant bits of the ``uuid``

proc `$`*(uuid: UUID): string
  ## Returns a string representation of the ``uuid`` in canonical form.

proc hash*(uuid: UUID): Hash
  ## Computes hash of the specified ``uuid``.

proc `==`*(x, y: UUID): bool
  ## Returns true when the specified UUIDs are equal, false otherwise.

proc isZero*(uuid: UUID): bool
  ## Returns ``true`` when the ``uuid`` is zero (not set), ``false`` otherwise.

proc genUUID*(): UUID
  ## Returns a random (v4) UUID.
  ## Uses a thread-local cryptographically secure PRNG (ISAAC) seeded with
  ## true random values obtained from OS.

proc parseUUID*(s: string): UUID {.raises: [ValueError].}
  ## Converts string representation of an UUID to UUID object.
  ## Raises ValueError if invalid format is provided.
```

## License
This library is licensed under the MIT license.
Read [LICENSE](https://github.com/pragmagic/uuids/blob/master/LICENSE) file for details.

Copyright (c) 2016 Xored Software, Inc.
