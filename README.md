# uuids

UUID library for Nim.

API:
```nim
type UUID* = object
  ## 128-bit UUID compliant with RFC-4122

proc `$`*(uuid: UUID): string
  ## Returns a string representation of the UUID in canonical form.

proc hash*(uuid: UUID): Hash
  ## Computes hash of the specified UUID.

proc `==`*(x, y: UUID): bool
  ## Returns true when the specified UUIDs are equal, false otherwise.

proc genUUID*(): UUID =
  ## Returns a random (v4) UUID.
  ## Uses random values obtained from system source (e.g. urandom).
  ## In the future this will use a cryptographically secure PRNG for efficiency.

proc toUUID*(s: string): UUID {.raises: [ValueError].}
  ## Converts string representation of an UUID to UUID object.
  ## Raises ValueError if invalid format is provided.
```

## License
This library is licensed under the MIT license.
Read [LICENSE](https://github.com/pragmagic/uuids/blob/master/LICENSE) file for details.

Copyright (c) 2016 Xored Software, Inc.
