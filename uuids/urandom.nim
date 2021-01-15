# Source: https://github.com/BlaXpirit/nim-random/blob/master/src/random/urandom.nim

when defined(windows):
  import winlean

  type ULONG_PTR = int
  type HCRYPTPROV = ULONG_PTR
  var PROV_RSA_FULL {.importc, header: """#include <windows.h>
#include <wincrypt.h>""".}: DWORD
  var CRYPT_VERIFYCONTEXT {.importc, header: """#include <windows.h>
#include <wincrypt.h>""".}: DWORD

  {.push, stdcall, dynlib: "Advapi32.dll".}

  when useWinUnicode:
    proc CryptAcquireContext(
      phProv: ptr HCRYPTPROV, pszContainer: WideCString,
      pszProvider: WideCString, dwProvType: DWORD, dwFlags: DWORD
    ): WINBOOL {.importc: "CryptAcquireContextW".}
  else:
    proc CryptAcquireContext(
      phProv: ptr HCRYPTPROV, pszContainer: cstring, pszProvider: cstring,
      dwProvType: DWORD, dwFlags: DWORD
    ): WINBOOL {.importc: "CryptAcquireContextA".}

  proc CryptGenRandom(
    hProv: HCRYPTPROV, dwLen: DWORD, pbBuffer: pointer
  ): WINBOOL {.importc: "CryptGenRandom".}

  {.pop.}

  var cryptProv: HCRYPTPROV = 0

  proc urandomInit() =
    let success = CryptAcquireContext(
      addr cryptProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
    )
    if success == 0:
      raise newException(OSError, "Call to CryptAcquireContext failed")

template urandomImpl() =
  when defined(windows):
    if cryptProv == 0:
      urandomInit()

    let success = CryptGenRandom(cryptProv, DWORD(size), addr result[0])
    if success == 0:
      raise newException(OSError, "Call to CryptGenRandom failed")

  else:
    var file: File
    if not file.open("/dev/urandom"):
      raise newException(OSError, "/dev/urandom is not available")
    try:
      var index = 0
      while index < size:
        let bytesRead = file.readBuffer(addr result[index], size-index)
        if bytesRead <= 0:
          raise newException(OSError, "Can't read enough bytes from /dev/urandom")
        index += bytesRead
    finally:
      file.close()

proc urandom*(size: static[Natural]): array[size, uint8] =
  ## Returns an ``array`` of random integers ``0 <= n < 256`` provided by
  ## the operating system's cryptographic source.
  urandomImpl()
