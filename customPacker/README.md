# cpacker-win — MBA-obfuscated executable packer (Windows / MinGW)

A minimal UPX-style packer for **Windows .exe** files. It compresses the target
with deflate, hides the decompression with Mixed Boolean-Arithmetic (MBA)
obfuscation, and unpacks + runs it at launch. Educational / RE study project.

## Files

- `mathcrypt.h` — the math layer (shared with the Linux version). Byte-wise
  affine cipher over Z/256 (`encode`) and its MBA-obfuscated inverse
  (`decode_mba`), verified exhaustively over all 256 byte values.
- `packer.c`   — build-time tool: deflate + encode the input, append to the stub.
- `stub_win.c` — runtime loader using native Win32
  (`GetModuleFileNameA`, `GetTempFileNameA`, `CreateProcessA`).
- `miniz.c` / `miniz.h` — single-file zlib replacement, so there is **no
  external library to install**. (from richgel999/miniz, MIT licensed)

## Layout of a packed file

```
[ stub .exe ][ encoded+compressed payload ][ orig u64 ][ comp u64 ][ "MBApack!" ]
```

The stub reads the 24-byte footer from the end of its own .exe to locate and
restore the payload.

## Build (MinGW-w64)

```sh
gcc -O2 -Wall stub_win.c miniz.c -o stub.exe
gcc -O2 -Wall packer.c   miniz.c -o packer.exe
```

No `-lz` needed — miniz is compiled in directly. (This is why the Linux
`-lz` build failed under MinGW: MinGW ships no zlib. miniz removes that
dependency entirely.)

## Use

```sh
packer.exe stub.exe yourprogram.exe yourprogram_packed.exe
yourprogram_packed.exe          # runs exactly like the original
```

## How it runs

1. The packed .exe *is* the stub with the payload appended.
2. On launch the stub finds its own path, reads the footer, reads the payload.
3. It DECODEs the payload (MBA affine inverse), then INFLATEs it (miniz).
4. It writes the original .exe to `%TEMP%`, runs it with `CreateProcess`, waits,
   forwards the exit code, and deletes the temp file.

## What "obfuscated" means here

Only the stub ships, and the stub only runs `decode`. So `decode` is what an
attacker disassembles — that's where the MBA lives. The clean affine inverse is
four obvious instructions (`ror; xor; sub; imul`); the MBA version is ~30
tangled `and/or/xor/add/shift` instructions with identical behavior.

## Known limitations (next steps)

- The final `imul` (= A^{-1}) is still visible; a full MBA multiply hides it.
- Byte-wise (Z/256) is weak — effectively a 256-entry substitution table.
  Moving to 32-bit words (Z/2^32) is much stronger.
- The MBA pattern is fixed => it has a signature. Randomizing per build defeats
  pattern matching.
- The stub drops the unpacked .exe to %TEMP%. A stealthier design would run it
  from memory, but that is substantially more involved on Windows.
- Antivirus heuristics flag self-unpacking stubs; this is expected for any
  packer and is why real distribution uses signed, well-known packers.

## Note on verification

This was built and round-trip tested via MinGW-w64 cross-compilation and Wine
(`packer.exe` → packed a test `victim.exe` → ran it → correct output). Behavior
on real Windows should match, but do test on your target Windows version.
