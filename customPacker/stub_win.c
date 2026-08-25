/* stub_win.c -- Windows runtime loader (native Win32).
 *
 * A packed file looks like:
 *   [ this stub .exe ][ compressed+encoded payload ][ orig_size u64 ]
 *   [ comp_size u64 ][ "MBApack!" magic ]
 *
 * At run time the stub:
 *   1. finds its own .exe path            (GetModuleFileNameA)
 *   2. reads the 24-byte footer to locate the payload
 *   3. reads the payload, DECODEs it (MBA), then INFLATEs it (zlib)
 *   4. writes the result to a temp .exe    (GetTempPath + GetTempFileName)
 *   5. runs it and waits                    (CreateProcess + WaitForSingleObject)
 *   6. deletes the temp file and forwards the child's exit code
 *
 * Build (MinGW):  gcc -O2 -Wall stub_win.c -o stub.exe -lz
 * Note: order matters -- put -lz AFTER the source file.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mathcrypt.h"
#include "miniz.h"

static const char MAGIC[8] = {'M','B','A','p','a','c','k','!'};
#define FOOTER_SIZE (8 + 8 + 8) /* orig_size + comp_size + magic */

static void die(const char *msg) {
    fprintf(stderr, "stub: %s (GetLastError=%lu)\n",
            msg, (unsigned long)GetLastError());
    exit(1);
}

int main(void) {
    /* --- 1. our own executable path ------------------------------------ */
    char self[MAX_PATH];
    DWORD sn = GetModuleFileNameA(NULL, self, sizeof(self));
    if (sn == 0 || sn >= sizeof(self)) die("GetModuleFileName failed");

    /* --- 2. open self and read footer ---------------------------------- */
    FILE *f = fopen(self, "rb");
    if (!f) die("cannot open self");

    if (fseek(f, 0, SEEK_END) != 0) die("seek end failed");
    long file_size = ftell(f);
    if (file_size < FOOTER_SIZE) die("file too small; not packed");

    uint8_t footer[FOOTER_SIZE];
    if (fseek(f, file_size - FOOTER_SIZE, SEEK_SET) != 0) die("seek footer failed");
    if (fread(footer, 1, FOOTER_SIZE, f) != FOOTER_SIZE) die("read footer failed");

    if (memcmp(footer + 16, MAGIC, 8) != 0)
        die("magic not found; this stub has no payload appended");

    uint64_t orig_size, comp_size;
    memcpy(&orig_size, footer + 0, 8);
    memcpy(&comp_size, footer + 8, 8);

    /* --- 3. read + decode + inflate ------------------------------------ */
    long payload_off = file_size - FOOTER_SIZE - (long)comp_size;
    if (payload_off < 0) die("bad payload offset");

    uint8_t *enc = (uint8_t *)malloc(comp_size ? (size_t)comp_size : 1);
    if (!enc) die("oom enc");
    if (fseek(f, payload_off, SEEK_SET) != 0) die("seek payload failed");
    if (fread(enc, 1, (size_t)comp_size, f) != (size_t)comp_size) die("read payload failed");
    fclose(f);

    decode_buf(enc, (size_t)comp_size);          /* undo affine cipher (MBA) */

    uint8_t *out = (uint8_t *)malloc(orig_size ? (size_t)orig_size : 1);
    if (!out) die("oom out");
    uLongf out_len = (uLongf)orig_size;
    if (uncompress(out, &out_len, enc, (uLong)comp_size) != Z_OK) die("uncompress failed");
    if (out_len != orig_size) die("size mismatch after inflate");
    free(enc);

    /* --- 4. write to a temp .exe --------------------------------------- */
    char tmp_dir[MAX_PATH];
    if (GetTempPathA(sizeof(tmp_dir), tmp_dir) == 0) die("GetTempPath failed");

    char tmp_file[MAX_PATH];
    /* uUnique=0 => make a unique name AND create the (empty) file. Ext is .tmp */
    if (GetTempFileNameA(tmp_dir, "MBA", 0, tmp_file) == 0) die("GetTempFileName failed");

    /* Windows really wants an .exe extension to run it cleanly. Rename .tmp -> .exe */
    char exe_file[MAX_PATH];
    strncpy(exe_file, tmp_file, sizeof(exe_file) - 1);
    exe_file[sizeof(exe_file) - 1] = '\0';
    size_t L = strlen(exe_file);
    if (L > 4 && _stricmp(exe_file + L - 4, ".tmp") == 0) {
        strcpy(exe_file + L - 4, ".exe");
        DeleteFileA(exe_file);                    /* in case it exists */
        if (!MoveFileA(tmp_file, exe_file)) {
            /* Fall back to the .tmp name if rename fails. */
            strcpy(exe_file, tmp_file);
        }
    }

    FILE *tf = fopen(exe_file, "wb");
    if (!tf) die("cannot open temp exe");
    if (fwrite(out, 1, (size_t)out_len, tf) != (size_t)out_len) die("write temp failed");
    fclose(tf);
    free(out);

    /* --- 5. run it and wait -------------------------------------------- */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* CreateProcess may modify the command-line buffer, so use a writable copy. */
    char cmdline[MAX_PATH + 2];
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_file);

    if (!CreateProcessA(exe_file, cmdline, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        die("CreateProcess failed");
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* --- 6. clean up --------------------------------------------------- */
    DeleteFileA(exe_file);   /* best effort; may fail if AV holds a lock */

    return (int)code;
}
