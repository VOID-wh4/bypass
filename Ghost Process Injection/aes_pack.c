#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#include "stage1_aes_key.h"

#define AES_PACKAGE_HEADER_SIZE 56
#define AES_PACKAGE_NONCE_SIZE 12
#define AES_PACKAGE_TAG_SIZE 16
#define AES_PACKAGE_ALGORITHM_GCM 1

#pragma comment(lib, "bcrypt.lib")

static void PutU16Le(unsigned char* value, uint16_t number) {
    value[0] = (unsigned char)(number & 0xff);
    value[1] = (unsigned char)((number >> 8) & 0xff);
}

static void PutU64Le(unsigned char* value, uint64_t number) {
    for (unsigned int index = 0; index < 8; ++index) {
        value[index] = (unsigned char)((number >> (index * 8)) & 0xff);
    }
}

static int OutputExists(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return 0;
    }
    fclose(file);
    return 1;
}

static int ReadInput(
    const char* path,
    unsigned char** contents,
    size_t* contentsSize
) {
    FILE* file = NULL;
    long fileSize = 0;
    unsigned char* buffer = NULL;
    int success = 0;

    *contents = NULL;
    *contentsSize = 0;
    file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "input open failed: %s: %s\n", path, strerror(errno));
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0 ||
        (fileSize = ftell(file)) <= 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "input size failed: %s\n", path);
        goto cleanup;
    }

    buffer = (unsigned char*)malloc((size_t)fileSize);
    if (!buffer) {
        fprintf(stderr, "input allocation failed: %ld bytes\n", fileSize);
        goto cleanup;
    }
    if (fread(buffer, 1, (size_t)fileSize, file) != (size_t)fileSize) {
        fprintf(stderr, "input read failed: %s\n", path);
        goto cleanup;
    }

    *contents = buffer;
    *contentsSize = (size_t)fileSize;
    buffer = NULL;
    success = 1;

cleanup:
    if (buffer) {
        SecureZeroMemory(buffer, (size_t)fileSize);
        free(buffer);
    }
    fclose(file);
    return success;
}

static int EncryptAesGcm(
    const unsigned char* plain,
    size_t plainSize,
    unsigned char* nonce,
    unsigned char* tag,
    unsigned char** cipher,
    size_t* cipherSize
) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    unsigned char* keyObject = NULL;
    unsigned char* output = NULL;
    DWORD keyObjectSize = 0;
    DWORD propertySize = 0;
    ULONG resultSize = 0;
    NTSTATUS status = 0;
    int success = 0;

    *cipher = NULL;
    *cipherSize = 0;
    status = BCryptGenRandom(
        NULL,
        nonce,
        AES_PACKAGE_NONCE_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        fprintf(stderr, "BCryptGenRandom failed: 0x%08lX\n",
            (unsigned long)status);
        return 0;
    }
    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (status < 0) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }
    status = BCryptSetProperty(
        algorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (status < 0) {
        fprintf(stderr, "BCryptSetProperty(GCM) failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjectSize,
        sizeof(keyObjectSize),
        &propertySize,
        0);
    if (status < 0 || propertySize != sizeof(keyObjectSize) ||
        keyObjectSize == 0) {
        fprintf(stderr, "BCryptGetProperty failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }

    keyObject = (unsigned char*)malloc(keyObjectSize);
    output = (unsigned char*)malloc(plainSize);
    if (!keyObject || !output) {
        fprintf(stderr, "AES allocation failed.\n");
        goto cleanup;
    }
    status = BCryptGenerateSymmetricKey(
        algorithm,
        &key,
        keyObject,
        keyObjectSize,
        (PUCHAR)STAGE1_AES_KEY,
        STAGE1_AES_KEY_SIZE,
        0);
    if (status < 0) {
        fprintf(stderr, "BCryptGenerateSymmetricKey failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = AES_PACKAGE_NONCE_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = AES_PACKAGE_TAG_SIZE;
    status = BCryptEncrypt(
        key,
        (PUCHAR)plain,
        (ULONG)plainSize,
        &authInfo,
        NULL,
        0,
        output,
        (ULONG)plainSize,
        &resultSize,
        0);
    if (status < 0 || resultSize != (ULONG)plainSize) {
        fprintf(stderr, "BCryptEncrypt failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }

    *cipher = output;
    *cipherSize = resultSize;
    output = NULL;
    success = 1;

cleanup:
    if (key) {
        BCryptDestroyKey(key);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (keyObject) {
        SecureZeroMemory(keyObject, keyObjectSize);
        free(keyObject);
    }
    if (output) {
        SecureZeroMemory(output, plainSize);
        free(output);
    }
    return success;
}

static int WritePackage(
    const char* path,
    const unsigned char* cipher,
    size_t cipherSize,
    size_t plainSize,
    const unsigned char* nonce,
    const unsigned char* tag
) {
    unsigned char header[AES_PACKAGE_HEADER_SIZE] = { 0 };
    FILE* file = NULL;
    int success = 0;

    memcpy(header, "BAES", 4);
    header[4] = 1;
    header[5] = AES_PACKAGE_ALGORITHM_GCM;
    PutU16Le(header + 6, 0);
    PutU64Le(header + 8, (uint64_t)plainSize);
    PutU64Le(header + 16, (uint64_t)cipherSize);
    memcpy(header + 24, nonce, AES_PACKAGE_NONCE_SIZE);
    memcpy(header + 36, tag, AES_PACKAGE_TAG_SIZE);

    file = fopen(path, "wb");
    if (!file) {
        fprintf(stderr, "output open failed: %s: %s\n", path, strerror(errno));
        return 0;
    }
    if (fwrite(header, 1, sizeof(header), file) != sizeof(header) ||
        fwrite(cipher, 1, cipherSize, file) != cipherSize) {
        fprintf(stderr, "output write failed: %s\n", path);
        goto cleanup;
    }
    if (fclose(file) != 0) {
        file = NULL;
        fprintf(stderr, "output close failed: %s\n", path);
        goto cleanup;
    }
    file = NULL;
    success = 1;

cleanup:
    if (file) {
        fclose(file);
    }
    if (!success) {
        remove(path);
    }
    return success;
}

static void Usage(const char* executable) {
    fprintf(stderr, "usage: %s <input> <output.baes>\n", executable);
}

int main(int argc, char** argv) {
    unsigned char* plain = NULL;
    unsigned char* cipher = NULL;
    unsigned char nonce[AES_PACKAGE_NONCE_SIZE] = { 0 };
    unsigned char tag[AES_PACKAGE_TAG_SIZE] = { 0 };
    size_t plainSize = 0;
    size_t cipherSize = 0;
    int result = 1;

    if (argc != 3) {
        Usage(argv[0]);
        return 2;
    }
    if (OutputExists(argv[2])) {
        fprintf(stderr, "output already exists, refusing to overwrite: %s\n",
            argv[2]);
        return 1;
    }
    if (!ReadInput(argv[1], &plain, &plainSize) ||
        !EncryptAesGcm(
            plain,
            plainSize,
            nonce,
            tag,
            &cipher,
            &cipherSize) ||
        !WritePackage(
            argv[2],
            cipher,
            cipherSize,
            plainSize,
            nonce,
            tag)) {
        goto cleanup;
    }

    printf("[+] AES-256-GCM package: %s -> %s\n", argv[1], argv[2]);
    printf("[+] plain size: %zu byte(s)\n", plainSize);
    result = 0;

cleanup:
    SecureZeroMemory(nonce, sizeof(nonce));
    SecureZeroMemory(tag, sizeof(tag));
    if (plain) {
        SecureZeroMemory(plain, plainSize);
        free(plain);
    }
    if (cipher) {
        SecureZeroMemory(cipher, cipherSize);
        free(cipher);
    }
    return result;
}
