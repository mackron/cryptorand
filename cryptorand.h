/*
Cryptographically Secure Pseudo-Random Number Generator. Choice of public domain or MIT-0. See license statements at the end of this file.

David Reid - mackron@gmail.com
*/

/*
This uses the operating system's random number generation. If you're looking for a CSPRNG from
scratch you'll need to look elsewhere.

Supported generation methods are Win32's BCryptGenRandom() with CryptGenRandom() as a fallback. On
Linux, /dev/urandom is used. Currently only Windows and Linux are supported. If you are aware of
other platforms that support /dev/urandom, let me know and I'll add support.

There is no need to link to anything with this library. You can use CRYPTORAND_IMPLEMENTATION to
define the implementation section, or you can use cryptorand.c if you prefer a traditional
header/source pair.

There's only three functions, all of which should be self explanatory and easy to figure out:

    ```
    cryptorand_result cryptorand_init(cryptorand* pRNG);
    void cryptorand_uninit(cryptorand* pRNG);
    cryptorand_result cryptorand_generate(cryptorand* pRNG, void* pBufferOut, size_t bufferSizeInBytes);
    ```

Call `cryptorand_init()` to initialize the random number generator. On Windows, this is where
libraries are linked at runtime so avoid calling this in high performance scenarios. It's best to
just create one instance and then read from it multiple times.

To generate random bytes you need only call `cryptorand_generate()`. You just specify a pointer to
a buffer that will receive the random data and the number of bytes you want. If this fails, the
content of the buffer will be cleared to zero.

Uninitialize the random number generator with `cryptorand_uninit()`.

Thread safety depends on the backend.
*/

#ifndef cryptorand_h
#define cryptorand_h

#if defined(_WIN32)
    #define CRYPTORAND_WIN32
#endif

/* At the moment only supporting urandom() with Linux, but if other platforms support they can be added to the list. */
#if defined(__linux__)
    #define CRYPTORAND_URANDOM
#endif

#include <stddef.h> /* For size_t. */

typedef enum
{
    CRYPTORAND_SUCCESS           =  0,
    CRYPTORAND_ERROR             = -1,
    CRYPTORAND_INVALID_ARGS      = -2,
    CRYPTORAND_INVALID_OPERATION = -3,
    CRYPTORAND_TOO_BIG           = -11,
    CRYPTORAND_NOT_IMPLEMENTED   = -29
} cryptorand_result;

typedef void (* cryptorand_proc)(void);

typedef struct
{
#if defined(CRYPTORAND_WIN32)
    struct
    {
        void* hBcryptDLL;   /* If set, using BCryptGenRandom() */
        cryptorand_proc BCryptOpenAlgorithmProvider;
        cryptorand_proc BCryptCloseAlgorithmProvider;
        cryptorand_proc BCryptGenRandom;
        void* hAlgorithm;   /* Used with BCryptGenRandom() */

        void* hAdvapiDLL;   /* If set, using CryptGenRandom() */
        cryptorand_proc CryptAcquireContextW;
        cryptorand_proc CryptReleaseContext;
        cryptorand_proc CryptGenRandom;
        void* hProvider;    /* Used with CryptGenRandom() */
    } win32;
#endif
#if defined(CRYPTORAND_URANDOM)
    struct
    {
        /*FILE**/ void* pFile;  /* The file handle returned by open(). */
    } urandom;
#endif
} cryptorand;

cryptorand_result cryptorand_init(cryptorand* pRNG);
void cryptorand_uninit(cryptorand* pRNG);
cryptorand_result cryptorand_generate(cryptorand* pRNG, void* pBufferOut, size_t bufferSizeInBytes);

#endif  /* cryptorand_h */

#if defined(CRYPTORAND_IMPLEMENTATION)
#ifndef cryptorand_c
#define cryptorand_c

#include <string.h>
#define CRYPTORAND_ZERO_MEMORY(p, sz)      memset((p), 0, (sz))
#define CRYPTORAND_ZERO_OBJECT(o)          CRYPTORAND_ZERO_MEMORY((o), sizeof(*o))

#if defined(CRYPTORAND_WIN32)
#include <windows.h>    /* For LoadLibrary(). */

typedef LONG (WINAPI * CRYPTORAND_PFN_BCryptOpenAlgorithmProvider)(void** phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
typedef LONG (WINAPI * CRYPTORAND_PFN_BCryptCloseAlgorithmProvider)(void* hAlgorithm, ULONG dwFlags);
typedef LONG (WINAPI * CRYPTORAND_PFN_BCryptGenRandom)(void* hAlgorithm, unsigned char* pbBuffer, ULONG cbBuffer, ULONG dwFlags);

#define CRYPTORAND_BCRYPT_RNG_ALGORITHM L"RNG"


typedef BOOL (WINAPI * CRYPTORAND_PFN_CryptAcquireContextW)(void** phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL (WINAPI * CRYPTORAND_PFN_CryptReleaseContext)(void* hProv, DWORD dwFlags);
typedef BOOL (WINAPI * CRYPTORAND_PFN_CryptGenRandom)(void* hProv, DWORD dwLen, BYTE* pbBuffer);

#define CRYPTORAND_PROV_RSA_FULL        1
#define CRYPTORAND_CRYPT_VERIFYCONTEXT  0xF0000000
#define CRYPTORAND_CRYPT_SILENT         0x00000040

static cryptorand_result cryptorand_init__win32(cryptorand* pRNG)
{
    /*
    We first need to try using BCrypt which is the most modern version. If this fails it might mean
    we're running on Windows XP in which case we'll fall back to CryptGenRandom().
    */
    CRYPTORAND_ZERO_OBJECT(&pRNG->win32);   /* For safety. */
    {
        HANDLE hBcryptDLL;

        hBcryptDLL = LoadLibraryW(L"bcrypt.dll");
        if (hBcryptDLL != NULL) {
            pRNG->win32.hBcryptDLL                   = (void*)hBcryptDLL;
            pRNG->win32.BCryptOpenAlgorithmProvider  = (cryptorand_proc)GetProcAddress(hBcryptDLL, "BCryptOpenAlgorithmProvider");
            pRNG->win32.BCryptCloseAlgorithmProvider = (cryptorand_proc)GetProcAddress(hBcryptDLL, "BCryptCloseAlgorithmProvider");
            pRNG->win32.BCryptGenRandom              = (cryptorand_proc)GetProcAddress(hBcryptDLL, "BCryptGenRandom");

            if (pRNG->win32.BCryptOpenAlgorithmProvider != NULL && pRNG->win32.BCryptCloseAlgorithmProvider != NULL && pRNG->win32.BCryptGenRandom != NULL) {
                if (((CRYPTORAND_PFN_BCryptOpenAlgorithmProvider)pRNG->win32.BCryptOpenAlgorithmProvider)(&pRNG->win32.hAlgorithm, CRYPTORAND_BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
                    return CRYPTORAND_SUCCESS;
                } else {
                    /* Failed to open provider. */
                }
            } else {
                /* Failed to retrieve function addresses.*/
            }
        } else {
            /* Failed to load DLL. */
        }
    }


    /* Getting here means we're falling back to the old method. */
    CRYPTORAND_ZERO_OBJECT(&pRNG->win32);   /* For safety. */
    {
        HANDLE hAdvapiDLL;

        hAdvapiDLL = LoadLibraryW(L"advapi32.dll");
        if (hAdvapiDLL != NULL) {
            pRNG->win32.hAdvapiDLL           = (void*)hAdvapiDLL;
            pRNG->win32.CryptAcquireContextW = (cryptorand_proc)GetProcAddress(hAdvapiDLL, "CryptAcquireContextW");
            pRNG->win32.CryptReleaseContext  = (cryptorand_proc)GetProcAddress(hAdvapiDLL, "CryptReleaseContext");
            pRNG->win32.CryptGenRandom       = (cryptorand_proc)GetProcAddress(hAdvapiDLL, "CryptGenRandom");

            if (pRNG->win32.CryptAcquireContextW != NULL && pRNG->win32.CryptReleaseContext != NULL && pRNG->win32.CryptGenRandom != NULL) {
                if (((CRYPTORAND_PFN_CryptAcquireContextW)pRNG->win32.CryptAcquireContextW)(&pRNG->win32.hProvider, NULL, NULL, CRYPTORAND_PROV_RSA_FULL, CRYPTORAND_CRYPT_VERIFYCONTEXT | CRYPTORAND_CRYPT_SILENT)) {
                    return CRYPTORAND_SUCCESS;
                } else {
                    /* Failed to acquire context. */
                }
            } else {
                /* Failed to retrieve function addresses.*/
            }
        } else {
            /* Failed to load DLL. */
        }
    }


    /* Getting here means both BCryptGenRandom() and CryptGenRandom() are unusable. */
    CRYPTORAND_ZERO_OBJECT(&pRNG->win32);
    return CRYPTORAND_ERROR;
}

static void cryptorand_uninit__win32(cryptorand* pRNG)
{
    if (pRNG->win32.hAlgorithm != NULL) {
        ((CRYPTORAND_PFN_BCryptCloseAlgorithmProvider)pRNG->win32.BCryptCloseAlgorithmProvider)(pRNG->win32.hAlgorithm, 0);
    } else if (pRNG->win32.hProvider != NULL) {
        ((CRYPTORAND_PFN_CryptReleaseContext)pRNG->win32.CryptReleaseContext)(pRNG->win32.hProvider, 0);
    }

    if (pRNG->win32.hBcryptDLL != NULL) {
        FreeLibrary((HANDLE)pRNG->win32.hBcryptDLL);
    }
    if (pRNG->win32.hAdvapiDLL != NULL) {
        FreeLibrary((HANDLE)pRNG->win32.hAdvapiDLL);
    }
}

static cryptorand_result cryptorand_generate__win32(cryptorand* pRNG, void* pBufferOut, size_t byteCount)
{
    if (byteCount > 0xFFFFFFFF) {
        return CRYPTORAND_TOO_BIG;  /* TODO: Maybe handle this better by running in a loop. */
    }

    if (pRNG->win32.hAlgorithm != NULL) {
        LONG result = ((CRYPTORAND_PFN_BCryptGenRandom)pRNG->win32.BCryptGenRandom)(pRNG->win32.hAlgorithm, pBufferOut, (ULONG)byteCount, 0);
        if (result != 0) {
            return CRYPTORAND_ERROR;
        }
    } else if (pRNG->win32.hProvider != NULL) {
        if (!((CRYPTORAND_PFN_CryptGenRandom)pRNG->win32.CryptGenRandom)(pRNG->win32.hProvider, (DWORD)byteCount, pBufferOut)) {
            return CRYPTORAND_ERROR;
        }
    }

    return CRYPTORAND_SUCCESS;
}
#endif

#if defined(CRYPTORAND_URANDOM)
#include <stdio.h>

static cryptorand_result cryptorand_init__urandom(cryptorand* pRNG)
{
    pRNG->urandom.pFile = fopen("/dev/urandom", "rb");
    if (pRNG->urandom.pFile == NULL) {
        return CRYPTORAND_ERROR;
    }

    return CRYPTORAND_SUCCESS;
}

static void cryptorand_uninit__urandom(cryptorand* pRNG)
{
    if (pRNG->urandom.pFile == NULL) {
        return;
    }

    fclose((FILE*)pRNG->urandom.pFile);
}

static cryptorand_result cryptorand_generate__urandom(cryptorand* pRNG, void* pBufferOut, size_t byteCount)
{
    size_t bytesRead;

    if (pRNG->urandom.pFile == NULL) {
        return CRYPTORAND_INVALID_OPERATION;
    }

    bytesRead = fread(pBufferOut, 1, byteCount, (FILE*)pRNG->urandom.pFile);
    if (bytesRead < byteCount) {
        return CRYPTORAND_ERROR;    /* Wasn't able to read all the data. Should never happen. */
    }

    return CRYPTORAND_SUCCESS;
}
#endif


cryptorand_result cryptorand_init(cryptorand* pRNG)
{
    cryptorand_result result;

    if (pRNG == NULL) {
        return CRYPTORAND_INVALID_ARGS;
    }

    CRYPTORAND_ZERO_OBJECT(pRNG);

#if defined(CRYPTORAND_WIN32)
    result = cryptorand_init__win32(pRNG);
#elif defined(CRYPTORAND_URANDOM)
    result = cryptorand_init__urandom(pRNG);
#else
    result = CRYPTORAND_NOT_IMPLEMENTED;
#endif

    if (result != CRYPTORAND_SUCCESS) {
        CRYPTORAND_ZERO_OBJECT(pRNG);   /* Make sure the caller is given a blank object on failure. */
    }

    return result;
}

void cryptorand_uninit(cryptorand* pRNG)
{
    if (pRNG == NULL) {
        return;
    }

#if defined(CRYPTORAND_WIN32)
    cryptorand_uninit__win32(pRNG);
#elif defined(CRYPTORAND_URANDOM)
    cryptorand_uninit__urandom(pRNG);
#else
    /* Not implemented. */
#endif

    CRYPTORAND_ZERO_OBJECT(pRNG);
}

cryptorand_result cryptorand_generate(cryptorand* pRNG, void* pBufferOut, size_t byteCount)
{
    cryptorand_result result;

    if (pRNG == NULL || pBufferOut == NULL) {
        return CRYPTORAND_INVALID_ARGS;
    }

#if defined(CRYPTORAND_WIN32)
    result = cryptorand_generate__win32(pRNG, pBufferOut, byteCount);
#elif defined(CRYPTORAND_URANDOM)
    result = cryptorand_generate__urandom(pRNG, pBufferOut, byteCount);
#else
    result = CRYPTORAND_NOT_IMPLEMENTED;
#endif

    /*
    If an error occurred, make sure everything is cleared to zero to make it clear to the caller that
    the content in the buffer is not valid.
    */
    if (result != CRYPTORAND_SUCCESS) {
        CRYPTORAND_ZERO_MEMORY(pBufferOut, byteCount);
    }

    return result;
}

#endif  /* cryptorand_c */
#endif  /* CRYPTORAND_IMPLEMENTATION */

/*
This software is available as a choice of the following licenses. Choose
whichever you prefer.

===============================================================================
ALTERNATIVE 1 - Public Domain (www.unlicense.org)
===============================================================================
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>

===============================================================================
ALTERNATIVE 2 - MIT No Attribution
===============================================================================
Copyright 2022 David Reid

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
