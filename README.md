<h4 align="center">Cryptographically Secure Pseudo-Random Number Generator.</h4>

<p align="center">
    <a href="https://discord.gg/9vpqbjU"><img src="https://img.shields.io/discord/712952679415939085?label=discord&logo=discord" alt="discord"></a>
    <a href="https://twitter.com/mackron"><img src="https://img.shields.io/twitter/follow/mackron?style=flat&label=twitter&color=1da1f2&logo=twitter" alt="twitter"></a>
</p>

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