# FINOA XTZ LIBRARY

## Prerequisites
To use the library with its default configuration, <code>openssl 1.1.1g</code> needs to be installed on the system. 
Maybe later versions of will work too, but that has not been tested until the time of writing. 

## Quickstart

Clone the repository.
```
git submodule init
git submodule update
cmake .
make
```

Run unit tests:
```
./bin/finoa_xtz_tests
```

## MACRO Setup
When using _finoa_xtz_'s default configuration, everything is nicely setup for you.

If you wish to replace the default MACROS, feel free to do so. Find below a list of the supported MACROS
with their corresponding signatures, that needs to be implemented.

`FIN_XTZ_MALLOC(x)` 
- `x`: takes a number as argument and returns some allocated buffer

`FIN_XTZ_FREE(x)` 
- `x`: takes a `uint8_t*` pointer to memory allocated on the heap and frees it 

`FIN_XTZ_MEMCPY(dst, src, len)`
- `dst`: a `uint8_t*` pointer to the location where `src` shall be copied to
- `src`: a `uint8_t*` pointer to the location where the data shall be copied from
- `len`: `size_t` length of the data to be copied

`FIN_XTZ_SIGN(sig, lsig, msg, lmsg, pk, lpk)`
- `sig`: a `uint8_t**` to the place where the signature is being stored. 
    **The memory needs to be allocated by the function**
- `lsig`: `size_t*` containing the length of the allocated memory for the signature  
- `msg`: a `const uint8_t*` containing the input for the Ed25519 signature
- `lmsg`: `size_t` length of the input data
- `pk`: `const uint8_t*` to the Ed25519 private key
- `lpk`: `size_t` length of the private key in bytes

`FIN_XTZ_BLAKE2B( a, b, c, d, e, f )`
- `a`: `uint8_t *` pointer to the hash output
- `b`: `size_t` containing the length of the hash to calculated
- `c`: `const uint8_t *` containing the input data
- `d`: `size_t` containing the length of the input data
- `e`: `const uint8_t *` containing a key to be used while hashing (may be NULL)
- `f`: `size_t` length of the key to use (may be zero)


`FIN_XTZ_BASE58( a, b, c, d )`
- `a`: `uint8_t *` pointer to the encoded result
- `b`: `size_t *` pointer containing the length of the encoded data output
- `c`: `const uint8_t *` pointer to the data to be encoded
- `d`: `size_t` containing the length of the data

`FIN_XTZ_SHA256( h, i, il )`
- `h`: `uint8_t *` pointer to the resulting hash. **Memory needs to be allocated by the caller** 
- `i`: `uint8_t *` pointer to the data to be hashed
- `il`: `size_t` containing the length of the data to be hashed

`FIN_XTZ_ZARITH_NUMBER(in, out, lout)`
- `in`: `uint8_t*` containing the hexadecimal representation of the number to be encoded as ZArith
- `out`: `uint8_t**` pointer to a pointer where the encoded result is being stored. **Memory needs to be allocated by the function**
- `lout`: `size_t *` pointer containing the length of the encoded data