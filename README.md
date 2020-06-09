# FINOA XTZ LIBRARY

## Purpose of the library
The `finoa_xtz` library is designed to 
- generate a XTZ address based on a given public key
- create and sign a XTZ transaction without interacting with the XTZ node and to
- calculate the ZArith encoded values needed by XTZ

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

## How to use the library
There are three main functions that can be used to interact with
1. `FIN_XTZ_ZARITH_NUMBER` which converts a hexadecimal number into ZArith encoding. The default implementation will 
calculate the ZArith encoding by using OpenSSL's BigNumber mechanism.
1. `generate_xtz_address` which will generate the Base58 encoded XTZ address needed to identify your account within the 
blockchain
1. `xtz_sign_transaction` which will serialize a given transaction structure and sign it with a given private key

### Generating a XTZ address from a given public key
Given a Ed25519 public key you are able to generate the corresponding XTZ address by using the `generate_xtz_address` function.

Example:
```c
uint8_t *ed25519_pub_key = {...};

int retVal;
uint8_t *address = NULL;
size_t len_address = 0;

retVal = generate_xtz_address(&address, &len_address, ed25519_pub_key, FIN_XTZ_SIZE_ED25519_PUBKEY )
```
The result is then a zero terminated string of the Base58 encoded XTZ address.

### Transaction Structure
A transaction is being described by the following structure:
```c
struct fin_xtz_txn {
     // These lengths are fixed
     uint8_t branch[32];
     uint8_t source[20];
     uint8_t destination[20];

     // These values are all ZArith encoded
     uint8_t *gas_limit;
     size_t   len_gas_limit;
     uint8_t *storage_limit;
     size_t   len_storage_limit;
     uint8_t *fee;
     size_t   len_fee;
     uint8_t *counter;
     size_t   len_counter;
     uint8_t *amount;
     size_t   len_amount;
 };
```
To setup a transaction you can do something like the following:
```c
fin_xtz_txn txn{};
FIN_XTZ_MEMCPY( txn.branch, branch, FIN_XTZ_SIZE_BRANCH );
FIN_XTZ_MEMCPY( txn.source, source, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );
FIN_XTZ_MEMCPY( txn.destination, destination, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );

FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"C350", &txn.fee, &txn.len_fee );
FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"C8", &txn.gas_limit, &txn.len_gas_limit );
FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"03", &txn.counter, &txn.len_counter );
FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"00", &txn.storage_limit, &txn.len_storage_limit );
FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"05F5E100", &txn.amount, &txn.len_amount );
```

The transaction then goes into the `xtz_sign_transaction` function as the first parameter.
Memory for the calculated signature is being allocated by the function and needs to be freed by the caller.

```c
uint8_t *txnAndSignature = nullptr;
size_t lenBin = 0;
int retVal;

retVal = xtz_sign_transaction(&txn, &txnAndSignature, &lenBin, private_key_for_signature, len_priv_key);
```

### ZArith encoding
To encoded a number to ZArith encoding, one needs to pass the number as a `uint8_t*` in hexadecimal representation.
The number 50'000 would therefore be given as `0xC350`.
Memory for the result is being allocated by the function and needs to be freed by the caller.

Example:
```c
uint8_t *number = NULL;
size_t len_number = 0;

FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"C350", &number, &len_number );
```
If you wish to modify or exchange the functions doing the work under the hood, see the following section.

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
