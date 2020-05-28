
#ifndef FINOA_XTZ_FINOA_XTZ_CONFIG_H
#define FINOA_XTZ_FINOA_XTZ_CONFIG_H

#define FIN_XTZ_MAGIC_ED25519_KEY "\x06\xA1\x9F"
#define FIN_XTZ_MAGIC_SIG         "\x09\xF5\xCD\x86\x12"

#define FIN_XTZ_SIZE_ADDRESS                36
#define FIN_XTZ_SIZE_BRANCH                 32
#define FIN_XTZ_SIZE_ED25519_PUBKEY         32
#define FIN_XTZ_SIZE_ED25519_SIGNATURE      64
#define FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY    20
#define FIN_XTZ_SIZE_BLAKE2B_HASH           32

#define FIN_XTZ_SIZE_TAG_TXN                1
#define FIN_XTZ_SIZE_TAG_ED25519_PUBKEY     1
#define FIN_XTZ_SIZE_TAG_CONTRACT_ID        1

#define FIN_XTZ_TAG_TXN                     0x6C
#define FIN_XTZ_TAG_ED25519_PUBKEY          0x00
#define FIN_XTZ_TAG_CONTRACT_ID             0x00
#define FIN_XTZ_TXN_HASH_PREFIX             0x03

#ifdef DEFAULT_CONFIG
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <BLAKE2/sse/blake2.h>
#include <sha-2/sha-256.h>
#include <libbase58/libbase58.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

int openssl_sign_oneshot( uint8_t **signature, size_t *len_signature, const uint8_t *msg, size_t len_msg, const uint8_t *private_key, size_t len_private_key );
void zarith_encode_number( uint8_t *number, uint8_t **result, size_t *size );

#define FIN_XTZ_MALLOC(x) malloc(x)
#define FIN_XTZ_FREE(x) free(x)
#define FIN_XTZ_MEMCPY(dst, src, len) memcpy(dst, src, len)
#define FIN_XTZ_SIGN( sig, lsig, msg, lmsg, pk, lpk ) openssl_sign_oneshot( sig, lsig, msg, lmsg, pk, lpk )
#define FIN_XTZ_BLAKE2B( a, b, c, d, e, f ) blake2b( a, b, c, d, e, f )
#define FIN_XTZ_BASE58( a, b, c, d ) b58enc( a, b, c, d )
#define FIN_XTZ_SHA256( h, i, il ) calc_sha_256( h, i, il )
#define FIN_XTZ_ZARITH_NUMBER( in, out, lout ) zarith_encode_number( in, out, lout )

#else

#define FIN_XTZ_MALLOC(x) malloc(x)
#define FIN_XTZ_FREE(x) free(x)
#define FIN_XTZ_MEMCPY(dst, src, len) memcpy(dst, src, len)

#define FIN_XTZ_SIGN( sig, lsig, msg, lmsg, pk )
#define FIN_XTZ_BLAKE2B( a, b, c, d, e, f )
#define FIN_XTZ_BASE58( a, b, c, d )
#define FIN_XTZ_SHA256( h, i, il )

#endif      // DEFAULT_CONFIG

#endif //FINOA_XTZ_FINOA_XTZ_CONFIG_H
