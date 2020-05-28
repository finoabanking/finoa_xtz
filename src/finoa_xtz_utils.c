
#ifdef DEFAULT_CONFIG

#include <finoa_xtz_config.h>

int openssl_sign_oneshot( uint8_t **signature, size_t *len_signature, const uint8_t *msg, size_t len_msg, const uint8_t *private_key, size_t len_private_key ) {
    EVP_PKEY* ed25519 = EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, private_key, len_private_key);
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_DigestSignInit( md_ctx, NULL, NULL, NULL, ed25519 );
    EVP_DigestSign( md_ctx, NULL, len_signature, msg, len_msg );

    *signature = (uint8_t*)FIN_XTZ_MALLOC( *len_signature );
    if ( *signature == NULL ) {
        return -1;
    }

    EVP_DigestSign( md_ctx, *signature, len_signature, msg, len_msg );

    EVP_MD_CTX_free( md_ctx );
    EVP_PKEY_free( ed25519 );

    return 0;
}

void zarith_encode_number( uint8_t *number, uint8_t **result, size_t *size ) {

    uint8_t buffer[100];
    memset( buffer, 0, 100 );
    *size = 0;

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *nn = BN_new();
    BIGNUM *checkValue = BN_new();
    BIGNUM *b = BN_new();

    uint8_t *pResult = buffer;

    if ( BN_dec2bn( &checkValue, "128" ) == 0 ) {
        return;
    }

    if ( BN_hex2bn( &nn, (char*)number ) == 0 ) {
        return;
    }

    while( true ) {
        if ( BN_cmp( nn, checkValue ) == -1 ) {
            BN_bn2bin( nn, pResult );
            (*size)++;
            break;
        } else {
            BN_nnmod( b, nn, checkValue, ctx );
            BN_sub( nn, nn, b );
            BN_div( nn, NULL, nn, checkValue, ctx );
            BN_add( b, b, checkValue );
            BN_bn2bin( b, pResult);
            pResult++;
            (*size)++;
        }
    }

    BN_free( nn );
    BN_free( b );
    BN_CTX_free( ctx );

    *result = (uint8_t*)FIN_XTZ_MALLOC(*size);
    if ( NULL != *result ) {
        FIN_XTZ_MEMCPY( *result, buffer, *size );
    } else {
        *size = 0;
    }

}

#endif