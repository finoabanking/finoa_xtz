
#include "finoa_xtz.h"

int generate_xtz_address( uint8_t **address, size_t *len_address, uint8_t *ed25519_pk, size_t len_pk ) {

    int error = 0;
    uint8_t *blake2bHash = NULL;
    uint8_t shaHash[32];
    uint8_t *shaInput = NULL;
    uint8_t *b58Input = NULL;

    // This size is fixed: XTZ addresses are always 36 bytes long plus 1 byte for a NULL termination
    *address = FIN_XTZ_MALLOC( FIN_XTZ_SIZE_ADDRESS + 1 );
    if ( NULL == *address ) {
        error = -1;
        goto cleanup;
    }
    *len_address = FIN_XTZ_SIZE_ADDRESS + 1;

    blake2bHash = FIN_XTZ_MALLOC(FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY);
    if ( NULL == blake2bHash ) {
        error = -1;
        goto cleanup;
    }
    FIN_XTZ_BLAKE2B( blake2bHash, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY, ed25519_pk, len_pk, NULL, 0 );

    shaInput = FIN_XTZ_MALLOC(23);
    if ( NULL == shaInput ) {
        error = -1;
        goto cleanup;
    }
    FIN_XTZ_MEMCPY(shaInput, FIN_XTZ_MAGIC_ED25519_KEY, 3 );
    FIN_XTZ_MEMCPY( shaInput+3, blake2bHash, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );
    // Double Hash the Hash :-S
    FIN_XTZ_SHA256( shaHash, shaInput, 23 );
    FIN_XTZ_SHA256( shaHash, shaHash, 32 );

    b58Input = FIN_XTZ_MALLOC( 30 );
    if ( NULL == b58Input ) {
        error = -1;
        goto cleanup;
    }

    FIN_XTZ_MEMCPY(b58Input, FIN_XTZ_MAGIC_ED25519_KEY, 3 );
    FIN_XTZ_MEMCPY( b58Input+3, blake2bHash, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );
    FIN_XTZ_MEMCPY( b58Input+23, shaHash, 4 );

    // Now calculate the Base58-Check-Encoding of the concatenation of the magic number + the blake hash + first four bytes of the shaHash
    if ( FIN_XTZ_BASE58( (char*)(*address), len_address, b58Input, 27 ) == 0 ) {
        error = -1;
    }

cleanup:
    if ( NULL != shaInput ) {
        FIN_XTZ_FREE(shaInput);
    }
    if ( NULL != blake2bHash ) {
        FIN_XTZ_FREE(blake2bHash);
    }
    if ( NULL != b58Input ) {
        FIN_XTZ_FREE(b58Input);
    }

    return error;
}

int xtz_sign_transaction(struct fin_xtz_txn *txn, uint8_t **bin_out, size_t *len_bin_out, uint8_t const *priv_key, size_t len_priv_key) {

    int error;
    size_t bin_txn_len = 0;
    uint8_t *bin_txn = NULL, *hash_input = NULL;
    size_t offset = 0;
    uint8_t txn_hash[FIN_XTZ_SIZE_BLAKE2B_HASH];
    uint8_t txn_prefix = FIN_XTZ_TXN_HASH_PREFIX;
    uint8_t *signature = NULL;
    size_t len_signature = 0;

    bin_txn_len += FIN_XTZ_SIZE_BRANCH;                 // Branch
    bin_txn_len += FIN_XTZ_SIZE_TAG_TXN;                // TAG 108
    bin_txn_len += FIN_XTZ_SIZE_TAG_ED25519_PUBKEY;     // TAG 00
    bin_txn_len += FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY;    // 20 bytes blake2b hash
    bin_txn_len += txn->len_fee;
    bin_txn_len += txn->len_counter;
    bin_txn_len += txn->len_gas_limit;
    bin_txn_len += txn->len_storage_limit;
    bin_txn_len += txn->len_amount;
    bin_txn_len += FIN_XTZ_SIZE_TAG_CONTRACT_ID;
    bin_txn_len += FIN_XTZ_SIZE_TAG_ED25519_PUBKEY;
    bin_txn_len += FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY;
    bin_txn_len += 1;                                   // 1 byte for parameters, which is currently always zero

    bin_txn = FIN_XTZ_MALLOC( bin_txn_len );
    if ( NULL == bin_txn ) {
        error = -1;
        goto cleanup;
    }

    FIN_XTZ_MEMCPY( bin_txn, txn->branch, FIN_XTZ_SIZE_BRANCH );
    offset += FIN_XTZ_SIZE_BRANCH;

    bin_txn[offset++] = FIN_XTZ_TAG_TXN;

    bin_txn[offset++] = FIN_XTZ_TAG_ED25519_PUBKEY;
    FIN_XTZ_MEMCPY( bin_txn + offset, txn->source, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );
    offset += FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY;

    FIN_XTZ_MEMCPY( bin_txn + offset, txn->fee, txn->len_fee );
    offset += txn->len_fee;
    FIN_XTZ_MEMCPY( bin_txn + offset, txn->counter, txn->len_counter );
    offset += txn->len_counter;
    FIN_XTZ_MEMCPY( bin_txn + offset, txn->gas_limit, txn->len_gas_limit );
    offset += txn->len_gas_limit;
    FIN_XTZ_MEMCPY( bin_txn + offset, txn->storage_limit, txn->len_storage_limit );
    offset += txn->len_storage_limit;
    FIN_XTZ_MEMCPY( bin_txn + offset, txn->amount, txn->len_amount );
    offset += txn->len_amount;

    bin_txn[offset++] = FIN_XTZ_TAG_CONTRACT_ID;
    bin_txn[offset++] = FIN_XTZ_TAG_ED25519_PUBKEY;
    FIN_XTZ_MEMCPY( bin_txn + offset, txn->destination, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );
    offset += FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY;
    bin_txn[offset++] = 0x00;

    hash_input = FIN_XTZ_MALLOC( bin_txn_len + 1 );
    if ( NULL == hash_input ) {
        error = -1;
        goto cleanup;
    }

    FIN_XTZ_MEMCPY( hash_input, &txn_prefix, 1 );
    FIN_XTZ_MEMCPY( hash_input + 1, bin_txn, bin_txn_len );
    FIN_XTZ_BLAKE2B( txn_hash, FIN_XTZ_SIZE_BLAKE2B_HASH, hash_input, bin_txn_len + 1, NULL, 0 );

    if ( ( error = FIN_XTZ_SIGN( &signature, &len_signature, txn_hash, FIN_XTZ_SIZE_BLAKE2B_HASH, priv_key, len_priv_key ) ) != 0 ) {
        error = -2;
        goto cleanup;
    }

    *len_bin_out = bin_txn_len + FIN_XTZ_SIZE_ED25519_SIGNATURE;
    *bin_out = FIN_XTZ_MALLOC( *len_bin_out );
    if ( NULL == *bin_out ) {
        error = -1;
        goto cleanup;
    }

    FIN_XTZ_MEMCPY( *bin_out, bin_txn, bin_txn_len );
    FIN_XTZ_MEMCPY( *bin_out + bin_txn_len, signature, FIN_XTZ_SIZE_ED25519_SIGNATURE );

cleanup:
    if ( NULL != bin_txn ) {
        FIN_XTZ_FREE( bin_txn );
    }
    if ( NULL != hash_input ) {
        FIN_XTZ_FREE( hash_input );
    }
    if ( NULL != signature ) {
        FIN_XTZ_FREE( signature );
    }

    return error;
}