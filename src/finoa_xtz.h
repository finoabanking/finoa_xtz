
#ifndef FINOA_XTZ_FINOA_XTZ_H
#define FINOA_XTZ_FINOA_XTZ_H

#include "finoa_xtz_config.h"

struct fin_xtz_txn {
    // These lengths are fixed
    uint8_t branch[32];
    uint8_t source[20];
    uint8_t destination[20];

    // these numbers are all ZArith encoded and the length has to be set
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

int generate_xtz_address( uint8_t **address, size_t *len_address, uint8_t *ed25519_pk, size_t len_pk );
int xtz_sign_transaction(struct fin_xtz_txn *txn, uint8_t **bin_out, size_t *len_bin_out, uint8_t const *priv_key, size_t len_priv_key);

#endif //FINOA_XTZ_FINOA_XTZ_H
