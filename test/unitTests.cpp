
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

extern "C" {
#include <finoa_xtz.h>
}

TEST_CASE( "zarith encode rubbish" ) {
    uint8_t *rubbish = (uint8_t*)"one blue dog is a funny cat";
    uint8_t *out = nullptr;
    size_t len_out = 0;
    FIN_XTZ_ZARITH_NUMBER( rubbish, &out, &len_out );
    REQUIRE( len_out == 0 );
    REQUIRE( NULL == out );
}

TEST_CASE( "zarith encode a very large number" ) {

    const char *very_long_number = "999999999999999999999999999";
    BIGNUM *number = BN_new();
    BN_dec2bn( &number, very_long_number );
    uint8_t *input = (uint8_t*)BN_bn2hex( number );

    uint8_t *out = nullptr;
    size_t len_out = 0;
    FIN_XTZ_ZARITH_NUMBER( input, &out, &len_out );

    const uint8_t expected_result[] = {0xFF, 0xFF, 0xFF, 0xBF, 0xCE, 0x87, 0xA0, 0xE8, 0x9F, 0xF9, 0xB8, 0xD9, 0x33};

    REQUIRE( len_out == 13 );
    REQUIRE( memcmp( out, expected_result, len_out ) == 0 );

}

TEST_CASE( "generate a xtz address from a given public key" ) {

    const char *expected_address = "tz1VCe5UfZwNWaT226z9feD2yG2PMGwrTfQA";

    uint8_t *address = nullptr;
    size_t len_address = 0;
    uint8_t ed25519_pub_key[] = {0x48, 0x8E, 0x32, 0x78, 0xBE, 0x59, 0x04, 0xD4, 0x55, 0x6D,
                                 0x7D, 0x46, 0x44, 0x24, 0x85, 0x25, 0xCD, 0xAC, 0x1C, 0x3A,
                                 0x58, 0x24, 0x08, 0x4F, 0x32, 0x55, 0x23, 0x33, 0xD4, 0x3C,
                                 0xF6, 0x2A};

    REQUIRE( generate_xtz_address(&address, &len_address, ed25519_pub_key, FIN_XTZ_SIZE_ED25519_PUBKEY ) == 0 );
    REQUIRE( len_address == FIN_XTZ_SIZE_ADDRESS + 1 );     // expected are 37 bytes because of the zero terminated string
    REQUIRE( memcmp(expected_address, address, len_address ) == 0 );

    FIN_XTZ_FREE( address );
}

TEST_CASE( "generate a transaction from scratch and sign it" ) {

    // Test Branch
    uint8_t branch[] = {0xCE, 0x69, 0xC5, 0x71, 0x3D, 0xAC, 0x35, 0x37, 0x25, 0x4E,
                          0x7B, 0xE5, 0x97, 0x59, 0xCF, 0x59, 0xC1, 0x5A, 0xBD, 0x53,
                          0x0D, 0x10, 0x50, 0x1C, 0xCF, 0x90, 0x28, 0xA5, 0x78, 0x63,
                          0x14, 0xCF};

    uint8_t source[] = {0x02, 0x29, 0x8C, 0x03, 0xED, 0x7D, 0x45, 0x4A, 0x10, 0x1E,
                        0xB7, 0x02, 0x2B, 0xC9, 0x5F, 0x7E, 0x5F, 0x41, 0xAC, 0x78};
    uint8_t destination[] = {0xE7, 0x67, 0x0F, 0x32, 0x03, 0x81, 0x07, 0xA5, 0x9A, 0x2B,
                             0x9C, 0xFE, 0xFA, 0xE3, 0x6E, 0xA2, 0x1F, 0x5A, 0xA6, 0x3C };
    // fee - 50000 in ZArith encoding
    uint8_t fee[] = {0xD0, 0x86, 0x03};
    // gas_limit - 200 in ZArith encoding
    uint8_t gas_limit[] = { 0xC8, 0x01 };
    // counter - 3 in ZArith encoding
    uint8_t counter[] = { 0x03 };
    // storage_limit - 0 in ZArith encoding
    uint8_t storage_limit[] = {0x00};
    // amount - 100.000.000 in ZArith encoding
    uint8_t amount[] = { 0x80, 0xC2, 0xD7, 0x2F };

    uint8_t expected_bin_and_signature[] = {0xCE, 0x69, 0xC5, 0x71, 0x3D, 0xAC, 0x35, 0x37, 0x25, 0x4E,
                                            0x7B, 0xE5, 0x97, 0x59, 0xCF, 0x59, 0xC1, 0x5A, 0xBD, 0x53,
                                            0x0D, 0x10, 0x50, 0x1C, 0xCF, 0x90, 0x28, 0xA5, 0x78, 0x63,
                                            0x14, 0xCF, 0x6C, 0x00, 0x02, 0x29, 0x8C, 0x03, 0xED, 0x7D,
                                            0x45, 0x4A, 0x10, 0x1E, 0xB7, 0x02, 0x2B, 0xC9, 0x5F, 0x7E,
                                            0x5F, 0x41, 0xAC, 0x78, 0xD0, 0x86, 0x03, 0x03, 0xC8, 0x01,
                                            0x00, 0x80, 0xC2, 0xD7, 0x2F, 0x00, 0x00, 0xE7, 0x67, 0x0F,
                                            0x32, 0x03, 0x81, 0x07, 0xA5, 0x9A, 0x2B, 0x9C, 0xFE, 0xFA,
                                            0xE3, 0x6E, 0xA2, 0x1F, 0x5A, 0xA6, 0x3C, 0x00, 0x9D, 0xFE,
                                            0x11, 0x3D, 0xB5, 0xEC, 0x90, 0x50, 0x17, 0x74, 0x84, 0xF7,
                                            0x00, 0x26, 0xF3, 0xAF, 0xF7, 0xD4, 0x98, 0x89, 0x5D, 0x55,
                                            0xE2, 0xD9, 0x6A, 0x69, 0xC9, 0x39, 0x36, 0x6E, 0xEC, 0x55,
                                            0xCD, 0xCF, 0x6D, 0x9E, 0xC0, 0x90, 0x10, 0x91, 0x55, 0x68,
                                            0xBB, 0x0D, 0xA4, 0x1E, 0xCA, 0x1E, 0x6D, 0xD4, 0xBC, 0xC5,
                                            0x1A, 0x89, 0x96, 0xC2, 0xF5, 0x7A, 0xEC, 0x51, 0x47, 0x26,
                                            0x1D, 0x0A};

    uint8_t private_key_for_signature[] = { 0x69, 0xBA, 0xC3, 0xE4, 0x4F, 0x0C, 0x9D, 0x3E, 0x1E, 0x1B,
                                            0x51, 0xE3, 0x1E, 0xB2, 0xEE, 0x71, 0x2E, 0x62, 0x5A, 0x3C,
                                            0x17, 0x37, 0x6C, 0x8D, 0xAB, 0xDB, 0xF6, 0x98, 0xBA, 0x93,
                                            0xAA, 0x61 };

    fin_xtz_txn txn{};
    FIN_XTZ_MEMCPY( txn.branch, branch, FIN_XTZ_SIZE_BRANCH );
    FIN_XTZ_MEMCPY( txn.source, source, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );
    FIN_XTZ_MEMCPY( txn.destination, destination, FIN_XTZ_SIZE_BLAKE2B_HASH_PUBKEY );

    FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"C350", &txn.fee, &txn.len_fee );
    FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"C8", &txn.gas_limit, &txn.len_gas_limit );
    FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"03", &txn.counter, &txn.len_counter );
    FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"00", &txn.storage_limit, &txn.len_storage_limit );
    FIN_XTZ_ZARITH_NUMBER( (uint8_t *)"05F5E100", &txn.amount, &txn.len_amount );

    REQUIRE( memcmp( txn.fee, fee, txn.len_fee ) == 0 );
    REQUIRE( memcmp( txn.gas_limit, gas_limit, txn.len_gas_limit ) == 0 );
    REQUIRE( memcmp( txn.storage_limit, storage_limit, txn.len_storage_limit ) == 0 );
    REQUIRE( memcmp( txn.counter, counter, txn.len_counter ) == 0 );
    REQUIRE( memcmp( txn.amount, amount, txn.len_amount ) == 0 );

    uint8_t *txnAndSignature = nullptr;
    size_t lenBin = 0;

    REQUIRE(xtz_sign_transaction(&txn, &txnAndSignature, &lenBin, private_key_for_signature, 32) == 0 );
    REQUIRE( lenBin == 152 );
    REQUIRE( memcmp(expected_bin_and_signature, txnAndSignature, lenBin ) == 0 );

    FIN_XTZ_FREE( txn.fee );
    FIN_XTZ_FREE( txn.amount );
    FIN_XTZ_FREE( txn.storage_limit );
    FIN_XTZ_FREE( txn.gas_limit );
    FIN_XTZ_FREE( txn.counter );

    FIN_XTZ_FREE( txnAndSignature );
}
