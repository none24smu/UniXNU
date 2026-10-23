/* Additional bounded verification checks; never replaces the existing POST.
 * The immutable official source's KAT bytes are generated into an ignored
 * header at build time, rather than copied into this repository.
 */
#include <stdint.h>
#include <corecrypto/ccmldsa.h>
#include "cc_memory.h"
#include "apfs-mldsa-kat.h"

_Static_assert(CCMLDSA87_PUBKEY_CTX_NBYTES == 2600, "Unaudited ML-DSA context ABI");
_Static_assert(sizeof(apfs_mldsa_kat_pubkey) == 2592, "Wrong KAT public key");
_Static_assert(sizeof(apfs_mldsa_kat_signature) == 4627, "Wrong KAT signature");
_Static_assert(sizeof(apfs_mldsa_kat_message) == 32, "Wrong KAT message");

volatile uint32_t native_apfs_mldsa_selftest_result = UINT32_MAX;

int native_apfs_mldsa_selftest(void)
{
    const size_t bytes = CCMLDSA87_PUBKEY_CTX_NBYTES
                       + sizeof(apfs_mldsa_kat_signature)
                       + sizeof(apfs_mldsa_kat_message);
    native_apfs_mldsa_selftest_result = 1;
    unsigned char *storage = cc_malloc_clear(bytes);
    if (storage == 0) {
        return 1;
    }
    ccmldsa_pub_ctx_t key = (ccmldsa_pub_ctx_t)storage;
    unsigned char *signature = storage + CCMLDSA87_PUBKEY_CTX_NBYTES;
    unsigned char *message = signature + sizeof(apfs_mldsa_kat_signature);
    const struct ccmldsa_params *params = ccmldsa87();
    native_apfs_mldsa_selftest_result = 2;
    if (params == 0 || ccmldsa_sizeof_pub_ctx(params) != CCMLDSA87_PUBKEY_CTX_NBYTES) {
        goto done;
    }
    cc_memcpy(signature, apfs_mldsa_kat_signature, sizeof(apfs_mldsa_kat_signature));
    cc_memcpy(message, apfs_mldsa_kat_message, sizeof(apfs_mldsa_kat_message));
    native_apfs_mldsa_selftest_result = 3;
    if (ccmldsa_import_pubkey(params, sizeof(apfs_mldsa_kat_pubkey),
                             apfs_mldsa_kat_pubkey, key) != CCERR_OK) {
        goto done;
    }
    native_apfs_mldsa_selftest_result = 4;
    if (ccmldsa_verify(key, sizeof(apfs_mldsa_kat_signature), signature,
                       sizeof(apfs_mldsa_kat_message), message) != CCERR_VALID_SIGNATURE) {
        goto done;
    }
    native_apfs_mldsa_selftest_result = 5;
    signature[0] ^= 1;
    if (ccmldsa_verify(key, sizeof(apfs_mldsa_kat_signature), signature,
                       sizeof(apfs_mldsa_kat_message), message) != CCERR_INVALID_SIGNATURE) {
        goto done;
    }
    signature[0] ^= 1;
    native_apfs_mldsa_selftest_result = 6;
    message[0] ^= 1;
    if (ccmldsa_verify(key, sizeof(apfs_mldsa_kat_signature), signature,
                       sizeof(apfs_mldsa_kat_message), message) != CCERR_INVALID_SIGNATURE) {
        goto done;
    }
    message[0] ^= 1;
    native_apfs_mldsa_selftest_result = 7;
    if (ccmldsa_verify(key, sizeof(apfs_mldsa_kat_signature) - 1, signature,
                       sizeof(apfs_mldsa_kat_message), message) != CCERR_PARAMETER) {
        goto done;
    }
    native_apfs_mldsa_selftest_result = 8;
    if (ccmldsa_import_pubkey(params, sizeof(apfs_mldsa_kat_pubkey) - 1,
                             apfs_mldsa_kat_pubkey, key) != CCERR_PARAMETER) {
        goto done;
    }
    native_apfs_mldsa_selftest_result = 0;
done:
    cc_clear(bytes, storage);
    cc_free(storage, bytes);
    return (int)native_apfs_mldsa_selftest_result;
}
