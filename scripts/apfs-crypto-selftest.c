/* Additional real known-answer checks for the optional APFS crypto KPIs.
 * Run after the existing provider POST; this does not replace that POST.
 * Expected SHA3 empty/abc values are fixed FIPS-202 known answers. The
 * SHA256 pair checks use distinct abc/xyz inputs with crossed output aliases.
 */
#include <stdint.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>

volatile uint32_t native_apfs_crypto_selftest_result = UINT32_MAX;

static unsigned native_apfs_hex_digit(char digit)
{
    return digit <= '9' ? (unsigned)(digit - '0') : (unsigned)(digit - 'a' + 10);
}

static int native_apfs_digest_matches(const unsigned char *actual,
                                    const char *expected, size_t bytes)
{
    unsigned difference = 0;
    for (size_t i = 0; i < bytes; ++i) {
        unsigned byte = (native_apfs_hex_digit(expected[2 * i]) << 4)
                      | native_apfs_hex_digit(expected[2 * i + 1]);
        difference |= actual[i] ^ byte;
    }
    return difference == 0;
}

int native_apfs_crypto_kpis_selftest(void)
{
    static const struct {
        ccdigest_info_selector_t selector;
        size_t output_bytes;
        const char *empty;
        const char *abc;
    } cases[] = {
        {ccsha3_256_di, 32,
         "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
         "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
        {ccsha3_384_di, 48,
         "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac"
         "3713831264adb47fb6bd1e058d5f004",
         "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b29"
         "8d88cea927ac7f539f1edf228376d25"},
        {ccsha3_512_di, 64,
         "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615"
         "b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
         "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10"
         "e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
    };
    unsigned char digest[64];
    native_apfs_crypto_selftest_result = UINT32_MAX;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t base = 0x100 + (uint32_t)i * 0x10;
        native_apfs_crypto_selftest_result = base + 1;
        const struct ccdigest_info *di = cases[i].selector();
        if (di == 0 || di->output_size != cases[i].output_bytes) {
            return (int)native_apfs_crypto_selftest_result;
        }
        native_apfs_crypto_selftest_result = base + 2;
        ccdigest(di, 0, "", digest);
        if (!native_apfs_digest_matches(digest, cases[i].empty, di->output_size)) {
            return (int)native_apfs_crypto_selftest_result;
        }
        native_apfs_crypto_selftest_result = base + 3;
        ccdigest(di, 3, "abc", digest);
        if (!native_apfs_digest_matches(digest, cases[i].abc, di->output_size)) {
            return (int)native_apfs_crypto_selftest_result;
        }
    }

    native_apfs_crypto_selftest_result = 0x201;
    const struct ccdigest_info *sha256 = ccsha256_di();
    if (sha256 == 0 || sha256->output_size != 32) {
        return (int)native_apfs_crypto_selftest_result;
    }
    unsigned char first[32] = {'a', 'b', 'c'};
    unsigned char second[32] = {'x', 'y', 'z'};
    native_apfs_crypto_selftest_result = 0x202;
    ccdigest_parallel(sha256, 3, first, second, second, first);
    if (!native_apfs_digest_matches(second,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32)) {
        return (int)native_apfs_crypto_selftest_result;
    }
    native_apfs_crypto_selftest_result = 0x203;
    if (!native_apfs_digest_matches(first,
            "3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282", 32)) {
        return (int)native_apfs_crypto_selftest_result;
    }
    native_apfs_crypto_selftest_result = 0;
    return 0;
}
