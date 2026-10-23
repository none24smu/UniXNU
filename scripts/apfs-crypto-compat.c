/* Scalar compatibility implementation of the XNU 12377 digest-pair KPI.
 *
 * Both inputs are consumed before either output is written. This permits
 * Merkle-tree callers to place outputs over either input, including cross
 * aliases. As with ccdigest(), the caller supplies a valid digest descriptor
 * and output buffers of at least di->output_size bytes. Overlapping output
 * buffers have no independent-result guarantee; final writes occur 1 then 2.
 *
 * Build against the kernel's ccdigest.h (including compress_parallel), using
 * the same namespace header as the provider. This performs real hashing and
 * never substitutes a success value for cryptographic verification.
 */
#include "cc_internal.h"
#include <corecrypto/ccdigest.h>

void ccdigest_parallel(const struct ccdigest_info *di, size_t data_nbytes,
                       const void *data1, void *digest1,
                       const void *data2, void *digest2)
{
    CC_ENSURE_DIT_ENABLED

    ccdigest_di_decl(di, context1);
    ccdigest_di_decl(di, context2);
    ccdigest_init(di, context1);
    ccdigest_init(di, context2);
    ccdigest_update(di, context1, data_nbytes, data1);
    ccdigest_update(di, context2, data_nbytes, data2);
    ccdigest_final(di, context1, digest1);
    ccdigest_final(di, context2, digest2);
    ccdigest_di_clear(di, context1);
    ccdigest_di_clear(di, context2);
}
