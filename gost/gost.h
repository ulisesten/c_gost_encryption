/**
 *  @file  gost.h
 *  @brief Umbrella header including the whole GOST library API.
 *
 *  The library implements, per feature:
 *  - @ref gost/cipher/cipher.h — symmetric encryption GOST 28147-89
 *    (simple substitution, gamma, gamma with feedback, authentication
 *    tag).
 *  - @ref gost/kuznyechik/kuznyechik.h — block cipher Kuznyechik,
 *    GOST R 34.12-2015 (128-bit block, 256-bit key).
 *  - @ref gost/cmac/cmac.h — CMAC per GOST R 34.13-2015.
 *  - @ref gost/ctr/ctr.h — counter mode CTR-ACPKM per GOST R
 *    34.13-2015 with the internal re-keying of RFC 8645.
 *  - @ref gost/aead/aead.h — authenticated encryption (encrypt-then-
 *    MAC: CTR-ACPKM plus CMAC) with associated data.
 *  - @ref gost/sframe/sframe.h — SFrame-GOST frame encryption profile
 *    for E2EE media calls.
 *  - @ref gost/hash/hash.h — hashing GOST R 34.11-2012 (Streebog), 256
 *    and 512 bits.
 *  - @ref gost/kdf/kdf.h — HMAC-Streebog (RFC 7836), PBKDF2
 *    (R 50.1.111-2016) and @ref gost/kdf/hkdf.h — HKDF (RFC 5869).
 *  - @ref gost/signature/signature.h — digital signature GOST
 *    R 34.10-2012: key generation, signing, verification and key
 *    agreement.
 *  - @ref gost/ecc/ecc.h — elliptic curve arithmetic and the standard
 *    parameter sets.
 *  - @ref gost/bigint/bigint.h — fixed-width integer arithmetic.
 *  - @ref gost/rng/rng.h — system random source.
 *
 *  See the project README for the build instructions and for the
 *  mapping between this API and the reference gost-cryptography project.
 */
#ifndef GOST_H
#define GOST_H

#include "common.h"
#include "bigint/bigint.h"
#include "cipher/cipher.h"
#include "hash/hash.h"
#include "text/text.h"
#include "kdf/kdf.h"
#include "kdf/hkdf.h"
#include "kuznyechik/kuznyechik.h"
#include "cmac/cmac.h"
#include "ctr/ctr.h"
#include "aead/aead.h"
#include "sframe/sframe.h"
#include "ecc/ecc.h"
#include "signature/signature.h"
#include "rng/rng.h"

#endif /* GOST_H */
