/**
 *  @file  gost.h
 *  @brief Umbrella header including the whole GOST library API.
 *
 *  The library implements, per feature:
 *  - @ref gost/cipher/cipher.h — symmetric encryption GOST 28147-89
 *    (simple substitution, gamma, gamma with feedback, authentication
 *    tag).
 *  - @ref gost/hash/hash.h — hashing GOST R 34.11-2012 (Streebog), 256
 *    and 512 bits.
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
#include "ecc/ecc.h"
#include "signature/signature.h"
#include "rng/rng.h"

#endif /* GOST_H */
