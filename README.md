# gost — criptografía GOST en C

Implementación en C de los estándares criptográficos rusos, portada desde el
proyecto de referencia [`gost-cryptography`](reference/nodejs/gost-encryption)
para Node.js:

| Estándar | Funcionalidad | Feature |
| --- | --- | --- |
| GOST 28147-89 | Cifrado simétrico: sustitución simple (ECB), gamificación, gamificación con retroalimentación (CFB) e imitovstavka (MAC) | `gost/cipher` |
| GOST R 34.12-2015 | Cifrador de bloques Kuznyechik (bloque 128 bits, clave 256 bits) | `gost/kuznyechik` |
| GOST R 34.13-2015 | CMAC-128 sobre Kuznyechik | `gost/cmac` |
| GOST R 34.13-2015 / RFC 8645 | Modo contador CTR-ACPKM con re-keying interno | `gost/ctr` |
| — | AEAD (encrypt-then-MAC: CTR-ACPKM + CMAC) con datos asociados | `gost/aead` |
| — | SFrame-GOST: perfil propio de cifrado de frames para llamadas E2EE | `gost/sframe` |
| GOST R 34.11-2012 | Hash «Streebog» de 256 y 512 bits | `gost/hash` |
| GOST R 34.10-2012 | Firma digital: generación de claves, firma, verificación y acuerdo de claves (VKO) | `gost/signature` |
| RFC 7836 / R 50.1.113-2016 | HMAC-Streebog de 256 y 512 bits | `gost/kdf` |
| RFC 8018 / R 50.1.111-2016 | PBKDF2 de contraseñas con PRF HMAC-Streebog-512 | `gost/kdf` |
| RFC 5869 | HKDF sobre HMAC-Streebog (extract/expand) | `gost/kdf/hkdf.h` |
| — | Aritmética de curva elíptica y conjuntos de parámetros estándar | `gost/ecc` |
| — | Aritmética entera de ancho fijo (512/1024 bits) | `gost/bigint` |
| — | Fuente de aleatoriedad del sistema | `gost/rng` |

## Arquitectura

Organización **por feature**: cada carpeta bajo `gost/` contiene una cabecera
pública junto a su implementación (sin separar `include/` de `src/`):

```
gost/
├── gost.h              cabecera paraguas con toda la API
├── common.h            códigos de estado, RNG, borrado seguro y comparación constante
├── bigint/             bigint.h + bigint.c
├── cipher/             cipher.h + cipher.c (+ tablas de sustitución)
├── kuznyechik/         kuznyechik.h + kuznyechik.c (GOST R 34.12-2015)
├── cmac/               cmac.h + cmac.c (GOST R 34.13-2015)
├── ctr/                ctr.h + ctr.c (CTR-ACPKM, RFC 8645)
├── aead/               aead.h + aead.c (encrypt-then-MAC)
├── sframe/             sframe.h + sframe.c (frames E2EE)
├── hash/               hash.h + hash.c (+ tablas LPS precalculadas)
├── kdf/                kdf.h, hkdf.h + implementaciones (HMAC, PBKDF2, HKDF)
├── ecc/                ecc.h + ecc.c (+ parámetros de las 10 curvas)
├── signature/          signature.h + signature.c
└── rng/                rng.h + rng.c
```

El código es declarativo: tipos por valor, sin asignación dinámica ni estado
global; toda función fallible devuelve `gost_status_t` y escribe su resultado
en un parámetro de salida.

## Construcción

Requiere CMake ≥ 3.16 y un compilador C11.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
cmake --install build --prefix /usr/local
```

Opciones: `GOST_BUILD_TESTS=ON`, `GOST_BUILD_EXAMPLES=ON`,
`GOST_BUILD_DOCS=OFF` (documentación Doxygen en `build/docs/html`).

Para consumir la librería desde otro proyecto C:

```cmake
find_package(gost 1.0 REQUIRED)
target_link_libraries(mi_app PRIVATE gost::gost)
```

## Uso

Incluye la cabecera paraguas `gost/gost.h` o la cabecera de la feature que
necesites.

### Cifrado reversible (equivalente a `reversible_encrypt` de `encrypt.js`)

```c
#include <gost/gost.h>

gost_cipher_t cipher;
const uint32_t key[GOST_CIPHER_KEY_WORDS] = { /* clave de 256 bits */ };
const uint32_t iv[2] = { 0x11223344, 0x55667788 };

gost_cipher_init(&cipher, key, GOST_SBOX_TC26_Z);
gost_cipher_cfb_encrypt(&cipher, iv, data, len);    /* cifra en sitio */
gost_cipher_cfb_decrypt(&cipher, iv, data, len);    /* descifra en sitio */
```

### Hash Streebog (equivalente a `hash` de `encrypt.js`)

```c
uint8_t digest[GOST_HASH_MAX_DIGEST];
gost_hash(data, len, GOST_HASH_256, digest);   /* compatible con el proyecto JS */
```

Para hashear texto igual que el servicio de referencia (que codifica cada
cadena a UTF-16LE antes de hashear), usa `gost_hash_text`:

```c
gost_hash_text("Chikatina", strlen("Chikatina"), GOST_HASH_256, digest);
/* be50... : idéntico a EncryptService.hash("Chikatina") */
```

`gost_text_utf16le` expone la codificación por separado para mensajes
mayores, y `gost_hash`/`gost_hash_update` aceptan esos bytes directamente.

### Firma digital (equivalente a `sign` / `verify` de `encrypt.js`)

```c
gost_key_pair_t keys;
gost_signature_generate_keys(gost_curve(GOST_CURVE_2001_CRYPTOPRO_C),
                             gost_rng_system, NULL, &keys);

gost_signature_t sig;
gost_signature_sign_message(gost_curve(GOST_CURVE_2001_CRYPTOPRO_C),
                            &keys.private_key, msg, msg_len, gost_rng_system, NULL, &sig);

bool ok = false;
gost_signature_verify_message(gost_curve(GOST_CURVE_2001_CRYPTOPRO_C),
                              &keys.public_key, msg, msg_len, &sig, &ok);
```

### HMAC y PBKDF2 (RFC 7836 / R 50.1.111-2016)

```c
uint8_t mac[64];
gost_hmac(key, key_len, msg, msg_len, GOST_HASH_256, mac);   /* RFC 7836 */

uint8_t dk[64];
gost_pbkdf2(password, password_len, salt, salt_len, 100000, dk, 64);
/* PRF según el estándar: HMAC-GOSTR3411-2012-512 interno */

```

Para derivar claves de contraseñas almacenadas (formato
`$gost-pbkdf2$512$<iter>$<salt>$<dk>`) se combinan `gost_rng_system` para el
salt aleatorio y `gost_text_utf16le` si la contraseña procede de texto. No
existe KDF memory-hard dentro del estándar GOST; la librería no inventa uno.

### Kuznyechik, CMAC y CTR-ACPKM (GOST R 34.12/34.13-2015)

```c
gost_kuznyechik_t cipher;
gost_kuznyechik_init(&cipher, key);                       /* clave de 32 bytes */
gost_kuznyechik_encrypt_block(&cipher, block, block);     /* bloque de 16 bytes */

uint8_t tag[16];
gost_cmac(key, msg, msg_len, tag);                        /* CMAC-128 */

gost_ctr_acpkm_ctx_t ctr;
gost_ctr_acpkm_init(&ctr, key, icn, 0);                   /* ICN de 8 bytes */
gost_ctr_acpkm_encrypt(&ctr, in, out, len);               /* streaming */
/* Sección por defecto: 256 bloques (4 KiB) por clave de sección;
   con icn de 64 bits de contador, m_max = 2^64 bloques. */
```

### AEAD (encrypt-then-MAC para contenido E2EE)

```c
uint8_t tag[16];
gost_aead_seal(key, nonce, aad, aad_len, plain, plain_len, ciphertext, tag);
gost_status_t st = gost_aead_open(key, nonce, aad, aad_len, ciphertext, plain_len, tag, plain);
/* st == GOST_OK autenticado; GOST_ERR_AUTH si el tag falla (sin plaintext). */
```

Construcción: `PRK = HKDF-Extract(nonce, key)`; claves separadas
`gost-aead-enc` (CTR-ACPKM) y `gost-aead-mac` (CMAC) con HKDF-Streebog-256;
tag = CMAC sobre `len8(aad)‖aad‖len8(ct)‖ct‖nonce`. El nonce (16 bytes) debe
ser único por clave: la reutilización revela el XOR de los plaintexts.

### SFrame-GOST (frames de llamadas E2EE)

```c
gost_sframe_ctx_t sender;
gost_sframe_init(&sender);
gost_sframe_set_key(&sender, kid, key);          /* rotación por KID/época */
gost_sframe_encrypt(&sender, frame, len, wire, cap, &wire_len);
gost_sframe_decrypt(&ctx, wire, wire_len, media, cap, &media_len);
```

Perfil propio (no interoperable con SFrame RFC 9605): cabecera de 10 bytes
(`versión=1, KID, contador BE64`) como AAD, payload cifrado con el AEAD
anterior, tag de 16 bytes, ventana antireplay de 64 frames por KID y
rotación de época al re-registrar un KID. La gestión de claves (VKO,
sender keys, distribución de épocas) queda en la aplicación. Ver
`examples/aead.c` para el flujo completo y `examples/benchmark.c` para el
rendimiento de cada capa.

## Correspondencia con el proyecto de referencia

| `encrypt.js` / `gost-cryptography` | API en C |
| --- | --- |
| `EncryptService.reversible_encrypt` | `gost_cipher_cfb_encrypt` |
| `EncryptService.decrypt` | `gost_cipher_cfb_decrypt` |
| `EncryptService.hash` | `gost_hash_text` (hashea la cadena codificada en UTF-16LE) |
| `EncryptService.sign` | `gost_signature_sign_message` |
| `EncryptService.verify` | `gost_signature_verify_message` |
| `ЭЦП.Сгенерировать_ключи` | `gost_signature_generate_keys` |
| `ЭЦП.Согласование_ключей` | `gost_signature_key_agreement` |
| `Шифрование.Гаммование` | `gost_cipher_gamma` |
| `Шифрование.Простая_замена` | `gost_cipher_ecb_encrypt` / `gost_cipher_ecb_decrypt` |
| `Шифрование.Имитовставка` | `gost_cipher_mac` |
| `Код.Строку_в_байты` | `gost_text_utf16le` |

La codificación de cadenas vive en la feature `gost/text`: `Код.Строку_в_байты`
del proyecto JS equivale a `gost_text_utf16le` (UTF-8 → UTF-16LE), y las
variantes `*_message` de la firma aplican la misma codificación que el JS.

## Convenciones de bytes

- **Hash:** `gost_hash` reproduce byte a byte a la implementación de
  referencia y a los vectores impresos del estándar (los bloques se consumen
  desde el final del mensaje; el digest sale con el byte más significativo
  primero). La API streaming `gost_hash_init/update/final` sigue la
  presentación de RFC 6986 (bloques en orden natural, digest little-endian).
  Ambas presentaciones describen el mismo valor del digest, invertido byte a
  byte: `gost_hash(m, n, w, out) == invertido(stream_digest(invertido(m)))`.
- **Curvas:** coordenadas y escalares se serializan big-endian
  (`gost_u512_to_bytes_be`).
- **Cifrador:** bloques y clave usan palabras de 32 bits little-endian,
  igual que el proyecto de referencia.

## Pruebas

`tests/test_gost.c` verifica los vectores oficiales reproducidos por el
proyecto de referencia y validados contra él:

- ECB sobre bloque nulo: `1b0bbc32cebcab42` (GOST R 34.11-94).
- Streebog sobre el mensaje del estándar («Слово о полку Игореве»):
  `508f7e553c06501d…` (256 bits) y `28fbc9bada033b14…` (512 bits), además de
  los vectores RFC 6986 M1/M2.
- Firma GOST R 34.10-2012 sobre `GostR3410-2001-TestParamSet`:
  `r = 41aa28d2f1ab1482…`, `s = 01456c64ba4642a1…`.
- Acuerdo de claves R 50.1.113-2016 sobre la curva de 512 bits:
  `KEK = 21c236efc054c082…`.
- Kuznyechik (GOST R 34.12-2015 A.1): cifrado y descifrado
  `7f679d90bebc24305a468d42b9d4edcd` y horario de claves K3..K10 del
  apéndice A.1.2, validados contra `gostcrypto`.
- CMAC (GOST R 34.13-2015) sobre Kuznyechik: mensajes de 0, 1, 15, 16, 17,
  32 y 100 bytes contra `gostcrypto`.
- CTR-ACPKM (RFC 8645 §6.2.2): mensaje multisección contra oráculo
  construido sobre el bloque ECB validado; la lógica ACPKM se validó
  además contra el ejemplo AES-256 oficial del RFC.
- HKDF-Streebog (RFC 5869): known-answer de extract/expand en 256 y 512
  bits, generados con HMAC-Streebog independiente.
- AEAD y SFrame: roundtrip por clases de longitud, alteración de
  ciphertext/tag/AAD/nonce, replay, KID desconocido y rotación de época.
- Consistencia interna: ida y vuelta de todos los modos, hash streaming
  contra one-shot, propiedades de la aritmética modular y validación de
  parámetros de curva con Miller-Rabin.

## Notas de seguridad

- Los modos gamma y CFB requieren una sincroposyla (IV) única por mensaje;
  `gost_rng_system` la provee cuando se necesita.
- La validación de parámetros de curva usa Miller-Rabin probabilístico
  (50 rondas).
- La aritmética de curva es afín y no constante en tiempo; no está blindada
  contra ataques de canal lateral.
- **AEAD/SFrame:** el tag se verifica en tiempo constante con
  `gost_ct_equal` antes de liberar plaintext; en fallo, `gost_aead_open` y
  `gost_sframe_decrypt` no entregan datos. El nonce/contador debe ser único
  por clave (el contador de SFrame lo garantiza; en AEAD es obligación del
  llamador). Reutilizar un nonce bajo la misma clave rompe la confidencialidad
  y la autenticidad.
- **Kuznyechik:** la S-box es una tabla de 256 bytes y la transformación
  lineal usa tablas escalares de 4 KiB; los accesos a tabla dependen del
  dato (clave ⊕ estado), por lo que la implementación es observable por
  cache-timing. Es el mismo riesgo de cualquier cifra software con tablas
  (AES incluido); para entornos hostiles se recomienda una variante
  bitsliced/constante y auditoría externa antes de declararla segura.
- **Borrado de secretos:** `gost_secure_zero` (resistente a optimización del
  compilador) borra claves, horarios de claves y temporales al terminar:
  los contextos de CMAC y CTR-ACPKM se autolimpian en `final`, y los
  ejemplos borran las claves de sesión al salir.
- **Benchmarks de referencia** (Linux x86_64, `-O2`, 64 KiB por ronda,
  `examples/benchmark.c`): Kuznyechik-ECB ≈ 15,5 MB/s, CTR-ACPKM ≈ 14 MB/s,
  CMAC ≈ 15 MB/s, AEAD ≈ 7,5 MB/s, SFrame ≈ 7,4 MB/s. Suficiente para audio
  (20 ms ≈ 0,16 KB/frame → < 0,1 % de CPU a 50 fps) y válido como base para
  video en gama media; medir en Android/Windows antes de fijar resoluciones.
- Criptografía propia sin auditoría externa: no declarar «100 % segura».
