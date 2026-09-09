# gost — criptografía GOST en C

Implementación en C de los estándares criptográficos rusos, portada desde el
proyecto de referencia [`gost-cryptography`](reference/nodejs/gost-encryption)
para Node.js:

| Estándar | Funcionalidad | Feature |
| --- | --- | --- |
| GOST 28147-89 | Cifrado simétrico: sustitución simple (ECB), gamificación, gamificación con retroalimentación (CFB) e imitovstavka (MAC) | `gost/cipher` |
| GOST R 34.11-2012 | Hash «Streebog» de 256 y 512 bits | `gost/hash` |
| GOST R 34.10-2012 | Firma digital: generación de claves, firma, verificación y acuerdo de claves (VKO) | `gost/signature` |
| — | Aritmética de curva elíptica y conjuntos de parámetros estándar | `gost/ecc` |
| — | Aritmética entera de ancho fijo (512/1024 bits) | `gost/bigint` |
| — | Fuente de aleatoriedad del sistema | `gost/rng` |

## Arquitectura

Organización **por feature**: cada carpeta bajo `gost/` contiene una cabecera
pública junto a su implementación (sin separar `include/` de `src/`):

```
gost/
├── gost.h              cabecera paraguas con toda la API
├── common.h            códigos de estado y contrato del RNG
├── bigint/             bigint.h + bigint.c
├── cipher/             cipher.h + cipher.c (+ tablas de sustitución)
├── hash/               hash.h + hash.c (+ tablas LPS precalculadas)
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

## Correspondencia con el proyecto de referencia

| `encrypt.js` / `gost-cryptography` | API en C |
| --- | --- |
| `EncryptService.reversible_encrypt` | `gost_cipher_cfb_encrypt` |
| `EncryptService.decrypt` | `gost_cipher_cfb_decrypt` |
| `EncryptService.hash` | `gost_hash` (GOST_HASH_256) |
| `EncryptService.sign` | `gost_signature_sign_message` |
| `EncryptService.verify` | `gost_signature_verify_message` |
| `ЭЦП.Сгенерировать_ключи` | `gost_signature_generate_keys` |
| `ЭЦП.Согласование_ключей` | `gost_signature_key_agreement` |
| `Шифрование.Гаммование` | `gost_cipher_gamma` |
| `Шифрование.Простая_замена` | `gost_cipher_ecb_encrypt` / `gost_cipher_ecb_decrypt` |
| `Шифрование.Имитовставка` | `gost_cipher_mac` |
| `Код.Строку_в_байты` | codificación UTF-16LE a cargo de la aplicación |

La codificación de cadenas queda fuera de la librería: en C los mensajes son
arreglos de bytes; `Код.Строку_в_байты` del proyecto JS equivale a codificar
el texto en UTF-16LE antes de pasarlo a la API.

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
