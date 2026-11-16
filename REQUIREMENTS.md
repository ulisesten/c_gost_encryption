# Requerimiento: Kuznyechik, CTR-ACPKM/CMAC, HKDF-Streebog y AEAD/SFrame-GOST

- **Estado:** propuesta para implementar.
- **Origen:** `cws_sodastream` (llamadas E2EE, propuesta `docs/calls_proposal.md`).
- **Base:** `c_gost_encryption` en `aedd242` (main).
- **Objetivo:** completar la librería para el cifrado de contenido de llamadas
  con GOST, sin AES/ECDHE/Ed25519 en contenido/identidad.

## 1. Motivación

Las llamadas necesitan cifrado extremo a extremo por frame (audio/video) que
pueda atravesar un SFU sin que éste descifre. El perfil previsto es
**SFrame-GOST** con **Kuznyechik**. La librería actual no tiene Kuznyechik,
CMAC, AEAD ni HKDF; solo Magma (GOST 28147-89) con MAC de 32 bits, que no es
suficiente para un AEAD moderno.

## 2. Estado actual

Ya implementado:

| Feature | Estado |
|---|---|
| Streebog-256/512 (RFC 6986 streaming) | Sí |
| HMAC-Streebog (RFC 7836) y PBKDF2 | Sí |
| GOST R 34.10-2012 (firma) y VKO | Sí |
| Curvas 2001/2012 (TC26) | Sí |
| Magma (GOST 28147-89): ECB, gamma, CFB, MAC 32 bits | Sí |
| RNG del sistema | Sí |

Faltante para E2EE:

- Kuznyechik (GOST R 34.12-2015).
- CTR-ACPKM y CMAC (GOST R 34.13-2015).
- HKDF (RFC 5869) sobre HMAC-Streebog.
- Construcción AEAD y perfil SFrame-GOST.
- Garantías constant-time y auditoría.
- Vectores de prueba y benchmarks.

## 3. Alcance funcional

### 3.1 Kuznyechik (GOST R 34.12-2015)

- Bloque de 128 bits, clave de 256 bits.
- Cifrado y descifrado de bloque.
- Expansión de clave (10 rondas).
- API sin asignación dinámica, sin estado global, C11.
- Test vector obligatorio (GOST R 34.12-2015, A.1):

```
clave:      8899aabbccddeeff0011223344556677
            fedcba98765432100123456789abcdef
plaintext:  1122334455667700ffeeddccbbaa9988
ciphertext: 7f679d90bebc24305a468d42b9d4edcd
```

Incluir además los vectores de descifrado y los del apéndice A.2.

### 3.2 CTR-ACPKM (GOST R 34.13-2015)

- Modo de contador con cambio de clave ACPKM.
- Nonce/IV de 128 bits; contador de bloque.
- API de cifrado/descifrado en sitio o buffers separados.
- Vectores del estándar (no inventar valores).
- Documentar el límite de datos por clave y la derivación de subclaves.

### 3.3 CMAC (GOST R 34.13-2015)

- CMAC sobre Kuznyechik, tag de 128 bits.
- API para MAC de mensaje completo y streaming.
- Vectores del estándar; probar mensajes vacíos, de 1 byte y múltiplos de
  bloque.
- No usar el MAC de 32 bits de Magma para AEAD.

### 3.4 HKDF-Streebog (RFC 5869)

- `extract` y `expand` con HMAC-Streebog-256/512.
- `salt`, `info` y longitud de salida arbitraria (respetar el límite RFC).
- La construcción es RFC 5869; el PRF es HMAC-Streebog (RFC 7836).
- Vectores: generar con una implementación independiente y fijarlos como
  known-answer; no hay vectores oficiales “HKDF-Streebog”.
- Documentar dominio/etiquetas (`info`) para separar claves de sesión, frames,
  sender keys, etc.

### 3.5 AEAD

Construcción recomendada: **Encrypt-then-MAC** con
Kuznyechik-CTR-ACPKM + CMAC (tag 128 bits), o una construcción AEAD
equivalente documentada. Requisitos:

- `seal(key, nonce, aad, plaintext) -> ciphertext || tag`.
- `open(key, nonce, aad, ciphertext, tag) -> plaintext` o error.
- Nonce único por clave; el llamador es responsable; documentar el riesgo.
- Tag verificado en tiempo constante antes de devolver plaintext.
- AAD autenticado; sin reutilización de nonce; sin liberar plaintext parcial
  si el tag falla (o documentar el contrato).
- Test de tamper: modificar ciphertext/tag/AAD/nonce y exigir rechazo.
- No usar AES-GCM ni ChaCha20 para contenido.

### 3.6 SFrame-GOST

Perfil propio, **no interoperable** con SFrame estándar (todos los extremos
son propios):

- Cabecera: versión, KID, contador de frame.
- Cifrado del payload con el AEAD anterior; cabecera como AAD.
- Tag de 16 bytes.
- Rotación de clave por KID y por epoch.
- Ventana de replay y rechazo de contadores repetidos.
- Funciones de frame completas:
  - `gost_sframe_encrypt(ctx, frame, out)`
  - `gost_sframe_decrypt(ctx, frame, out)`
- La gestión de claves (X3DH/VKO, Double Ratchet, sender keys) queda en la
  aplicación; la librería solo aplica el cifrado de frame.
- Benchmarks de audio (20 ms) y video (30 fps) en Android/Linux/Windows.

### 3.7 Utilidades

- `gost_secure_zero` (o equivalente) para borrar claves/temporales.
- Helpers de hex/base64 solo para tests/ejemplos, no para producción.
- No usar el `gost_hash` one-shot reverso para cripto; usar la API streaming
  canónica RFC 6986. Documentar esta distinción.

## 4. API propuesta

Nombres orientativos; mantener el estilo de la librería (tipos por valor,
`gost_status_t`, sin malloc):

```c
/* gost/kuznyechik/kuznyechik.h */
typedef struct gost_kuznyechik {
    uint8_t rk[10][16];
} gost_kuznyechik_t;

gost_status_t gost_kuznyechik_init(gost_kuznyechik_t* ctx,
                                   const uint8_t key[32]);
void gost_kuznyechik_encrypt_block(const gost_kuznyechik_t* ctx,
                                   const uint8_t in[16], uint8_t out[16]);
void gost_kuznyechik_decrypt_block(const gost_kuznyechik_t* ctx,
                                   const uint8_t in[16], uint8_t out[16]);

/* gost/modes/ctr_acpkm.h */
gost_status_t gost_ctr_acpkm_encrypt(const gost_kuznyechik_t* ctx,
                                     const uint8_t iv[16],
                                     const uint8_t* in, uint8_t* out,
                                     size_t len);

/* gost/mac/cmac.h */
typedef struct gost_cmac_ctx { /* ... */ } gost_cmac_ctx_t;
gost_status_t gost_cmac_init(gost_cmac_ctx_t* ctx,
                             const uint8_t key[32]);
gost_status_t gost_cmac_update(gost_cmac_ctx_t* ctx,
                               const uint8_t* data, size_t len);
gost_status_t gost_cmac_final(gost_cmac_ctx_t* ctx, uint8_t tag[16]);

/* gost/kdf/hkdf.h */
gost_status_t gost_hkdf_extract(gost_hash_width_t width,
                                const uint8_t* salt, size_t salt_len,
                                const uint8_t* ikm, size_t ikm_len,
                                uint8_t* prk);
gost_status_t gost_hkdf_expand(gost_hash_width_t width,
                               const uint8_t* prk, size_t prk_len,
                               const uint8_t* info, size_t info_len,
                               uint8_t* out, size_t out_len);

/* gost/aead/aead.h */
gost_status_t gost_aead_seal(const uint8_t key[32],
                             const uint8_t nonce[16],
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* in, size_t in_len,
                             uint8_t* out, uint8_t tag[16]);
gost_status_t gost_aead_open(const uint8_t key[32],
                             const uint8_t nonce[16],
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* in, size_t in_len,
                             const uint8_t tag[16],
                             uint8_t* out);

/* gost/sframe/sframe.h */
typedef struct gost_sframe_ctx gost_sframe_ctx_t;
gost_status_t gost_sframe_encrypt(gost_sframe_ctx_t* ctx,
                                  const uint8_t* frame, size_t len,
                                  uint8_t* out, size_t* out_len);
gost_status_t gost_sframe_decrypt(gost_sframe_ctx_t* ctx,
                                  const uint8_t* frame, size_t len,
                                  uint8_t* out, size_t* out_len);
```

Ajustar nombres/firmas a la arquitectura final; lo importante es el contrato
y las garantías.

## 5. Vectores y pruebas

- Kuznyechik: vector A.1 y A.2 del estándar; cifrado y descifrado.
- CTR-ACPKM: vectores de GOST R 34.13-2015.
- CMAC: vectores de GOST R 34.13-2015; vacío, 1 byte, 16, 17, 32 bytes.
- HKDF: known-answer generados y revisados; probar longitudes 1, 32, 64,
  255*HashLen y truncamiento.
- AEAD: roundtrip, tamper de tag/ciphertext/AAD/nonce, nonce repetido
  (documentar), longitudes 0/1/bloque/múltiplo.
- SFrame: frame de audio 20 ms, frame de video, pérdida/replay, KID rotation.
- Fuzz: parser de frame SFrame, `gost_aead_open` con entradas malformadas.
- Regresión: todos los tests existentes deben seguir pasando.
- Comparar con una implementación de referencia independiente cuando sea
  posible (Kuznyechik/CMAC/CTR).
- Añadir `ctest` y un ejemplo `examples/aead.c`.

## 6. Seguridad

- Implementación de criptografía propia: requiere revisión y auditoría
  externa antes de llamarla “100%”.
- **Constant-time**: evitar ramas y accesos a tablas dependientes de secretos;
  si Kuznyechik usa tablas, documentar el riesgo de cache-timing y evaluar una
  versión bitsliced/constant-time.
- Verificación de tag en tiempo constante; no devolver plaintext si falla.
- Borrado de claves/temporales (`gost_secure_zero`).
- Sin logs de claves, nonces, plaintext ni tokens.
- No reutilizar nonce; documentar el límite por clave.
- No usar el hash one-shot reverso para E2EE.
- No usar AES/ECDHE/Ed25519 para contenido/identidad (decisión del proyecto).
- Test de canal lateral y revisión de la gestión de claves en la app.

## 7. Rendimiento y plataformas

- C11, CMake, sin dependencias externas; sin malloc/estado global.
- Linux, Windows, Android (NDK) e iOS; opcional WASM.
- Benchmarks: MB/s de Kuznyechik, CTR-ACPKM, CMAC, AEAD y SFrame en:
  - Android ARM64 de gama media/baja.
  - Linux x86_64.
  - Windows x86_64.
- Objetivo: audio 20 ms y video 720p/30 con CPU razonable; documentar el
  costo de GOST en software.
- Sin aceleración hardware obligatoria; si se agrega, opcional y detrás de
  una feature.

## 8. Integración con `cws_sodastream`

- La app usará `gost_aead`/`gost_sframe` para el contenido E2EE.
- El acuerdo de claves 1:1 usa VKO/34.10-2012 y HKDF-Streebog.
- Grupo: sender keys + epoch, distribuidas por los canales 1:1.
- Janus solo reenvía frames cifrados; no descifra.
- El transporte WebRTC sigue siendo DTLS-SRTP estándar; el contenido va
  cifrado con GOST.
- La app no debe usar `gost_hash` one-shot para cripto.

## 9. Entregables

- Cabeceras y fuentes de Kuznyechik, CTR-ACPKM, CMAC, HKDF, AEAD y SFrame.
- Tests con vectores y fuzz.
- Ejemplo de uso.
- Documentación de API y del perfil SFrame-GOST.
- Benchmarks.
- Nota de seguridad y limitaciones.
- Tag/release (p. ej. `0.2.0`) y changelog.

## 10. Criterios de aceptación

- [ ] `ctest` pasa en Linux; build limpio con `-Wall -Wextra`.
- [ ] Vectores oficiales de Kuznyechik/CTR-ACPKM/CMAC pasan.
- [ ] HKDF/AEAD/SFrame con vectores y pruebas de tamper/replay.
- [ ] Sin malloc/estado global; sin dependencias externas.
- [ ] Benchmarks publicados.
- [ ] Revisión de constant-time y auditoría externa (o plan firmado).
- [ ] Documentación y ejemplo.
- [ ] Integración probada desde `cws_sodastream` en un spike.

## 11. Fuera de alcance

- TLS/DTLS o GOST TLS (eso es del transporte).
- Interoperabilidad con SFrame estándar (el perfil es propio).
- MLS o gestión de grupos completa (queda en la app).
- Aceleración hardware obligatoria.
- Certificación FSTEC; solo conformidad algorítmica.

## 12. Riesgos

- Criptografía propia sin auditoría: riesgo alto; no declarar “100%”.
- Cache-timing en tablas de Kuznyechik.
- Rendimiento en Android de gama baja; medir antes de fijar video.
- Complejidad del perfil SFrame y de la rotación de claves.
- Diferencias entre plataformas (endianness, alineación, compiladores).

## 13. Referencias

- GOST R 34.12-2015 (Kuznyechik/Magma).
- GOST R 34.13-2015 (modos, CTR-ACPKM, CMAC).
- RFC 6986 (Streebog), RFC 7836 (HMAC-Streebog),
  R 50.1.113-2016 (VKO), RFC 5869 (HKDF).
- RFC 9605 (SFrame) como referencia de diseño, no de interoperabilidad.
- `docs/calls_proposal.md` del proyecto `cws_sodastream`.
