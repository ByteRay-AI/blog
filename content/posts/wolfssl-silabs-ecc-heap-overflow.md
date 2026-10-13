Title: Wire Length vs. Buffer Bounds: An Out-of-Bounds Write in wolfSSL's Silicon Labs Port
Date: 2026-10-12
Slug: wolfssl-silabs-ecc-heap-overflow
Author: Mehrun P. Hunter and Shahriyar Jalayeri
Category: Security
Tags: wolfssl, tls, ecc, heap-overflow, embedded, silabs, memory-corruption, disclosure
Summary: wolfSSL's Silicon Labs ECC import took the coordinate size from the peer's point and the curve from a separate identifier. A 133-byte point on a P-256 session wrote past a 96-byte heap field while the certificate was still being decoded.

wolfSSL is the TLS library on a lot of small devices: modules, industrial boards, parts where the vendor already has a crypto engine and would rather not do P-256 in software. One of those engines is the Silicon Labs Secure Element. The port is off unless you build with `WOLFSSL_SILABS_SE_ACCEL`.

I was reading a pinned 5.0.1 tree with Shahriyar Jalayeri, an older release a deployment was still on, and the import path on that port did not agree with itself. The encoded point says how long its coordinates are. The curve id says how long they are supposed to be. The buffer on the key object was sized for the second number, and the copy used the first.

## The bug

An uncompressed point is `04 || X || Y`. The public entry point is `wc_ecc_import_x963_ex()`. On the master tree its body is a static helper, `_ecc_import_x963_ex2()`, that the public function reaches through `wc_ecc_import_x963_ex2()`; on the 5.0.1 tree the same code sits in `wc_ecc_import_x963_ex()` itself. Either way it halves the encoded length and calls that the key size:

```c
keysize = (int)(inLen >> 1);
err = wc_ecc_set_curve(key, keysize, curve_id);
```

`wc_ecc_set_curve()` stops at `ECC_MAXSIZE`, which is 66. Under that, a named curve is selected by id. Nothing in that function asks whether `keysize` equals `dp->size`. Send a 133-byte point and ask for P-256, and you get `keysize == 66` on a curve whose coordinates are 32 bytes.

The Silicon Labs branch then hands that 66 straight to the hardware import. On the master I diffed (`d95483fff`, the 5.9.2 line), the public-key branch is:

```c
#elif defined(WOLFSSL_SILABS_SE_ACCEL)
    if (err == MP_OKAY)
        err = silabs_ecc_import(key, keysize, 1, 0);
```

`silabs_ecc_import()` points the secure-element key descriptor at `key->key_raw` and exports the coordinates with `wc_export_int()`. The field is declared for the hardware stride, not for whatever showed up on the wire:

```c
/* public X, public Y, and private D, at 0, keysize, and 2 * keysize */
byte key_raw[3 * ECC_MAX_CRYPTO_HW_SIZE];
```

On a non-Vault part `ECC_MAX_CRYPTO_HW_SIZE` is 32, so `key_raw` is 96 bytes. The public import writes X at offset 0 and Y at offset `keysize`:

```text
key_raw + 0     X, 66 bytes
key_raw + 66    Y, 66 bytes     ends at offset 132
```

The field ends at 96. Y runs 36 bytes past it. Those 36 bytes are attacker-chosen. They come from the point in the certificate or the key share.

On wolfSSL 5.0.1 the same import also wrote the scalar. `wc_ecc_import_x963_ex()` called `silabs_ecc_import(key, keysize)`, and that version exported X, Y, and the scalar, the last one at offset `2 * keysize`. Three 66-byte writes are 198 bytes into a 96-byte field, 102 bytes past the end.

Vault parts are a different size. There `ECC_MAX_CRYPTO_HW_SIZE` is 66 and `key_raw` is 198 bytes, so this particular point fits in the field. The comparison with `dp->size` is still missing. The overflow I reproduced is the build where the constant is 32.

`wc_ecc_check_key()` does not run in time to stop the copy. It is compiled in only with `WOLFSSL_VALIDATE_ECC_IMPORT`, and on this path it runs after `silabs_ecc_import()` has already written the field.

## How I ran it

I did not have the chip. The overflow is in wolfSSL's own copy, before the secure element is asked to do anything, so a stub of the Gecko SDK calls was enough. Randomness came from `/dev/urandom`. The hash calls used real SHA, because the DRBG health tests check the digest. Verify was stubbed. AES, ECDH, and key generation returned errors. Neither scenario in the test gets as far as record protection, so those stubs never mattered.

The input is a TLS certificate chain. The client parses it through the ordinary handshake path.

`gen_certs.py` builds two chains. Both have a P-256 root the client trusts. The benign intermediate has a real 65-byte P-256 point and a real signature from that root. The evil intermediate is the same shape, signed by the same root, except its subject public key is 133 bytes: `04`, then 66 bytes, then 66 bytes.

A wolfSSL server sends the chain. An ASan build of the client, loading only `root-cert.pem`, walks the usual certificate path:

```text
wolfSSL_connect
  DoCertificate
    ProcessPeerCerts
      ProcessPeerCertParse
        ParseCertRelative
          ConfirmSignature
            wc_EccPublicKeyDecode
              wc_ecc_import_x963_ex
                silabs_ecc_import
                  wc_export_int
```

The client has to verify the intermediate before it will use that key as the leaf's signer. The signature check succeeds, because the root really did sign the evil certificate. The next thing the parser does is decode the public key it just trusted the signature on. That decode is the overflow.

On the 5.0.1 build, AddressSanitizer reported:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 66 at 0x621000009f18
    #1 wc_export_int            wolfcrypt/src/wolfmath.c:243
    #2 silabs_ecc_import        wolfcrypt/src/port/silabs/silabs_ecc.c:202
    #3 wc_ecc_import_x963_ex    wolfcrypt/src/ecc.c:8968
0x621000009f18 is located 0 bytes to the right of 4632-byte region
allocated by ConfirmSignature   wolfcrypt/src/asn.c:13266
```

The benign chain, same shape, 65-byte point, real keys, printed `ConfirmSignature return 0` and "Verified Peer's cert", with no sanitizer output.

The ASan crash above is the 5.0.1 case. The extra scalar write carries the overrun 102 bytes past `key_raw` and off the end of the `ecc_key` allocation, which is what ASan flags. On the master line (`d95483fff`) and in the `v5.9.4-stable` tag the public import drops the scalar write, so the same point overruns the 96-byte `key_raw` by 36 bytes. `key_raw` is a member inside the larger `ecc_key`, so a 36-byte overrun can land on later fields of the same object instead of off the end, and may not trip ASan. For those trees I confirmed the missing bound at the source level, not as a separate reproduced crash: the import still never compares the size from the point with the curve before the copy.

## What I sent, and what landed

The patch I proposed put the bound in two places.

At the call in `wc_ecc_import_x963_ex()`, after `wc_ecc_set_curve()` succeeds, require `key->dp != NULL`, `keysize == key->dp->size`, and `keysize <= ECC_MAX_CRYPTO_HW_SIZE`. Otherwise return `ECC_BAD_ARG_E`. That rejects 66 against a P-256 curve before the hardware import runs.

Then the same capacity check inside every function in `silabs_ecc.c` that writes `key_raw`: `silabs_ecc_import`, `silabs_ecc_import_private`, `silabs_ecc_make_key`, `silabs_ecc_sig_to_rs`, and `silabs_ecc_import_private_raw`. The call-site check is not enough on its own. `wc_ecc_import_private_key_ex()` reaches the same buffer with `key->dp->size`, and a P-521 `dp->size` is 66. On the 96-byte field that overflows even when the key is well formed.

I looked at fixing `wc_ecc_set_curve()` so a named curve would refuse a mismatched size for every caller. That function is shared by every ECC build, not just Silicon Labs. A bad size on this one port did not justify changing the curve lookup for everyone else. The ATECC port already had its own length check against `pubkey_raw`. Matching that, and keeping the check on the Silicon Labs side, was the smaller change.

wolfSSL did the port half, which is the half that stops the write. PR [11530](https://github.com/wolfSSL/wolfssl/pull/11530), commit `c46e620c2a70677da7694cf06d241444c6cfe6bb`, does not touch `ecc.c`. In `silabs_ecc_import()` the size is rejected before the descriptor is pointed at `key_raw`:

```c
if (keysize == 0 || keysize > ECC_MAX_CRYPTO_HW_SIZE ||
        keysize != (word32)key->dp->size)
    return ECC_BAD_ARG_E;
```

`ECC_BAD_ARG_E` is `-170`. A 133-byte point on P-256 fails that test on `keysize != dp->size`. A P-384 or P-521 key on the non-Vault field fails it on `ECC_MAX_CRYPTO_HW_SIZE`. `silabs_ecc_make_key()` now takes its size from `dp->size` and applies the same limit, and `silabs_ecc_export_public()` refuses a curve that does not fit the field.

wolfSSL describes the bug in [PR 11530](https://github.com/wolfSSL/wolfssl/pull/11530), and again in the comment above the check: the size comes from the imported point, the curve comes from `key->dp`, and a size that disagrees with the curve writes past `key_raw`. That comment is at [`silabs_ecc.c` lines 249-256](https://github.com/wolfSSL/wolfssl/blob/c46e620c2a70677da7694cf06d241444c6cfe6bb/wolfcrypt/src/port/silabs/silabs_ecc.c#L249-L256).

I reviewed the patch against master and wrote back the same day, 23 September, that it covered the report. The fix landed in commit `c46e620`, which is on master now. David Garske confirmed the merge on 9 October, when he closed the ticket. The pull request carries wolfSSL's "Not for release 5.9.4" label, and the fix is not in the 5.9.4 tag. Until a release contains `c46e620`, the builds that need the workaround are the ones compiled with `WOLFSSL_SILABS_SE_ACCEL` on a non-Vault part. Turning the port off removes the copy. It also removes the hardware acceleration those builds were turned on for.

wolfSSL thanked ByteRay for the reports in PR [11606](https://github.com/wolfSSL/wolfssl/pull/11606). That pull request is a separate batch. The Silicon Labs fix is 11530.

The advisory is [BYTERAY-2026-0220](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0220.html).
