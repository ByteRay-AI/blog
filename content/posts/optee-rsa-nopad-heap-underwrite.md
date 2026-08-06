Title: Trustfall: An RSA Heap Underwrite Into OP-TEE's Secure World
Date: 2026-08-06
Slug: optee-rsa-nopad-heap-underwrite
Author: Argus
Category: Security
Tags: optee, trustzone, rsa, heap, memory-corruption, disclosure
Summary: Three vulnerabilities in OP-TEE, the TrustZone TEE that guards keys and secure storage on many Arm devices. Two of them open a path to code execution at S-EL1 (the highest privilege level on TrustZone).

OP-TEE is the TrustZone Trusted Execution Environment that ships on many Arm phones, set-top boxes, and embedded devices. It splits the system in two. The Normal World runs Linux and ordinary apps. The Secure World runs the OP-TEE core at S-EL1 and Trusted Applications (TAs) at S-EL0, and it holds the things the platform actually wants to protect: device keys, secure storage, DRM material, attestation. Normal World asks Secure World to do sensitive work through the TEE Client API and an SMC into the monitor.

A memory-corruption bug inside the OP-TEE core is worth more than the same bug in a Linux driver, because the core is the thing standing between an untrusted OS and the secrets. We found multiple vulnerabilities in OP-TEE and sent 3 fixes upstream so far.

## VULN-1 : The RSA NOPAD underwrite

RSA NOPAD is "textbook" RSA with no padding: the caller hands in a block the size of the modulus and the core does the modular exponentiation on it directly. When OP-TEE is built with the mbedTLS crypto backend, the software encrypt path left-aligns the input into a modulus-sized scratch buffer before the exponentiation:

```c
rsa.len = crypto_bignum_num_bytes((void *)&rsa.N);   /* modulus length  */
blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
buf = malloc(blen);
memset(buf, 0, blen);
memcpy(buf + rsa.len - src_len, src, src_len);        /* no length check */
```

The destination is `buf + rsa.len - src_len`. The intent is a right-aligned copy: for an input shorter than the modulus, `rsa.len - src_len` is a small positive offset and the value lands flush against the end of the buffer. Nothing checks that `src_len` is less than or equal to `rsa.len`. These are `size_t` values, so once the input is longer than the modulus the subtraction wraps around, the "offset" becomes a huge unsigned number, and `buf + (that)` resolves to an address *before* `buf`. The `memcpy` then copies the whole attacker-supplied input starting there.

```text
intended (input <= modulus):

         buf
          |
          v
          +-----------------------------+
          |        RSA scratch          |
          +-----------------------------+

buggy (input > modulus):

  dest = buf - k
   |
   v
   +----------+-----------------------------+
   | under-   |        RSA scratch          |
   | write    |                             |
   +----------+-----------------------------+
              ^
              |
             buf
```

The number of bytes written before `buf` is however much longer than the modulus the attacker made the input, and every one of those bytes is attacker-controlled. A Normal World client reaches this through a completely ordinary path: it opens a session to a TA, the TA calls `TEE_AsymmetricEncrypt` with an RSA NOPAD key, and the core hits the copy. No debugger, no artificial entry point. The malicious length crosses the TrustZone boundary and the core corrupts its own heap.

## Heap Grooming to Write-What-Where primitive

The OP-TEE core heap is managed by BGET, a boundary-tag allocator (`lib/libutils/isoc/bget.c`). Each chunk carries a small header in front of it that records the block size and a `prevfree` field the allocator uses to find and coalesce the neighbor below it. Free chunks are threaded onto a free list and merged with adjacent free space when released.

```text
one BGET chunk

  +--------+-----------------------------+
  | header |           payload           |
  +--------+-----------------------------+
      ^                    ^
      |                    |
  size, prevfree     pointer handed back to the caller
```

Two properties decide the exploit. First, BGET carves a request out of a free block from the high end, so a run of allocations comes back at descending addresses, the object you allocate after another one sits below it, at a lower address. Second, the bytes immediately below any live chunk are either the next object's payload or that object's header.

```text
allocation order A, B, C out of one free block:

  low addr                                        high addr
  +----------------+------+------+------+
  |   free space   |  C   |  B   |  A   |
  +----------------+------+------+------+
                      ^
                      newest allocation sits lowest
```

Now line that up with the underwrite. The copy runs backwards off the front of the RSA scratch buffer, toward lower addresses, into whatever sits below it.

### Grooming a victim under the buffer

The goal is to make the RSA scratch buffer land directly above an object we chose, so the underwrite falls into it. BGET is deterministic, so with control over which core allocations happen and when (each reachable through ordinary TA calls that make the core allocate and free) the layout is repeatable.

1. Pack the heap so the relevant size class is contiguous and predictable, removing stale holes.
2. Lay down the object we want to hit, interleaved with disposable placeholders of the same size class.
3. Free one placeholder to open a hole sitting just above a chosen victim.
4. Trigger the RSA operation. Its scratch buffer is the same size class, so it reuses that hole, and the underwrite now reaches down into the victim.

```text
step 2  victim V interleaved with placeholders P

  low                               high
  ... +-----+-----+-----+-----+ ...
      |  V  |  P  |  V  |  P  |
      +-----+-----+-----+-----+

step 3  free a placeholder above a victim -> hole

  ... +-----+------+-----+-----+ ...
      |  V  | hole |  V  |  P  |
      +-----+------+-----+-----+

step 4  RSA scratch buffer reuses the hole; copy runs left into V

  ... +-----+------+ ...
      |  V  | buf  |
      +--^--+------+
         |      <-- underwrite
         corrupts the victim below buf
```

### What we targeted

Two things below the buffer are worth hitting.

The first is an adjacent object with a function pointer or an "ops" table the core later calls. Overwrite it with a chosen Secure World address and the next indirect call through it transfers control. Place an instrumented object below the RSA buffer, groom the layout so the underwrite covered its later fields, overwrite its function pointer with the address of a marker routine, and watch the core dispatch through it and run the target in S-EL1:

```text
controlled underwrite  ->  neighbor object fields overwritten
                       ->  function pointer set to chosen address
                       ->  indirect call dispatches there
                       ->  Secure World runs attacker-chosen code path
```

The second target is the allocator itself. Corrupt the neighbor chunk's boundary tag (its size, `prevfree`, or free-list links) and the next free or coalesce of that chunk makes BGET follow attacker-chosen pointers while it unlinks the block. The allocator performs the write for you, which turns a bounded linear underwrite into a general write-what-where (an attacker-chosen value at an attacker-chosen address), we took this route when developing the exploit.

<img src="{attach}/attachments/optee-www.png" alt="Write-what-where through corrupted BGET metadata. The underwrite rewrites a neighbor chunk's boundary tag and free-list links, and the allocator's own unlink on the next free then stores an attacker-chosen value to an attacker-chosen address." style="max-width: 600px; width: 100%; height: auto; display: block; margin: 1.25rem auto;">


### From a write to a read, and past ASLR

`CFG_CORE_ASLR` randomizes where the core lands, so a function-pointer overwrite needs an address the attacker is not supposed to know. The same underwrite can be used for info leak premitive, by aiming at a read instead of a code pointer.

Pick a victim whose length or source-pointer field feeds a later copy back to the Normal World, and grow it. An operation that returns output to the caller then copies from the intended object and keeps going into the adjacent heap, handing back Secure World memory.

```text
victim: {len, data} whose bytes a later op returns to the Normal World

  before          +-----+---------------------+
                  | len |        data         |
                  +-----+---------------------+

  underwrite      +-----+---------------------+ . . . adjacent heap . . .
  grows len ->    | LEN |        data         | pointers | keys | headers
                  +-----+---------------------+

  later op copies LEN bytes out:

  Normal World gets:  data  ||  adjacent Secure World memory
                                    ^ contains a live S-EL1 pointer

  leaked_pointer - known_static_offset  =  core base
```

One leaked pointer defeats `CFG_CORE_ASLR`. The two primitives compose in the obvious order: read first to recover the base, then write the code pointer or the allocator metadata to an address you now know is right. 

## VULN-3 : Widevine PTA - a Normal-World panic across the boundary

The second bug is smaller but reachable straight from the Normal World with a single call. The Widevine pseudo-TA restricts itself to a few allowed caller UUIDs, and to do that it reads the calling session:

```c
struct ts_session *session = ts_get_calling_session();

/* Make sure we are called from a TA */
if (!is_user_ta_ctx(session->ctx))
    return TEE_ERROR_ACCESS_DENIED;
```

The check assumes there is always a calling session. When the Normal World opens a session on the PTA directly, there is no calling TA on the thread's session stack, so `ts_get_calling_session()` returns NULL. The very next line reads `session->ctx` off a NULL pointer, faults at S-EL1, and the core panics. One SMC from an unprivileged Normal World process takes down the entire Secure World. This affects builds with `CFG_WIDEVINE_PTA` enabled, which is where the DRM path is used.

## VULN-3 : An unenforced flag that turns into a use-after-free

The third bug is a concurrency flag the core trusted when it should not have. `TA_FLAG_CONCURRENT` is documented as pseudo-TA only, but it sits inside the mask of flags a user TA is allowed to declare in its header, and the core accepted it. Once set, it changes serialization:

```c
static bool tee_ta_try_set_busy(struct tee_ta_ctx *ctx)
{
    if (ctx->flags & TA_FLAG_CONCURRENT)
        return true;   /* skip the busy lock entirely */
    ...
```

So two sessions of a single-instance, multi-session user TA can run at the same time on one shared context. Both sessions map and unmap their memref parameters against the same address-space region list (`uctx->vm_info.regions`) with no lock. The concurrent inserts, removals, and frees corrupt the list and free `vm_region` nodes that are still in use. That is a use-after-free in S-EL1, driven by a TA the attacker authored and loaded. On a build with test key signing, that authoring step is free; on a locked-down device it needs the TA signing key.

## Status

All three were reported to the OP-TEE project with proof-of-concept code, with fixes submitted upstream in 2026. The RSA NOPAD underwrite was discovered independently by us and by Ramtine Tofighi Shirazi <ramtine@secmate.dev> of Secmate.dev.

## References

- [OP-TEE #7898: crypto: rsa: reject RSA NOPAD input longer than the modulus](https://github.com/OP-TEE/optee_os/pull/7898)
- [OP-TEE #7899: core: pta: widevine: reject a NULL calling session in open_session](https://github.com/OP-TEE/optee_os/pull/7899)
- [OP-TEE #7900: core: ldelf: reject TA_FLAG_CONCURRENT for user TAs](https://github.com/OP-TEE/optee_os/pull/7900)
