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

The destination is `buf + rsa.len - src_len`. The intent is a right-aligned copy: for an input shorter than the modulus, `rsa.len - src_len` is a small positive offset and the value lands right at the end of the buffer. Nothing checks that `src_len` is less than or equal to `rsa.len`. These are `size_t` values, so once the input is longer than the modulus the subtraction wraps around, the "offset" becomes a huge unsigned number, and `buf + (that)` resolves to an address *before* `buf`. The `memcpy` then copies the whole attacker-supplied input starting there.

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

## From the underwrite to S-EL1 code execution

The underwrite is a linear, fully controlled write running below a heap buffer. We turn it into code execution in three steps: leak a live Secure World pointer to defeat ASLR, turn the underwrite into a write we can aim at any address, then use that write to take control of the program counter, the register that decides what runs next.

### Inside BGET

The core heap runs on BGET, a boundary-tag allocator (`lib/libutils/isoc/bget.c`). Every chunk carries a 16-byte header. Two important fields are `bsize` which is the size of this chunk, stored negative while it is allocated and positive once it is free and `prevfree` which is the size of the chunk immediately below when that neighbour is free, and zero otherwise. A free chunk also stores two pointers in the first bytes of its old payload: `flink` and `blink`, the forward and backward links of the free list.

```text
allocated chunk                      free chunk
+---------------------+             +---------------------+
| prevfree | bsize<0  |  header     | prevfree | bsize>0  |  header
+---------------------+             +---------------------+
|                     |             | flink    | blink    |  free-list links
|      payload        |             +---------------------+
|                     |             |   (rest is slack)   |
+---------------------+             +---------------------+
```

The free list is circular and doubly linked, with its head in a fixed core symbol (`malloc_ctx`, in `.bss`).

```text
head <-> chunk <-> chunk <-> ... <-> head
```

BGET uses two allocation policies. This guide is based on first-fit, not best-fit. In first-fit a request takes the first free chunk on the list large enough to hold it and when that chunk is bigger than the request, BGET decides where to carve. An exact fit takes the whole chunk off the list with no leftover. Anything else is carved from the high end, and the low part stays free as a remnant, sitting directly below the new allocation.

```text
free chunk, non-exact request:

+-----------------------+        +------------------+  new allocation
|                       |        |     request      |
|      free chunk       |  --->  +------------------+
|                       |        |  remnant (free)  |  <- stays on the free list,
+-----------------------+        +------------------+     directly below the alloc
```

The big initial free region, the "wilderness", sits at the head of the list and only shrinks as it is carved. Freed chunks go to the tail, so a fresh allocation comes out of the wilderness and, unless it exact-fits, leaves a free remnant just beneath it.

On `free`, BGET writes pointers of its own, and those are the writes we hijack. It looks at the neighbour above, and if that neighbour is free it unlinks it from the list and merges it in. The unlink is a standard doubly-linked-list splice:

```text
F = victim.flink
B = victim.blink
B->flink = F      i.e.  *(B + 16) = F      (WRITE 1)
F->blink = B      i.e.  *(F + 24) = B      (WRITE 2)
```

We forge a chunk with `flink = VALUE` and `blink = TARGET - 16`, get the allocator to merge (coalesce) it, and WRITE 1 becomes `*(TARGET) = VALUE`. The unlink does have sanity checks, but they are asserts, compiled out of release builds like this one, so the forged unlink runs unchecked. That gives us a write-what-where, which means we can store a value of our choice at an address of our choice. WRITE 2 is collateral. It does `*(VALUE + 24) = TARGET - 16`, so whatever we store at TARGET must itself be an address whose `+24` is writable. Because of that, we have to be careful picking the code-exec target.

### Where the underwrite lands

The copy runs downward off the front of the scratch buffer into whatever the allocator put below it. In the un-groomed case that is the free remnant from the carve, and a free remnant holds `flink`/`blink`, live randomized addresses. Overwriting them makes the very next allocation walk the free list, follow a trampled link, and dereference garbage.

```text
buf carved from the wilderness leaves a free remnant below it:

+---------------------+
|   RSA scratch buf   |
+---------------------+  buf's own header (prevfree, bsize)
|   free remnant      |  flink/blink = live S-EL1 pointers
+---------------------+

underwrite tramples flink/blink  ->  next malloc walks the list
                                 ->  data abort, the core panics
```

Repairing those links means writing back the exact randomized addresses we do not have yet, so the write cannot come first. We need the read to recover them.

### The read primitive: leaking a live pointer past ASLR

With ASLR on, the core is loaded at a random offset (the slide) each boot, so we cannot aim a write until we learn where it landed. The first job is to turn the underwrite into a read that hands back a live Secure World pointer.

To avoid corrupting the free list, the whole underwrite must land inside allocated memory. If the scratch buffer sits directly on top of an allocated object, with no free chunk between them, everything the copy touches is either that object's data or the buffer's own header, and both rebuild from size constants, not an address. No live link is disturbed, so nothing crashes, and the read works regardless of the slide.

Getting the buffer to land there takes grooming. We need a free hole exactly the size of the scratch buffer, with an object we can read back sitting directly below it. An RSA key gives us both. It keeps its modulus and its exponent in separate heap buffers, each the same size as the scratch buffer, sitting next to the small descriptor structs that point at them.

To free just one of those buffers without merging it into its neighbours, we grow a number. We populate an RSA public key, then hand it a larger exponent. BGET reserves a new, bigger buffer for the exponent and releases the old one, and because it takes the new buffer *before* releasing the old, the freed buffer is left isolated, which gives us a clean hole of exactly the scratch size, with the key's modulus descriptor sitting directly below it. Because allocation is first-fit and the wilderness is at the head of the list, we fill the wilderness with throwaway objects so the next request cannot be served from it. The RSA operation then drops its scratch buffer straight into that tail hole, directly above the modulus descriptor.

Now the underwrite has an all-allocated path down. It reaches into the modulus descriptor and bumps the field that counts how many limbs (machine words) the number is made of, while leaving the pointer to the number's data untouched. The modulus is a public attribute; we ask the core to hand it back and it copies out that many limbs from the still-valid data pointer, runs off the end of the real modulus, and keeps copying adjacent Secure World heap to the caller. That heap holds object descriptors and free-list links, all of them live S-EL1 pointers.

```text
scratch buffer exact-fits the isolated hole, directly above the descriptor:

+---------------------------+
|     RSA scratch buffer    |  <- underwrite starts here, writes downward
+---------------------------+
|     modulus descriptor    |  { data-ptr , ... , limb-count }
+---------------------------+
|    modulus limb buffer    |  <- data-ptr still points here
+---------------------------+
        adjacent Secure World heap
        (descriptors, free-list links = live S-EL1 pointers)

underwrite: bump limb-count, leave data-ptr intact
read the modulus back:  real modulus  ||  adjacent heap (live pointers)
```

<img src="{attach}/attachments/optee-info-leak.png" alt="Secure-world console and Normal-World output from the RSA NOPAD info-leak under CFG_CORE_ASLR=y. The scratch buffer exact-fits its hole (prevfree=0), the modulus read returns 1600 bytes, and the Normal World receives live S-EL1 pointers at fixed offsets." style="max-width: 600px; width: 100%; height: auto; display: block; margin: 1.25rem auto;">

The screenshot shows the result. `prevfree=0x0` confirms the scratch buffer exact-fit its hole with no remnant below it. The read returns 1600 bytes instead of the real modulus length, and the Normal World receives them with live S-EL1 pointers at fixed offsets. Those pointers are addresses in the current boot's secure heap.

The leak is reusable, becuse nothing on the write path was a free chunk, so the free-list walk stays consistent and the core never faults. And if we freed the object with the count still inflated, its teardown would scrub that many limbs and run far off the end of the buffer, so a second, identical underwrite sets the count back first. With that, the Secure World stays up and the leak can be repeated.

One leaked pointer is enough. We subtract its known link-time offset to get the ASLR slide, and every core address follows from it.

### The write primitive: a self-restoring write-what-where

With the slide known, we aim the unlink write from the BGET internals above. The same constraint from the leak applies. Forging a coalesce victim must not corrupt a real free chunk, or the next allocation crashes. So we forge the victim inside the scratch buffer's own payload and leave everything else alone.

It stays works becuse for two reasons, first is a split then a recoalesce. We shrink the scratch buffer's own header so the allocator believes a second, free chunk begins partway inside the payload, then place the forged `flink`/`blink` there. On free, BGET coalesces that forged chunk, performs the two unlink writes, and merges it back, leaving the buffer a whole free chunk again. No real free-list entry is disturbed. The second reason is an even modulus. The RSA path would overwrite the buffer with the exponentiation result and destroy the forged chunk, but the software backend rejects an even modulus before it allocates or writes anything. So the encrypt allocates the buffer, the underwrite lays down the forged chunk, the exponentiation bails out, and `free` runs on a buffer that still holds the forgery.

```text
underwrite lays a forged free chunk inside buf's own payload:

+---------------------------+
|  buf header (shrunk)      |  buf now looks like a small chunk
+---------------------------+
|  forged chunk header      |  bsize > 0  -> looks free to the coalescer
|  flink = VALUE            |
|  blink = TARGET - 16      |
+---------------------------+
|  rest of buf payload      |
+---------------------------+

free(buf):  coalesce forged chunk  ->  *(TARGET) = VALUE
            merge back             ->  buf is a whole free chunk again
```

Because it disturbs no live metadata and restores itself, the write is repeatable and leaves the heap exactly as it found it.

<img src="{attach}/attachments/optee-www.png" alt="Write-what-where through a forged BGET chunk. The underwrite lays down a forged chunk's boundary tag and free-list links inside the scratch buffer, and the allocator's own unlink on the next free stores an attacker-chosen value to an attacker-chosen address." style="max-width: 600px; width: 100%; height: auto; display: block; margin: 1.25rem auto;">

### Code execution: hijacking a crypto vtable

With a write-what-where and the leaked slide, we can overwrite any function pointer, and the core has an good one to hit. Every crypto operation dispatches through an "ops" table, a set of function pointers hanging off the operation's context object. A hash update compiles down to three instructions:

```text
ldr x3, [x0]        ; x3 = ctx->ops     (ops pointer at offset 0 of the ctx)
ldr x3, [x3, #8]    ; x3 = ops->update  (update slot at offset 8 of the table)
br  x3              ; tail call, x0 = ctx passed straight through
```

Whatever sits at `ctx->ops` is loaded and branched to. So the chain is short:

1. We stand up a hash operation. Its context holds the ops pointer at offset 0.
2. We build a fake ops table inside an object we control, every slot pointing at the address we want to run.
3. We fire the write-what-where to set `ctx->ops` to that fake table.
4. We call update. The core loads the fake table, reads the update slot, and branches there.

We set `ctx->ops` rather than writing a bare code pointer because of that collateral write. The value we store is the address of our fake table, a heap object, so the collateral `*(VALUE + 24) = ...` lands harmlessly inside that same object.

Firing the chain branches the secure-world program counter to our sentinel. That address is not executable, so the core faults on the instruction fetch and dumps its registers, and `elr`, the faulting PC, holds `0x414243444546`, the value we chose.

<img src="{attach}/attachments/optee-pc-control.png" alt="Secure-world console under CFG_CORE_ASLR=y. The write-what-where sets a crypto ctx->ops to a fake vtable, and TEE_DigestUpdate branches S-EL1 to the sentinel. The prefetch-abort register dump shows elr = 0x414243444546, the value we chose, with the same value in x16 (the branch register) and x3 (the loaded ops->update), and x0 still pointing at ctx." style="max-width: 600px; width: 100%; height: auto; display: block; margin: 1.25rem auto;">

Two mitigations are still standing. They won't stops the hijack, but both limit what we can run once we land. Writable pages being execute-never rules out injected shellcode, so the payload is code-reuse only. TA code is privileged-execute-never, so S-EL1 cannot branch into the attacker's own TA. So the payload can only reuse existing Secure World code, jumped to at an address we choose.

## VULN-2 : An unenforced flag that turns into a use-after-free

The third bug is a concurrency flag the core trusted when it should not have. `TA_FLAG_CONCURRENT` is documented as pseudo-TA only, but it sits inside the mask of flags a user TA is allowed to declare in its header, and the core accepted it. Once set, it changes serialization:

```c
static bool tee_ta_try_set_busy(struct tee_ta_ctx *ctx)
{
    if (ctx->flags & TA_FLAG_CONCURRENT)
        return true;   /* skip the busy lock entirely */
    ...
```

So two sessions of a single-instance, multi-session user TA can run at the same time on one shared context. Both sessions map and unmap their memref parameters against the same address-space region list (`uctx->vm_info.regions`) with no lock. The concurrent inserts, removals, and frees corrupt the list and free `vm_region` nodes that are still in use. That is a use-after-free in S-EL1, driven by a TA the attacker authored and loaded. On a build with test key signing, that authoring step is free; on a locked-down device it needs the TA signing key.

## VULN-3 : Widevine PTA - a Normal-World panic across the boundary

The second bug is smaller but reachable straight from the Normal World with a single call. The Widevine pseudo-TA restricts itself to a few allowed caller UUIDs, and to do that it reads the calling session:

```c
struct ts_session *session = ts_get_calling_session();

/* Make sure we are called from a TA */
if (!is_user_ta_ctx(session->ctx))
    return TEE_ERROR_ACCESS_DENIED;
```

The check assumes there is always a calling session. When the Normal World opens a session on the PTA directly, there is no calling TA on the thread's session stack, so `ts_get_calling_session()` returns NULL. The very next line reads `session->ctx` off a NULL pointer, faults at S-EL1, and the core panics. One SMC from an unprivileged Normal World process takes down the entire Secure World. This affects builds with `CFG_WIDEVINE_PTA` enabled, the ones that use the DRM path.

## Status

All three were reported to the OP-TEE project with proof-of-concept code, with fixes submitted upstream in 2026. The RSA NOPAD underwrite was discovered independently by us and by Ramtine Tofighi Shirazi <ramtine@secmate.dev> of Secmate.dev.

## References

- [OP-TEE #7898: crypto: rsa: reject RSA NOPAD input longer than the modulus](https://github.com/OP-TEE/optee_os/pull/7898)
- [OP-TEE #7899: core: pta: widevine: reject a NULL calling session in open_session](https://github.com/OP-TEE/optee_os/pull/7899)
- [OP-TEE #7900: core: ldelf: reject TA_FLAG_CONCURRENT for user TAs](https://github.com/OP-TEE/optee_os/pull/7900)
