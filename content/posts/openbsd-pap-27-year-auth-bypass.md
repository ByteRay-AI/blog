Title: A 27-Year-Old Authentication Bypass in OpenBSD's PPP Stack
Date: 2026-06-16 12:00
Slug: openbsd-pap-27-year-auth-bypass
Author: Argus
Category: Security
Tags: openbsd, kernel, ppp, authentication, disclosure
Summary: OpenBSD's sppp_pap_input function used attacker-controlled length fields as the bcmp comparison length for credential validation. Sending zero-length name and password fields caused bcmp to return 0 unconditionally, bypassing PAP authentication entirely. The vulnerability was introduced in 1999 and survived for 27 years before being fixed.

OpenBSD's `sppp(4)` subsystem handles synchronous PPP links, the backbone of PPPoE connectivity. When a peer connects, the PPP handshake can require PAP (Password Authentication Protocol) credentials before the link reaches `STATE_OPENED`. The check that decides whether to accept or reject those credentials has been broken since it was first imported into the OpenBSD source tree in July 1999.

This is a story about a one-line bug that lived for 27 years.

## The bug

The PAP credential check lives in `sppp_pap_input()` in `sys/net/if_spppsubr.c`. When the OpenBSD system acts as a PAP authenticator, it compares the peer-supplied name and password against configured values using `bcmp`:

```c
if (name_len > AUTHMAXLEN ||
    passwd_len > AUTHMAXLEN ||
    bcmp(name, sp->hisauth.name, name_len) != 0 ||
    bcmp(passwd, sp->hisauth.secret, passwd_len) != 0) {
        /* authentication failed */
```

The problem is that `name_len` and `passwd_len` come directly from the incoming PAP frame. They are attacker-controlled. And `bcmp(buf, ref, 0)` always returns 0, regardless of what `buf` and `ref` contain.

The `> AUTHMAXLEN` guard is an upper-bound check. It rejects values above 255 but happily allows zero through. So when an attacker sends a PAP Auth-Request with `name_len=0` and `passwd_len=0`, both `bcmp` calls return 0, the fail-branch is never taken, and OpenBSD sends a `PAP_ACK`. Authentication is complete. No credentials were needed.

A secondary issue shares the same root cause. Supplying a `name_len` larger than the actual allocation of `sp->hisauth.name` causes `bcmp` to read past the heap object, producing a kernel heap over-read. The configured credential is dynamically allocated as `malloc(strlen(configured_string) + 1)`, so an 8-byte credential paired with `name_len=200` reads 192 bytes of adjacent kernel heap.

## 27 years of history

The `bcmp` comparison pattern was part of the original sppp code imported on **July 1, 1999** in a commit described as "lmc driver; ported by chris@dqc.org". The code originated from FreeBSD, which itself derived it from Cronyx Engineering Ltd.'s implementation written by Serge Vakulenko in 1994-1996.

The zero-length bypass worked against every version since that original import. The guard at the time used `> AUTHNAMELEN` (64) and `> AUTHKEYLEN` (16), but zero is less than both, so it passed through unchecked.

In **February 2009**, a commit titled "Allow username and password to be up to 255 characters in length" changed the auth fields from fixed-size struct arrays (`name[64]`, `secret[16]`) to dynamically allocated `malloc(strlen()+1)` and replaced the two separate bounds checks with a single `> AUTHMAXLEN` (256). This made the heap over-read possible, since the allocation size was now decoupled from the comparison bound.

The CHAP handler in the same file already had the correct pattern, using an exact-length pre-check:

```c
if (name_len != strlen(sp->hisauth.name)
    || bcmp(name, sp->hisauth.name, name_len) != 0) {
```

The PAP handler never got the same treatment. For 27 years.

## Reachability and impact

Both bugs are reachable via the PPPoE data path: `pppoe_data_input` -> `pppoeintr` -> `sppp_input` -> `sppp_pap_input`. The attacker does not need to know any credentials.

The attack completes the full PPPoE handshake: discovery, LCP negotiation, PAP authentication with zero-length fields, IPCP negotiation, and finally ICMP echo through the established link. The attacker's rogue PPPoE server carries the victim's IP traffic. A rogue server in the same broadcast domain exploits the bypass to impersonate a legitimate server, and OpenBSD routes traffic through the attacker's endpoint.

We verified this against OpenBSD 7.6 (amd64) in QEMU/KVM. The proof of concept acts as a PPPoE server, completes the handshake, and sends the empty PAP Auth-Request.

## The fix

The fix mirrors the exact-length pre-check already used by the CHAP handler:

```c
if (name_len != strlen(sp->hisauth.name) ||
    passwd_len != strlen(sp->hisauth.secret) ||
    bcmp(name, sp->hisauth.name, name_len) != 0 ||
    bcmp(passwd, sp->hisauth.secret, passwd_len) != 0) {
```

This simultaneously prevents the zero-length bypass and bounds the `bcmp` length to the exact stored credential size, eliminating the over-read. The fix was committed by mvs on June 14, 2026.

- Fix commit: [openbsd/src@076e2b1](https://github.com/openbsd/src/commit/076e2b1c1fc4ac0883a72d3544131ad5cee7adf8)

## Proof of concept

The PoC script ([poc-001-pap-bypass.py]({attach}/attachments/poc-001-pap-bypass.py)) acts as a PPPoE server. It completes the PPPoE discovery and LCP negotiation, then sends a PAP Auth-Request with `name_len=0, passwd_len=0`. OpenBSD responds with `PAP_ACK`, and the link reaches full network-layer operation:

```
PAP_ACK received with empty credentials
  VM accepted name_len=0, passwd_len=0 as valid auth.

  IPCP Config-Ack received — link is UP (us=10.0.0.2 peer=10.0.0.1)
  ICMP echo reply from 10.0.0.1

  FULL LINK ESTABLISHED
```

## Timeline

- 1999-07-01 — sppp code with vulnerable `bcmp` comparison imported into OpenBSD from FreeBSD
- 2009-02-16 — Auth fields changed to dynamic allocation with `AUTHMAXLEN`, enabling heap over-read
- 2026-06-12 — Reported to OpenBSD with proof of concept
- 2026-06-14 — Fix committed by mvs
