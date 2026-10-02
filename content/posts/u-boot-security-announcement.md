Title: ByteRay finds and fixes eight vulnerabilities in U-Boot
Date: 2026-10-02
Slug: u-boot-security-announcement
Author: Argus
Category: Security
Tags: u-boot, bootloader, secure-boot, memory-corruption, disclosure
Summary: ByteRay found, reproduced and fixed eight memory-safety vulnerabilities in U-Boot. Flaws in BMP and SquashFS parsing could undermine verified boot, and bugs in IP reassembly, NFS, DHCPv6 and HTTP give attackers on the network a potential path to code execution before the operating system starts.


An attacker who gains code execution in a bootloader gets an opportunity to change what happens before the operating system takes control. They could alter the next boot stage or interfere with the checks meant to keep untrusted code off the device. Our recent U-Boot research found eight memory-safety vulnerabilities in that early boot environment, all were identified, reproduced, and remediated autonomously using our state-of-the-art cybersecurity system, Argus.

Several findings offer potential routes to code execution inside U-Boot. Others could undermine verified, secured or measured boot when the bootloader processes malicious data before authentication. For a team shipping embedded devices, the consequences can reach beyond a failed boot and into the integrity of the system that eventually runs.

## A crafted boot logo could undermine verified boot

A splash image seems like a small part of a device's boot process. Yet our research found that a crafted compressed BMP could make U-Boot write outside the framebuffer and corrupt surrounding memory. A filesystem had a similar opportunity: an overflowing size calculation in SquashFS could leave a buffer too small for the data written into it.

Both operations can happen inside the bootloader before the input is authenticated. If an attacker turns that memory corruption into control over verification logic, they could bypass secure boot and allow an altered next stage to run. A signed operating system cannot protect the boot process if the code deciding whether to trust it has already been compromised.

## Network boot can expose a path to code execution

The research also uncovered five vulnerabilities in U-Boot's network boot paths. IP fragment handling could write outside its reassembly buffer. Two NFS flaws mishandled reply lengths and allowed oversized copies. The HTTP download client could continue using a TCP connection after freeing it, while DHCPv6 identifier handling could overrun a packet buffer.

The IP reassembly, NFS, and DHCPv6 findings provide attacker-influenced memory writes that could be developed into bootloader code-execution exploits. That would give an attacker an opportunity to tamper with the image being loaded before the operating system starts. The HTTP finding causes a use-after-free, with further exploitation depending on how the freed memory is reused.

Our eighth finding was in Android boot-image loading, where an unchecked image size could cause a read to overrun its destination buffer when AVB does not gate the read. Each advisory explains the affected configurations and practical exposure in detail.

## Patched findings

The table below links each affected component to its advisory and summarises the security impact.

| Component | Security impact | Advisory |
| --- | --- | --- |
| IP fragment reassembly | Attacker-influenced memory corruption provides a potential route to bootloader code execution. | [CVE-2026-71971](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0212.html) |
| BMP RLE8 decoding | Writes outside the framebuffer could interfere with verification logic and enable a secure-boot bypass. | [CVE-2026-71972](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0213.html) |
| SquashFS directory tables | Heap corruption before authentication could undermine verified boot. | [CVE-2026-71973](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0214.html) |
| Android boot-image loading | An oversized read can corrupt bootloader memory and crash the device when AVB does not gate the read. | [CVE-2026-71974](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0215.html) |
| NFS READ replies | Out-of-bounds memory accesses provide a potential route to bootloader code execution. | [CVE-2026-74220](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0216.html) |
| NFS READLINK replies | Path-buffer corruption provides a potential route to bootloader code execution. | [CVE-2026-74221](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0217.html) |
| lwIP HTTP downloads | A use-after-free in the bootloader; providing a potential route to code execution. | [CVE-2026-74222](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0218.html) |
| DHCPv6 identifiers | An out-of-bounds write provides a potential route to bootloader code execution. | [CVE-2026-74225](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0219.html) |

## Bootloader compromise can open the door to a backdoors

Control at this stage could let an attacker alter the kernel as it loads or introduce code that runs before the operating system's security tools. That creates an opportunity for a bootkit or for planting a rootkit in the system that follows. A compromised verification path could also make an unauthorised image appear acceptable to the boot flow.

## We find, reproduce, and deliver fixes

We developed patches for every finding, and the advisories link to the upstream fixes so firmware teams can inspect and apply them. Most of fixes are included across U-Boot 2026.10-rc3 through rc5. For teams shipping U-Boot, this work provides a direct route from a disclosed vulnerability to a source-level repair. The individual advisories contain the version and commit details needed to check a deployed build.

## Bring ByteRay into your product's security work

We built [Argus](https://byteray.co.uk/) to find and fix vulnerabilities across the software and firmware a product relies on. Our Argus system combines specialised agents with deterministic program analysis to investigate source code and compiled binaries, then develop and test patches for review.

Our U-Boot research gives you a public record of that work. It also gives your team a reason to look closely at the dependencies beneath your own product, including components outside the usual application security review.

If you ship embedded firmware or connected devices, we can examine that code with you. [Request your first free sweep](https://byteray.co.uk/) or contact [hello@byteray.co.uk](mailto:hello@byteray.co.uk) to discuss your product.
