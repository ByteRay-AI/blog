Title: Initial access through embedded devices: a vulnerability in lwIP
Date: 2026-09-30
Slug: lwip-mqtt-initial-access
Author: Argus
Category: Security
Tags: lwip, mqtt, heap-overflow, embedded, rce
Summary: A heap overflow in lwIP's MQTT client (CVE-2026-87121) lets a malicious broker get code execution on a connecting device before MQTT authentication. It affects lwIP 2.0.1 through 2.2.1, and because lwIP ships inside many embedded SDKs, the bug can reach devices from dozens of vendors.


Our research into lwIP's MQTT client uncovered a vulnerability that turns a malicious broker reply into remote code execution. We developed a working end-to-end exploit and a fix for the underlying bug, and worked with [CISA to coordinate disclosure and remediation](https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-01). Because lwIP is incorporated into embedded SDKs, the affected code could reach dozens of vendors and device families, making coordination across the supply chain an important part of getting the fix to deployed products.

<img src="{attach}/attachments/lwip-mqtt-rce.png" alt="PoC run of the lwIP MQTT client against a malicious broker. The broker sends CONNACK followed by a 200-byte 0x80 fixed-header flood, the client overflows its heap buffer and a neighbouring command byte flips from 0x00 to 0x30, firmware dispatch jumps into handlers[0x30], and the attacker code runs id to show remote code execution as uid=1000(shah)." style="max-width: 600px; width: 100%; height: auto; display: block; margin: 1.25rem auto;">

Tracked as [CVE-2026-87121](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0211.html), the flaw affects the MQTT client bundled with lwIP versions 2.0.1 through 2.2.1. The vulnerable code dates back to December 2016. A device connecting to a malicious or compromised broker can be attacked before MQTT-level authentication, giving the attacker a route into the device through a connection it already makes.

## Initial access through embedded software

The client keeps storing malformed packet-header bytes beyond the end of a heap buffer. That overflow corrupts nearby control fields, which lets an attacker influence a subsequent memory write. Our exploit takes this sequence through to code execution over a TCP connection.

For an attacker, code execution is a foothold from which to pursue device control. Embedded devices can remain in service for years with infrequent firmware updates and little security review after deployment. When an update never reaches the installed device, a vulnerability can remain available to attackers long after a fix exists. The networking dependency beneath the application can quietly become a lasting entry point.

That exposure can reach beyond the device itself. A compromised device already inside a network can give an attacker a position from which to [target other connected systems](https://www.nccoe.nist.gov/publication/1800-15/VolB/index.html). An organisation may keep its servers patched and its external access tightly controlled while an overlooked embedded device offers another way in. Where network access permits it, the attacker can use that foothold to probe internal services and attempt to move towards more valuable systems.

## Bring ByteRay into your product's security work

Our fix enforces the protocol's header-length limit and rejects malformed input before it overruns the buffer. It also closes related out-of-bounds-read and integer-underflow paths caused by the same missing check. The [full advisory](https://pop.byteray.co.uk/advisory/BYTERAY-2026-0211.html) documents the vulnerability and links to the upstream patch.

This is the work we do at [ByteRay](https://byteray.co.uk/): investigate embedded software and firmware, establish how a vulnerability can be exploited, and develop fixes engineers can integrate. If you build connected devices, [request your first free sweep](https://byteray.co.uk/) or contact [hello@byteray.co.uk](mailto:hello@byteray.co.uk) to discuss your product.
