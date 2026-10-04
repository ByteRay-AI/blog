Title: Boot Logo to Bootkit: An Out-of-Bounds Write in U-Boot's RLE8 BMP Decoder
Date: 2026-08-10
Slug: uboot-rle8-bmp-framebuffer-underwrite
Author: Shahriyar Jalayeri and Mehrun P. Hunter
Category: Security
Tags: u-boot, bmp, rle8, framebuffer, memory-corruption, bootloader, logofail, disclosure
Summary: A crafted boot-splash BMP walks U-Boot's RLE8 decoder off the front of the framebuffer and writes attacker bytes into U-Boot's own image. On the SoCs that scan out from DRAM it becomes pre-OS code execution, decoded automatically before anything checks a signature.

U-Boot is the bootloader on a large share of Arm embedded devices: routers, set-top boxes, industrial controllers, single-board computers. Many of them show a logo while they boot. That logo is a BMP file, and on a lot of boards it is a loose `splash.bmp` read off the boot media and decoded automatically, before U-Boot loads or verifies the kernel.

A memory-corruption bug in that decoder is worth more than the same bug in a kernel driver. The splash is decoded by the component that verifies the next stage, and it is decoded from unsigned data. If the decode can be pushed into corrupting U-Boot itself, the attacker runs code inside the verifier before it verifies anything. This is the LogoFAIL pattern, where trusted firmware parses an untrusted image.

## The bug

RLE8 is a run-length encoding for 8-bit BMPs. The stream is a series of opcodes: a run of one color, a run of literal bytes, an end-of-line marker, an end-of-bitmap marker, and a delta that jumps the cursor. U-Boot decodes it in `video_display_rle8_bitmap()` (`drivers/video/video_bmp.c`). BMP scanlines are stored bottom to top, so the decoder starts at the bottom row of the framebuffer and walks upward, one row per end-of-line marker.

The end-of-line handler moves the write cursor and checks nothing:

```c
case BMP_RLE8_EOL:            /* end of line */
    bmap += 2;
    x = 0;
    y--;
    fb -= width * bytes_per_pixel + priv->line_length;
    break;
```

`fb` is the pointer the decoder writes through. Every end-of-line marker subtracts one row plus one scanline from it, moving it toward lower addresses, and there is no lower bound. The only guard anywhere near the writes checks the row counter, not the pointer:

```c
default:                      /* unencoded run */
    runlen = bmap[1];
    bmap += 2;
    if (y < height) {                       /* checks the row, never fb */
        if (x < width) {
            ...
            draw_unencoded_bitmap(&fb, bpix, eformat, bmap, palette, cnt);
        }
        x += runlen;
    }
```

`y` is an `int` and `height` is a `ulong`, but that mismatch is not even the point. The guard is on the logical row `y`. It says nothing about where `fb` is pointing. The two have drifted apart, because each end-of-line marker moves `fb` but the run opcodes are what advance the image.

So the attack is direct. Send N end-of-line markers with N smaller than the image height. `y` counts down from `height - 1` and stays a small positive number that passes the guard. Meanwhile `fb` has slid `N * (width * bpp + line_length)` bytes below the start of the framebuffer. Then send one unencoded run, and the decoder copies attacker bytes to that drifted pointer, well outside the framebuffer.

```
priv->fb   +-----------------------------+  start of the framebuffer
           |                             |
           |         framebuffer         |
           |                             |
           +-----------------------------+  bottom row: decode starts here
                        |
   each EOL marker:     |  fb -= width*bpp + line_length   (no floor)
   fb slides down       v
           +-----------------------------+
           |   whatever sits below the   |  <- fb lands here after N markers,
           |   framebuffer in memory     |     and the next run writes here
           +-----------------------------+
```

The delta opcode has the same defect. It recomputes `fb` from the unchecked `y`, so it can place the cursor anywhere.

## How you trigger it

The image reaches the decoder through ordinary, documented paths. No debugger, no special build.

- **The boot splash.** With `CONFIG_SPLASH_SCREEN`, U-Boot decodes a logo automatically at boot. When the logo is loaded from the boot media (`splashimage` / a `splash.bmp` on SD, eMMC, or USB), it is attacker-writable by anyone who can write that partition, and it is decoded before the next stage is authenticated. No interaction.
- **The network.** If the splash is fetched over TFTP, the image comes from the network.
- **The `bmp display` command.** With `CONFIG_CMD_BMP`, `bmp display <addr>` runs the same decoder. This one needs console access, so it is the weaker path.

The first path is the one that matters. On a device that boots from a removable SD card or an eMMC boot partition, the realistic attack is a tampered card or a reflashed boot partition: evil-maid, supply chain, or a one-time write from a transient root compromise. The splash is a loose file, not a signed payload.

## From an out-of-bounds write to running code

An out-of-bounds write is not automatically code execution. Two things have to line up: the write has to land on something useful, and the attacker has to control the bytes that get written.

**Where it lands.** On the SoCs with a display controller that scans out from DRAM (NXP i.MX6, Amlogic Meson, STMicro STM32), U-Boot places the framebuffer at the top of RAM, directly above its own relocated image. On i.MX6 the video driver sets only the framebuffer size and lets `video_reserve()` carve it from the top of DRAM (`drivers/video/imx/mxc_ipuv3_fb.c`), so the framebuffer sits immediately above U-Boot's `.text`, `.data`, and `.bss`. Walking the cursor below the framebuffer walks it straight into U-Boot's own code and function-pointer tables.

That is the difference between the vulnerable boards and a desktop-style setup. A PCI graphics card keeps its framebuffer in the card's own VRAM, far from U-Boot, so the same underwrite just corrupts VRAM. The embedded DRAM framebuffer is what puts U-Boot's own image within reach.

**What gets written.** RLE8 carries one palette index per pixel. When the framebuffer is 8 bits per pixel, the decoder writes that index straight through (`*fb++ = *bmap`), so every pixel in the crafted run is one raw attacker byte at the target address. That is byte-exact control, enough to lay down a full 64-bit pointer. A deeper framebuffer maps the index through the palette before storing it, which still corrupts memory but makes exact pointer forging harder. The clean primitive wants an 8-bit framebuffer, which is exactly what an indexed logo uses.

**The target.** Pick a function pointer that U-Boot calls on a predictable event. The serial driver's `putc` entry, in its `dm_serial_ops` table, is ideal: U-Boot calls it on the next character it writes to the console, and the call site jumps through the pointer without any name lookup or extra dereference. Solve the geometry (image width and marker count) so the cursor lands exactly on that `putc` slot, and write the address of code you also embedded in the same BMP. The next console write jumps there.

The whole exploit is one file. The shellcode is appended to the BMP after the end-of-bitmap marker, so the decoder ignores it as trailing data, and the run writes a pointer to it. One image on the boot partition, no side-loaded payload. That is the real LogoFAIL shape.

## The demonstration

We reproduced the full chain on `qemu -M virt` running an unmodified aarch64 U-Boot, with a DRAM framebuffer standing in for the SoC display controller that QEMU does not emulate. The bug, the relocation, the memory protections, and the splash and decode code are all the real U-Boot.

A single `splash.bmp` sits on a FAT partition of a USB stick. U-Boot enumerates USB, auto-loads the logo through the normal `splash_source` path, and the decoder runs. With the framebuffer at `0x7fd00000` and U-Boot relocated to `0x7fbad000`, an image of width 1021 with 368 end-of-line markers lands the cursor exactly on the `putc` slot at `0x7fca4850`. The run overwrites it with the address of the appended shellcode. The next line U-Boot tries to print calls `putc`, jumps into the shellcode, and the shellcode writes an attacker-chosen banner straight to the UART. It talks to the UART directly rather than through U-Boot's console, because it just overwrote that console's write function.

Nothing about the boot looks abnormal until the payload prints. The addresses are fixed because U-Boot has no ASLR, so the same image works every boot.

## What it gets you

Code execution here runs at U-Boot's privilege level, before the operating system, inside the component that is supposed to verify the operating system.

- **Secure boot bypass.** Verified boot authenticates U-Boot's code, and then U-Boot decodes an unsigned splash. The splash decode is ordered strictly before the kernel is loaded or its signature checked (`splash_display()` runs from console init in `board_init_r`, well before `main_loop()` reaches `bootcmd` and the FIT signature check). Code execution from the splash therefore runs inside the verifier before it verifies, so the attacker turns off the check and boots an unsigned kernel. Secure boot does not block this; the attack goes around it.
- **A persistent bootkit.** The trigger is a file on the boot media, decoded on every boot. Write the malicious `splash.bmp` once and it runs every time, below and before the OS. It survives OS reinstalls short of reflashing the boot partition, and it can render a normal-looking logo while it does its work, so the boot looks unchanged.
- **Measured boot does not stop it either.** The splash is typically not measured, and even where it is, code execution this early lets the attacker forge the later measurements.

The environment makes it easy. There is no `CONFIG_ASLR` in the tree, so relocation is deterministic. On aarch64, U-Boot maps all of DRAM as normal memory with no execute-never bit (`arch/arm/cpu/armv8/cache_v8.c`), so injected bytes are executable. The stack canary is opt-in and off in the configs we checked.

## Who is affected

Thirty-seven in-tree defconfigs build the RLE8 decoder. Thirty-six also enable a trigger that reaches it, all through the boot splash, several also through `bmp display`.

- **NXP i.MX6** (7 boards, the Nitrogen6 and SABRE Lite family). Cortex-A9, framebuffer carved above the image. A confirmed code-execution target.
- **Amlogic Meson** (26 boards: Odroid, Khadas VIM, BananaPi, LibreTech, and others). Cortex-A53/A73, arm64, framebuffer pinned at the end of DRAM. Very likely; one step in the layout is inferred rather than line-checked.
- **STMicro STM32F746** (2 boards). Cortex-M7 running code execute-in-place from internal flash, so the code itself is not writable through this bug. RAM data, heap, and function pointers still are, so a control-flow hijack through a RAM pointer is plausible but we have not built one.
- **NXP i.MX7** (1 board). Reachable; the framebuffer placement was not verified.

Any build that enables `CONFIG_VIDEO_BMP_RLE8` plus a trigger on a DRAM-framebuffer target is in the same position, in or out of tree.

## The fix

The decoder should never write outside the framebuffer, so the fix bounds the cursor against `[priv->fb, priv->fb + fb_size)` before each run and rejects the image if a write would fall outside:

```c
uchar *fb_start = priv->fb;
uchar *fb_end   = (uchar *)priv->fb + priv->fb_size;
...
    if (fb < fb_start || fb + cnt * bytes_per_pixel > fb_end)
        return -EINVAL;
    draw_unencoded_bitmap(&fb, bpix, eformat, bmap, palette, cnt);
```

The same check goes on the encoded-run path, the function returns an error instead of `void`, and `video_bmp_display()` propagates it. A crafted image is rejected cleanly; a well-formed logo still renders. The proper defense-in-depth on top of the bounds check is to stop decoding unsigned images before the boot chain is verified, or to include the logo in the signed payload so it cannot be swapped on the media.

## Status

Reported to the U-Boot project with proof-of-concept code, with the bounds-check fix sent to the mailing list in July 2026 (*video: bmp: bound RLE8 decode writes to the framebuffer*).

## References

- Bug: `drivers/video/video_bmp.c`, `video_display_rle8_bitmap()` (U-Boot).
- Framebuffer placement: `drivers/video/imx/mxc_ipuv3_fb.c` (i.MX6), `drivers/video/meson/meson_vpu.c` (Amlogic).
- LogoFAIL (Binarly, 2023): the same class of bug in UEFI image parsers, the precedent for treating a boot logo as an attack surface.
