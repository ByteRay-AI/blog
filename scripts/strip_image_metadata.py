#!/usr/bin/env python3
"""Strip all metadata from PNG and JPEG images, keeping only what is needed to render them.

Usage:
    scripts/strip_image_metadata.py content/attachments/*.png
    scripts/strip_image_metadata.py --check content/attachments/*.png   # report only, exit 1 if anything found

PNG: keeps IHDR, PLTE, tRNS, sRGB, gAMA, cHRM, IDAT, IEND. Drops tEXt, zTXt, iTXt,
tIME, eXIf, iCCP, pHYs, bKGD, sBIT, hIST, sPLT and any other ancillary chunk.
JPEG: keeps SOI, the frame/scan segments and APP14 (Adobe colour transform, needed to
decode correctly). Drops APP0..APP13/APP15 (JFIF, EXIF, XMP, ICC, Photoshop), COM.

Standard library only, so it runs anywhere Python 3 does.
"""

import struct
import sys
import zlib
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"tRNS", b"sRGB", b"gAMA", b"cHRM", b"IDAT", b"IEND"}

JPEG_KEEP_MARKERS = {0xEE}  # APP14 Adobe, affects colour decoding
JPEG_DROP_MARKERS = {0xFE} | {m for m in range(0xE0, 0xF0) if m not in JPEG_KEEP_MARKERS}


def png_chunks(data: bytes):
    pos = len(PNG_SIG)
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        yield ctype, body


def strip_png(data: bytes):
    out = [PNG_SIG]
    dropped = []
    for ctype, body in png_chunks(data):
        if ctype in PNG_KEEP:
            crc = struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)
            out.append(struct.pack(">I", len(body)) + ctype + body + crc)
        else:
            dropped.append(ctype.decode("latin-1"))
    return b"".join(out), dropped


def strip_jpeg(data: bytes):
    out = [data[:2]]  # SOI
    dropped = []
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            raise ValueError("bad JPEG marker alignment")
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            out.append(data[pos:])
            break
        if marker == 0xDA:  # SOS: everything from here to EOI is entropy coded data
            end = data.rfind(b"\xff\xd9")
            out.append(data[pos:end])
            pos = end
            continue
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        segment = data[pos : pos + 2 + seg_len]
        if marker in JPEG_DROP_MARKERS:
            dropped.append(f"APP{marker - 0xE0}" if marker != 0xFE else "COM")
        else:
            out.append(segment)
        pos += 2 + seg_len
    return b"".join(out), dropped


def process(path: Path, check_only: bool) -> bool:
    data = path.read_bytes()
    if data.startswith(PNG_SIG):
        new, dropped = strip_png(data)
    elif data[:2] == b"\xff\xd8":
        new, dropped = strip_jpeg(data)
    else:
        print(f"skip  {path}: not PNG or JPEG")
        return False
    if not dropped:
        print(f"clean {path}")
        return False
    summary = ", ".join(sorted(set(dropped)))
    if check_only:
        print(f"FOUND {path}: {summary}")
    else:
        path.write_bytes(new)
        print(f"strip {path}: removed {summary} ({len(data) - len(new)} bytes)")
    return True


def main(argv):
    check_only = "--check" in argv
    files = [Path(a) for a in argv if a != "--check"]
    if not files:
        print(__doc__)
        return 2
    found = any([process(p, check_only) for p in files])
    return 1 if (check_only and found) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
