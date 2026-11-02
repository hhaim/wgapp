#!/usr/bin/env python3
"""Build a modern PNG-backed ICNS file from the macOS app icon set."""
import argparse
from pathlib import Path
import struct


ICON_MEMBERS = [
    (b"icp4", "icon_16x16.png", 16),
    (b"ic11", "icon_16x16@2x.png", 32),
    (b"icp5", "icon_32x32.png", 32),
    (b"ic12", "icon_32x32@2x.png", 64),
    (b"ic07", "icon_128x128.png", 128),
    (b"ic13", "icon_128x128@2x.png", 256),
    (b"ic08", "icon_256x256.png", 256),
    (b"ic14", "icon_256x256@2x.png", 512),
    (b"ic09", "icon_512x512.png", 512),
    (b"ic10", "icon_512x512@2x.png", 1024),
]


def png_size(content: bytes) -> tuple[int, int]:
    if content[:8] != b"\x89PNG\r\n\x1a\n" or content[12:16] != b"IHDR":
        raise ValueError("icon member is not a PNG")
    return struct.unpack(">II", content[16:24])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iconset", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    members = []
    for icon_type, filename, expected_size in ICON_MEMBERS:
        content = (args.iconset / filename).read_bytes()
        if png_size(content) != (expected_size, expected_size):
            raise ValueError(f"{filename} must be {expected_size}x{expected_size}")
        members.append(icon_type + struct.pack(">I", len(content) + 8) + content)

    body = b"".join(members)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)


if __name__ == "__main__":
    main()
