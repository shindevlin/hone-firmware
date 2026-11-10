#!/usr/bin/env python3
"""Hone mascot: a Great Kiskadee, original 1-bit pixel art (40x38 sprites).
Run: kiskadee.py OUTDIR  -> kiskadee_sprites.h (XBM bytes) + kiskadee_preview.png
Sprites are drawn from simple shapes so every frame stays consistent."""
import sys
from PIL import Image, ImageDraw

W, H = 40, 38
BLK, WHT = 1, 0  # 1 = pixel on (black on the Flipper screen)


def dither(img, box, mask, step=2):
    """light checker inside mask (the yellow belly)"""
    x0, y0, x1, y1 = box
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            if 0 <= x < W and 0 <= y < H and mask.getpixel((x, y)) and (x + y) % step == 0 and y % 2 == 0:
                img.putpixel((x, y), BLK)


def bird(head_turn=False, crest=False, beak_open=False, wings_up=False, eye="open",
         fluff=0, tilt=0):
    img = Image.new("1", (W, H), WHT)
    d = ImageDraw.Draw(img)
    by = fluff  # body lowered a bit when sleeping
    # --- branch + feet
    d.line([(0, 36), (39, 36)], fill=BLK)
    d.line([(0, 37), (39, 37)], fill=BLK)
    d.point([(6, 35), (33, 35)], fill=BLK)
    for fx in (17, 22):
        d.line([(fx, 32 + by), (fx, 35)], fill=BLK)
        d.point([(fx - 1, 35), (fx + 1, 35)], fill=BLK)
    # --- tail (down-left, notched)
    d.polygon([(10, 25 + by), (1, 33), (4, 34), (6, 32), (8, 34), (13, 29 + by)], fill=BLK)
    # --- body: chunky oval
    body = Image.new("1", (W, H), 0)
    ImageDraw.Draw(body).ellipse([7, 15 + by, 31, 33 + by], fill=1)
    d.ellipse([7, 15 + by, 31, 33 + by], outline=BLK, fill=WHT)
    # yellow belly: dither on the lower/front half
    belly = Image.new("1", (W, H), 0)
    ImageDraw.Draw(belly).ellipse([14, 20 + by, 30, 32 + by], fill=1)
    inner = Image.new("1", (W, H), 0)
    ImageDraw.Draw(inner).ellipse([8, 16 + by, 30, 32 + by], fill=1)
    for y in range(H):
        for x in range(W):
            if belly.getpixel((x, y)) and inner.getpixel((x, y)) and (x + y) % 2 == 0 and y % 2 == 1:
                img.putpixel((x, y), BLK)
    # --- wing (brown = dense hatch with outline)
    if wings_up:
        wing = [(9, 21 + by), (4, 8), (8, 9), (12, 6), (15, 10), (18, 9), (20, 20 + by)]
    else:
        wing = [(8, 21 + by), (13, 17 + by), (21, 18 + by), (24, 24 + by), (19, 29 + by), (10, 28 + by)]
    d.polygon(wing, outline=BLK, fill=WHT)
    wmask = Image.new("1", (W, H), 0)
    ImageDraw.Draw(wmask).polygon(wing, fill=1)
    for y in range(H):
        for x in range(W):
            if wmask.getpixel((x, y)) and (x + y) % 2 == 0:
                img.putpixel((x, y), BLK)
    # wing edge stripes (rufous fringe, shown as two lines)
    if not wings_up:
        d.line([(11, 26 + by), (19, 27 + by)], fill=BLK)
    # --- head: big round head, striped. Facing right, or turned to the left.
    s = -1 if head_turn else 1        # beak side
    cx = 26 if not head_turn else 24  # head centre x
    hx0, hy0, hx1, hy1 = cx - 9, 1 + tilt, cx + 9, 19 + tilt
    head = Image.new("1", (W, H), 0)
    ImageDraw.Draw(head).ellipse([hx0, hy0, hx1, hy1], fill=1)
    d.ellipse([hx0, hy0, hx1, hy1], outline=BLK, fill=WHT)

    def band(y0, y1, color):
        for y in range(y0, y1 + 1):
            for x in range(W):
                if head.getpixel((x, y)):
                    img.putpixel((x, y), color)
    band(hy0, hy0 + 4, BLK)        # black crown
    band(hy0 + 5, hy0 + 7, WHT)    # white brow stripe, runs round to the nape
    band(hy0 + 8, hy0 + 11, BLK)   # black mask through the eye
    # outline stays closed on the throat side; brow stripe breaks it at the nape
    d.ellipse([hx0, hy0, hx1, hy1], outline=BLK)
    nape = hx0 if s > 0 else hx1
    d.point([(nape, hy0 + 5), (nape, hy0 + 6), (nape, hy0 + 7)], fill=WHT)
    # --- crest: kiskadees flash a hidden crown patch when excited
    if crest:
        for x, h in [(cx - 5, 3), (cx - 2, 5), (cx + 1, 6), (cx + 4, 4), (cx + 7, 2)]:
            d.line([(x, hy0 - h + 1), (x, hy0 + 1)], fill=BLK)
        d.line([(cx - 2, hy0 + 2), (cx + 2, hy0 + 2)], fill=WHT)  # the crown patch
    # --- eye (in the mask), toward the beak
    ex, ey = cx + 3 * s, hy0 + 9
    if eye == "open":
        d.rectangle([ex - 1, ey - 1, ex + 1, ey + 1], fill=WHT)
        d.point([(ex, ey)], fill=BLK)
    elif eye == "closed":
        d.line([(ex - 2, ey + 1), (ex + 2, ey + 1)], fill=WHT)
    elif eye == "x":
        d.rectangle([ex - 2, ey - 2, ex + 2, ey + 2], fill=WHT)
        d.line([(ex - 2, ey - 2), (ex + 2, ey + 2)], fill=BLK)
        d.line([(ex - 2, ey + 2), (ex + 2, ey - 2)], fill=BLK)
    # --- beak: thick and heavy, slight hook
    bx = hx1 - 1 if s > 0 else hx0 + 1

    def P(pts):
        return [(bx + s * dx, hy0 + dy) for dx, dy in pts]
    if beak_open:
        d.polygon(P([(0, 8), (5, 7), (5, 9), (1, 10)]), fill=BLK)
        d.polygon(P([(0, 12), (4, 13), (1, 14)]), fill=BLK)
    else:
        d.polygon(P([(0, 8), (5, 9), (5, 11), (0, 13)]), fill=BLK)
        d.point(P([(5, 12)]), fill=BLK)  # hook
    if fluff:  # sleeping: puffed outline + head sunk a little
        d.arc([6, 14 + by, 32, 34 + by], 200, 340, fill=BLK)
    if tilt:  # hurt: a ruffled feather tuft
        d.line([(9, 15), (7, 12)], fill=BLK)
        d.line([(12, 14), (12, 11)], fill=BLK)
    return img


FRAMES = [
    ("idle", dict()),
    ("scan_turn", dict(head_turn=True)),
    ("found", dict(crest=True, beak_open=True)),
    ("send_flap", dict(wings_up=True)),
    ("sleep", dict(eye="closed", fluff=1)),
    ("hurt", dict(eye="x", tilt=1)),
]


def xbm_bytes(img):
    out = []
    for y in range(H):
        for xb in range((W + 7) // 8):
            v = 0
            for bit in range(8):
                x = xb * 8 + bit
                if x < W and img.getpixel((x, y)):
                    v |= 1 << bit
            out.append(v)
    return out


def main(outdir):
    imgs = [(n, bird(**kw)) for n, kw in FRAMES]
    with open(f"{outdir}/kiskadee_sprites.h", "w") as f:
        f.write("/* Hone mascot: Great Kiskadee, original 1-bit art (generated by kiskadee.py) */\n")
        f.write("#pragma once\n#include <stdint.h>\n\n")
        f.write(f"#define KISKADEE_W {W}\n#define KISKADEE_H {H}\n\n")
        f.write("typedef enum {\n" + "".join(f"    KiskadeeFrame_{n},\n" for n, _ in imgs) +
                "    KiskadeeFrameCount,\n} KiskadeeFrame;\n\n")
        f.write(f"static const uint8_t kiskadee_frames[KiskadeeFrameCount][{len(xbm_bytes(imgs[0][1]))}] = {{\n")
        for n, im in imgs:
            b = xbm_bytes(im)
            f.write(f"    /* {n} */ {{")
            f.write(",".join(f"0x{v:02x}" for v in b))
            f.write("},\n")
        f.write("};\n")
    # preview: frames 6x scale with labels, white bg, black pixels
    S = 6
    sheet = Image.new("RGB", (len(imgs) * (W * S + 20) + 20, H * S + 60), "white")
    sd = ImageDraw.Draw(sheet)
    for i, (n, im) in enumerate(imgs):
        big = im.convert("L").point(lambda v: 0 if v else 255).resize((W * S, H * S), Image.NEAREST)
        x = 20 + i * (W * S + 20)
        sheet.paste(big.convert("RGB"), (x, 20))
        sd.rectangle([x - 1, 19, x + W * S, 20 + H * S], outline=(180, 180, 180))
        sd.text((x, H * S + 30), n, fill="black")
    sheet.save(f"{outdir}/kiskadee_preview.png")
    for n, im in imgs:
        print("==", n)
        for y in range(0, H, 2):
            print("".join("█" if im.getpixel((x, y)) and im.getpixel((x, y + 1)) else
                          "▀" if im.getpixel((x, y)) else "▄" if y + 1 < H and im.getpixel((x, y + 1)) else " "
                          for x in range(W)))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
