"""Generate the animated pixel-art README hero for Repo Scan.

usage: python3 tools/build_hero.py id docs/hero.svg && python3 tools/build_hero.py en docs/hero.en.svg
"""
import random
import sys

W, H, T = 1200, 420, 24.0
GROUND = 356

LANG = {
    "id": dict(
        kicker="PEMINDAI KEAMANAN STATIS UNTUK AI AGENT APA SAJA",
        sub1="Cek dulu, baru install. ", sub2="Kode dibaca, tidak dijalankan.",
        chips=[("PINDAI", "TANPA EKSEKUSI", "#5aa9ff"), ("TEMUAN", "28 MASALAH", "#f5b83d"),
               ("VONIS", "BAHAYA", "#f05252")],
        repo="CONTOH-REPO-JAHAT", risk="RISIKO", files="FILE", findings="TEMUAN",
        bubbles=["aman", "prompt injection tersembunyi", ".exe menyamar jadi .png", "aman",
                 "curi kunci SSH -> Discord", "postinstall: curl | sh"],
        danger="BAHAYA", donot="JANGAN DIINSTALL",
        label="Repo Scan: kucing pixel memeriksa file repo satu per satu tanpa menjalankan kodenya. "
              "README.md dan LICENSE aman; SKILL.md (prompt injection tersembunyi), logo.png (.exe menyamar), "
              "index.js (curi kunci SSH ke Discord) dan package.json (postinstall curl | sh) ditandai merah. "
              "Skor risiko naik ke 515 dengan 28 temuan, vonis BAHAYA: jangan diinstall. Bisa dipakai di "
              "Claude Code, Codex, Gemini CLI, Cursor, GitHub Actions dan terminal.",
    ),
    "en": dict(
        kicker="STATIC SECURITY SCANNER FOR ANY AI AGENT",
        sub1="Check first, then install. ", sub2="Reads the code, never runs it.",
        chips=[("SCAN", "READ-ONLY", "#5aa9ff"), ("FIND", "28 ISSUES", "#f5b83d"),
               ("VERDICT", "DANGER", "#f05252")],
        repo="EVIL-SAMPLE-REPO", risk="RISK", files="FILES", findings="FINDINGS",
        bubbles=["clean", "hidden prompt injection", "an .exe posing as .png", "clean",
                 "steals SSH keys -> Discord", "postinstall: curl | sh"],
        danger="DANGER", donot="DO NOT INSTALL",
        label="Repo Scan: a pixel cat inspects a repository file by file without running any code. "
              "README.md and LICENSE are clean; SKILL.md (hidden prompt injection), logo.png (an .exe in "
              "disguise), index.js (steals SSH keys to Discord) and package.json (postinstall curl | sh) are "
              "flagged red. The risk score climbs to 515 with 28 findings and the verdict is DANGER: do not "
              "install. Works in Claude Code, Codex, Gemini CLI, Cursor, GitHub Actions and the terminal.",
    ),
}

FILES = ["README.md", "SKILL.md", "logo.png", "LICENSE", "index.js", "package.json"]
BAD = [False, True, True, False, True, True]
SCORE_ADD = [0, 175, 70, 0, 190, 80]      # -> 515
FIND_ADD = [0, 9, 2, 0, 12, 5]            # -> 28
FILE_X = [430 + 135 * i for i in range(6)]
STOP_X = [x - 62 for x in FILE_X]
CAT_START = 320

RED, GREEN, AMBER, BLUE = "#f05252", "#4ade80", "#f5b83d", "#5aa9ff"
SANS = "'Segoe UI',-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"

# ---------------------------------------------------------------- pixel font 5x7
G = {
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "B": ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
    "C": [".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."],
    "D": ["####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."],
    "E": ["#####", "#....", "#....", "####.", "#....", "#....", "#####"],
    "F": ["#####", "#....", "#....", "####.", "#....", "#....", "#...."],
    "G": [".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".####"],
    "H": ["#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "I": ["###", ".#.", ".#.", ".#.", ".#.", ".#.", "###"],
    "J": ["..###", "...#.", "...#.", "...#.", "#..#.", "#..#.", ".##.."],
    "K": ["#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"],
    "L": ["#....", "#....", "#....", "#....", "#....", "#....", "#####"],
    "M": ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"],
    "N": ["#...#", "#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"],
    "O": [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    "P": ["####.", "#...#", "#...#", "####.", "#....", "#....", "#...."],
    "Q": [".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"],
    "R": ["####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"],
    "S": [".####", "#....", "#....", ".###.", "....#", "....#", "####."],
    "T": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."],
    "U": ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    "V": ["#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."],
    "W": ["#...#", "#...#", "#...#", "#.#.#", "#.#.#", "#.#.#", ".#.#."],
    "X": ["#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"],
    "Y": ["#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."],
    "Z": ["#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"],
    "0": [".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."],
    "1": ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."],
    "2": [".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"],
    "3": ["####.", "....#", "....#", ".###.", "....#", "....#", "####."],
    "4": ["...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."],
    "5": ["#####", "#....", "####.", "....#", "....#", "#...#", ".###."],
    "6": [".###.", "#....", "#....", "####.", "#...#", "#...#", ".###."],
    "7": ["#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."],
    "8": [".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."],
    "9": [".###.", "#...#", "#...#", ".####", "....#", "....#", ".###."],
    "-": ["....", "....", "....", "####", "....", "....", "...."],
    ".": [".", ".", ".", ".", ".", ".", "#"],
    "·": [".", ".", ".", "#", ".", ".", "."],
    ":": [".", ".", "#", ".", ".", "#", "."],
    "/": ["....#", "....#", "...#.", "..#..", ".#...", "#....", "#...."],
    "+": [".....", "..#..", "..#..", "#####", "..#..", "..#..", "....."],
    "!": ["#", "#", "#", "#", "#", ".", "#"],
    " ": ["..", "..", "..", "..", "..", "..", ".."],
}


def fmt(v):
    return ("%.2f" % v).rstrip("0").rstrip(".")


def rect(x, y, w, h, fill, extra=""):
    return '<rect x="%s" y="%s" width="%s" height="%s" fill="%s"%s/>' % (
        fmt(x), fmt(y), fmt(w), fmt(h), fill, extra)


def ptext_width(s, sc=1, track=2):
    w = 0
    for ch in s:
        w += (len(G[ch][0]) + track) * sc
    return w - track * sc


def ptext(s, x, y, fill, sc=1, track=2):
    out = []
    cx = x
    for ch in s:
        g = G[ch]
        for r, row in enumerate(g):
            c = 0
            while c < len(row):
                if row[c] == "#":
                    c2 = c
                    while c2 < len(row) and row[c2] == "#":
                        c2 += 1
                    out.append(rect(cx + c * sc, y + r * sc, (c2 - c) * sc, sc, fill))
                    c = c2
                else:
                    c += 1
        cx += (len(g[0]) + track) * sc
    return "".join(out)


def sprite(rows, pal, ox, oy, sc):
    out = []
    for r, row in enumerate(rows):
        c = 0
        while c < len(row):
            ch = row[c]
            if ch in pal:
                c2 = c
                while c2 < len(row) and row[c2] == ch:
                    c2 += 1
                out.append(rect(ox + c * sc, oy + r * sc, (c2 - c) * sc, sc, pal[ch]))
                c = c2
            else:
                c += 1
    return "".join(out)


# ---------------------------------------------------------------- sprites
CAT_PAL = {"O": "#FF9F43", "L": "#FFE0B8", "D": "#B8641F", "K": "#18181c", "W": "#ffffff",
           "P": "#ff8fa3", "M": "#cfd6e6", "Q": "#9fd0ff", "H": "#8a5a2b"}
WALK_A = [
    "........O.O..",
    "O.......OOOO.",
    "O.......OKWO.",
    ".O......OOOP.",
    "..OOOOOOOOO..",
    "..OLLLLLLOO..",
    "..OOOOOOOO...",
    "..O.O..O.O...",
    "..D.D..D.D...",
]
WALK_B = WALK_A[:7] + ["...OO..OO....", "...DD..DD...."]
SCAN = [  # one extra row on top (y = -40)
    "..............MMM.",
    "........O.O..MQQQM",
    "O.......OOOO.MQQQM",
    "O.......OKWO.MQQQM",
    ".O......OOOP.HMMM.",
    "..OOOOOOOOOOH.....",
    "..OLLLLLLOOL......",
    "..OOOOOOOO........",
    "..O.O..O.O........",
    "..D.D..D.D........",
]
LENS = [r.replace("M", ".").replace("O", ".").replace("L", ".").replace("D", ".").replace("K", ".")
        .replace("W", ".").replace("P", ".").replace("H", ".") for r in SCAN]

FILE_PAL = {"F": "#d9dce6", "C": "#9aa0b4", "L": "#7c8399", "S": BLUE, "Y": AMBER, "G": GREEN}
TOP = ["FFFFFFC...", "FFFFFFCC..", "FFFFFFCCC.", "FFFFFFFFFF"]


def doc(lines):
    rows = list(TOP)
    for i in range(9):
        rows.append("FFFFFFFFFF" if i % 2 == 0 else "F" + "L" * lines[i // 2] + "F" * (9 - lines[i // 2]))
    return rows


IMG = TOP + ["FSSSSSSSSF", "FSSSSSYYSF", "FSSSSSYYSF", "FSSGSSSSSF", "FSGGGSSGSF", "FGGGGGGGGF",
             "FFFFFFFFFF", "FLLLLLFFFF", "FFFFFFFFFF"]
FILE_SPRITES = [doc([6, 4, 7, 5]), doc([4, 7, 6, 3]), IMG, doc([7, 7, 5, 6]), doc([5, 7, 6, 4]),
                doc([3, 6, 7, 5])]

CHECK = [".......", ".....W.", "....WW.", ".W.WW..", ".WWW...", "..W....", "......."]
CROSS = [".......", ".W...W.", "..W.W..", "...W...", "..W.W..", ".W...W.", "......."]
BANG = ["##", "##", "##", "##", "..", "##"]
SHIELD = [
    ".RRRRRRRRR.",
    "RRRRRRRRRRD",
    "RRWRRRRRWRD",
    "RRRWRRRWRRD",
    "RRRRWRWRRRD",
    "RRRRRWRRRRD",
    "RRRRWRWRRRD",
    "RRRWRRRWRRD",
    "RRWRRRRRWRD",
    ".RRRRRRRRD.",
    "..RRRRRRD..",
    "...RRRRD...",
    "....RRD....",
]

# ---------------------------------------------------------------- animation helpers
KF = []


def P(t, base=T):
    return "%.3f%%" % (100.0 * max(0.0, min(base, t)) / base)


def keyframes(frames, base=T):
    name = "k%d" % (len(KF) + 1)
    seen = {}
    for t, css in frames:
        seen[P(t, base)] = css
    body = "".join("%s{%s}" % (p, c) for p, c in seen.items())
    KF.append("@keyframes %s{%s}" % (name, body))
    return name


def anim(frames, timing="linear", dur=T, delay=0):
    return ' style="animation:%s %ss %s %ss infinite"' % (keyframes(frames, dur), fmt(dur), timing, fmt(delay))


def steps(points, prop="opacity"):
    """points: [(t, value)] -> step-end style attr. Value holds from t onward."""
    fr = [(0, "%s:%s" % (prop, points[0][1]))] + [(t, "%s:%s" % (prop, v)) for t, v in points]
    fr.append((T, "%s:%s" % (prop, points[-1][1])))
    return anim(fr, "step-end")


def pop(cx, cy, inner, t, extra_frames=None, cls=""):
    fr = [(0, "transform:scale(0)"), (t, "transform:scale(0)"), (t + 0.25, "transform:scale(1.15)"),
          (t + 0.4, "transform:scale(1)"), (T, "transform:scale(1)")]
    if extra_frames:
        fr = extra_frames
    c = ' class="%s"' % cls if cls else ""
    return '<g transform="translate(%s %s)"%s><g%s><g transform="translate(%s %s)">%s</g></g></g>' % (
        fmt(cx), fmt(cy), c, anim(fr), fmt(-cx), fmt(-cy), inner)


# ---------------------------------------------------------------- timeline
WALK_START = [1.0 + 3 * i for i in range(6)]
ARRIVE = [w + 1.0 for w in WALK_START]
RESULT = [a + 1.1 for a in ARRIVE]
VERDICT = 19.0
OUTRO = 23.2


def build(lang):
    L = LANG[lang]
    KF.clear()
    rnd = random.Random(7)
    o = []
    a = o.append

    a('<rect width="%d" height="%d" fill="url(#sky)"/>' % (W, H))

    # stars
    for _ in range(70):
        x, y = rnd.randrange(0, W, 1), rnd.randrange(0, 300, 1)
        col = rnd.choice(["#2c2c33", "#5a5a63", "#8a8a96"])
        d = rnd.choice([1.7, 2.3, 3.1, 4.3])
        a(rect(x, y, 2, 2, col, ' class="tw" style="animation-duration:%ss;animation-delay:-%ss"' % (
            d, fmt(rnd.random() * d))))

    # skyline (two layers) with windows
    for layer, (col, hmin, hmax, win) in enumerate([("#0f0f13", 60, 150, "#1b1b22"), ("#141419", 30, 96, "#202029")]):
        x = -rnd.randrange(0, 40, 4)
        while x < W:
            bw = rnd.randrange(28, 72, 4)
            bh = rnd.randrange(hmin, hmax, 4)
            top = GROUND - bh
            a(rect(x, top, bw, bh, col))
            if rnd.random() < 0.35:
                a(rect(x + bw // 2 - 2, top - 12, 4, 12, col))
            for wy in range(top + 8, GROUND - 8, 12):
                for wx in range(x + 6, x + bw - 8, 10):
                    r = rnd.random()
                    if r < 0.55:
                        continue
                    if r < 0.93:
                        a(rect(wx, wy, 4, 4, win))
                    else:
                        lit = rnd.choice([BLUE, GREEN, AMBER])
                        d = rnd.choice([3.1, 4.3, 5.9])
                        a(rect(wx, wy, 4, 4, lit, ' opacity="%s" class="tw" style="animation-duration:%ss;'
                               'animation-delay:-%ss"' % (0.35 if layer else 0.22, d, fmt(rnd.random() * d))))
            x += bw + rnd.randrange(0, 12, 4)

    # ground
    a(rect(0, GROUND, W, H - GROUND, "#0d0d11"))
    a(rect(0, GROUND, W, 4, "#26262e"))
    for x in range(8, W, 24):
        a(rect(x, GROUND + 8, 10, 2, "#1d1d24"))
    for x in range(12, W, 48):
        a(rect(x, 400, 4, 4, "#1f5f3a"))

    # ---------------------------------------------------------- files
    for i, fx in enumerate(FILE_X):
        top = GROUND - 52
        a(sprite(FILE_SPRITES[i], FILE_PAL, fx - 20, top, 4))
        a('<text x="%d" y="%d" font-family="%s" font-size="11" fill="#5c5c68" text-anchor="middle">%s</text>' % (
            fx, GROUND + 26, MONO, FILES[i]))
        lit = RED if BAD[i] else GREEN
        a('<text x="%d" y="%d" font-family="%s" font-size="11" font-weight="700" fill="%s" text-anchor="middle"%s>%s</text>' % (
            fx, GROUND + 26, MONO, lit, steps([(0, 0), (RESULT[i], 1)]), FILES[i]))
        if BAD[i]:
            tint = sprite(FILE_SPRITES[i], {k: RED for k in FILE_PAL}, fx - 20, top, 4)
            a('<g opacity="0.55"><g%s>%s</g></g>' % (steps([(0, 0), (RESULT[i], 1)]), tint))
        # scan beam
        y0 = top - 2
        beam = (rect(fx - 24, y0 - 7, 48, 16, "url(#beam)") + rect(fx - 24, y0, 48, 3, GREEN))
        mid = (ARRIVE[i] + RESULT[i]) / 2
        a('<g class="tmp"%s>%s</g>' % (anim([
            (0, "opacity:0;transform:translateY(0)"), (ARRIVE[i] + 0.05, "opacity:0;transform:translateY(0)"),
            (ARRIVE[i] + 0.1, "opacity:1;transform:translateY(0)"), (mid, "opacity:1;transform:translateY(50px)"),
            (RESULT[i] - 0.05, "opacity:1;transform:translateY(0)"), (RESULT[i], "opacity:0;transform:translateY(0)"),
            (T, "opacity:0;transform:translateY(0)")]), beam))
        # badge
        bx, by = fx + 10, top - 12
        badge = (rect(bx - 1, by - 1, 23, 23, "#0b0b0e") + rect(bx, by, 21, 21, lit) +
                 sprite(CROSS if BAD[i] else CHECK, {"W": "#ffffff"}, bx, by, 3))
        a(pop(bx + 10.5, by + 10.5, badge, RESULT[i]))

    # ---------------------------------------------------------- cat
    def cat_layers():
        walk = ('<g%s><g%s>%s</g><g%s>%s</g></g>' % (
            steps([(0, 0)] + sum([[(WALK_START[i], 1), (ARRIVE[i], 0)] for i in range(6)], [])),
            anim([(0, "opacity:1"), (0.2, "opacity:0"), (0.4, "opacity:0")], "step-end", 0.4),
            sprite(WALK_A, CAT_PAL, -24, -36, 4),
            anim([(0, "opacity:0"), (0.2, "opacity:1"), (0.4, "opacity:1")], "step-end", 0.4),
            sprite(WALK_B, CAT_PAL, -24, -36, 4)))
        glint = '<g%s>%s</g>' % (
            anim([(0, "opacity:1"), (0.15, "opacity:0"), (0.3, "opacity:0")], "step-end", 0.3),
            sprite(LENS, {"Q": GREEN}, -24, -40, 4))
        pose = '<g%s>%s%s</g>' % (
            steps([(0, 1)] + sum([[(WALK_START[i], 0), (ARRIVE[i], 1)] for i in range(6)], [])),
            sprite(SCAN, CAT_PAL, -24, -40, 4), glint)
        return walk.replace("<g style", '<g class="tmp" style', 1) + pose

    cat_fr = [(0, CAT_START), (WALK_START[0], CAT_START)]
    prev = CAT_START
    for i in range(6):
        cat_fr += [(WALK_START[i], prev), (ARRIVE[i], STOP_X[i])]
        prev = STOP_X[i]
    cat_fr.append((T, prev))
    a('<g transform="translate(%d %d)"%s>%s</g>' % (
        STOP_X[-1], GROUND, anim([(t, "transform:translate(%dpx,%dpx)" % (x, GROUND)) for t, x in cat_fr]),
        cat_layers()))

    # "!" when a threat is found
    for i in range(6):
        if not BAD[i]:
            continue
        ex, ey = STOP_X[i] + 6, GROUND - 66
        r = RESULT[i]
        a('<g class="tmp"%s>%s</g>' % (anim([
            (0, "opacity:0;transform:translateY(0)"), (r, "opacity:0;transform:translateY(0)"),
            (r + 0.08, "opacity:1;transform:translateY(-8px)"), (r + 0.3, "opacity:1;transform:translateY(0)"),
            (r + 0.9, "opacity:1;transform:translateY(0)"), (r + 1.1, "opacity:0;transform:translateY(0)"),
            (T, "opacity:0;transform:translateY(0)")]),
            rect(ex - 2, ey - 2, 12, 22, "#0b0b0e") + sprite(BANG, {"#": RED}, ex, ey, 4)))

    # finding bubbles
    for i, fx in enumerate(FILE_X):
        txt = L["bubbles"][i]
        bw = len(txt) * 7.25 + 30
        bx = min(max(fx - bw / 2, 306), W - 10 - bw)
        by = GROUND - 100
        col = RED if BAD[i] else GREEN
        inner = (rect(bx + 3, by + 3, bw, 24, "#000000") + rect(bx, by, bw, 24, "#f3ead7") +
                 rect(bx + 1, by + 1, bw - 2, 22, "none", ' stroke="#18181c" stroke-width="2"') +
                 rect(bx + 8, by + 8, 8, 8, col) +
                 '<text x="%s" y="%s" font-family="%s" font-size="12" font-weight="700" fill="#18181c">%s</text>' % (
                     fmt(bx + 22), fmt(by + 16.5), MONO, txt.replace("<", "&lt;").replace(">", "&gt;")))
        r = RESULT[i]
        hide = (WALK_START[i + 1] + 0.6) if i < 5 else VERDICT - 0.2
        fr = [(0, "opacity:0;transform:scale(.6)"), (r, "opacity:0;transform:scale(.6)"),
              (r + 0.18, "opacity:1;transform:scale(1.06)"), (r + 0.3, "opacity:1;transform:scale(1)"),
              (hide, "opacity:1;transform:scale(1)"), (hide + 0.3, "opacity:0;transform:scale(1)"),
              (T, "opacity:0;transform:scale(1)")]
        a(pop(bx + bw / 2, by + 24, inner, r, fr, cls="tmp"))

    # ---------------------------------------------------------- verdict
    a('<rect width="%d" height="%d" fill="%s" class="tmp"%s/>' % (W, H, RED, anim([
        (0, "opacity:0"), (VERDICT, "opacity:0"), (VERDICT + 0.15, "opacity:.13"), (VERDICT + 0.45, "opacity:0"),
        (VERDICT + 0.6, "opacity:.13"), (VERDICT + 0.9, "opacity:0"), (T, "opacity:0")])))
    vx, vy = 700, 112
    dw = ptext_width(L["donot"], 2, 1)
    vw = 93 + max(dw, 176) + 22
    v = (rect(vx + 4, vy + 4, vw, 101, "#000000") + rect(vx, vy, vw, 101, "#0b0b0e") +
         rect(vx + 1, vy + 1, vw - 2, 99, "none", ' stroke="%s" stroke-width="2"' % RED) +
         sprite(SHIELD, {"R": RED, "D": "#b42d2d", "W": "#ffffff"}, vx + 18, vy + 18, 5) +
         '<text x="%d" y="%d" font-family="%s" font-size="44" font-weight="800" fill="%s" textLength="%d" '
         'lengthAdjust="spacingAndGlyphs">%s</text>' % (vx + 91, vy + 58, SANS, RED, 176, L["danger"]) +
         ptext(L["donot"], vx + 93, vy + 70, "#e8e8ee", 2, 1))
    a(pop(vx + vw / 2, vy + 50, v, VERDICT))

    # curtain (intro/outro)
    a('<rect x="300" y="48" width="900" height="372" fill="#000000" class="tmp"%s/>' % anim([
        (0, "opacity:1"), (0.3, "opacity:1"), (0.9, "opacity:0"), (OUTRO, "opacity:0"), (OUTRO + 0.6, "opacity:1"),
        (T, "opacity:1")]))

    # ---------------------------------------------------------- header text
    a(ptext(L["kicker"], 42, 34, BLUE, 1, 2))
    a('<text x="40" y="92" font-family="%s" font-size="46" font-weight="800" fill="#ffffff" textLength="238" '
      'lengthAdjust="spacingAndGlyphs" letter-spacing="-1">Repo Scan</text>' % SANS)
    a(sprite(SCAN, CAT_PAL, 292, 56, 3))
    a('<text x="42" y="124" font-family="%s" font-size="18" font-weight="700" fill="#ffffff">%s'
      '<tspan fill="%s">%s</tspan></text>' % (SANS, L["sub1"], GREEN, L["sub2"]))

    cx = 42
    lit_at = [WALK_START[0], RESULT[-1], VERDICT]
    for (k, v, col), t in zip(L["chips"], lit_at):
        kw, vw2 = ptext_width(k) + 16, ptext_width(v) + 16
        a(rect(cx, 141, kw + vw2, 19, "#1c1c22"))
        a(ptext(k, cx + 8, 147, "#55555f"))
        a(ptext(v, cx + kw + 8, 147, "#33333b"))
        a('<g%s>%s%s%s</g>' % (steps([(0, 0), (t, 1)]), ptext(k, cx + 8, 147, "#cfd3dc"), rect(cx + kw, 141, vw2, 19, col),
                               ptext(v, cx + kw + 8, 147, "#0b0b0e")))
        cx += kw + vw2 + 10

    # ---------------------------------------------------------- stats panel
    a(rect(40, 292, 250, 100, "#0b0b0e"))
    a(rect(41, 293, 248, 98, "none", ' stroke="#3a3a44" stroke-width="2"'))
    a(ptext("%s · %s" % (L["repo"], L["risk"]), 58, 306, "#8a8a96"))
    a(ptext(L["files"], 200, 324, "#8a8a96"))
    for i in range(6):
        sx = 200 + 12 * i
        a(rect(sx, 335, 8, 8, "#2a2a33"))
        a(rect(sx, 335, 8, 8, RED if BAD[i] else GREEN, steps([(0, 0), (RESULT[i], 1)])))
    a(ptext(L["findings"], 58, 376, "#8a8a96"))
    score, finds = 0, 0
    states = [(0.0, 0, 0)]
    for i in range(6):
        if SCORE_ADD[i]:
            score += SCORE_ADD[i]
            finds += FIND_ADD[i]
            states.append((RESULT[i], score, finds))
    for j, (t, s, f) in enumerate(states):
        end = states[j + 1][0] if j + 1 < len(states) else None
        pts = [(0, 0), (t, 1)] + ([(end, 0)] if end else [])
        if t == 0:
            pts = [(0, 1), (end, 0)]
        last = end is None
        colr = "#ffffff" if s == 0 else (RED if last else AMBER)
        cls = "" if last else ' class="tmp"'
        a('<g%s><g%s><text x="56" y="365" font-family="%s" font-size="40" font-weight="800" fill="%s">%d</text>'
          '<text x="274" y="382" font-family="%s" font-size="14" font-weight="700" fill="%s" text-anchor="end">%d</text>'
          '</g></g>' % (cls, steps(pts), SANS, colr, s, SANS, AMBER, f))

    # ---------------------------------------------------------- works with chips
    tools = [("Claude Code", "#D97757"), ("Codex", "#e8e8ee"), ("Gemini CLI", "#8b7cf6"), ("Cursor", "#9aa0b4"),
             ("GitHub Actions", "#2f81f7"), ("Terminal", GREEN)]
    widths = [len(n) * 6.9 for n, _ in tools]
    total = sum(w + 30 for w in widths) + 8 * (len(tools) - 1)
    cx = W - 18 - total
    for k, ((name, col), tw) in enumerate(zip(tools, widths)):
        cw = tw + 30
        inner = (rect(cx + 2, 16, cw, 26, "#000000") + rect(cx, 14, cw, 26, "#ffffff") +
                 rect(cx + 1, 15, cw - 2, 24, "none", ' stroke="%s" stroke-width="2"' % BLUE) +
                 rect(cx + 9, 23, 8, 8, col) +
                 '<text x="%s" y="%s" font-family="%s" font-size="12" font-weight="700" fill="#18181c" '
                 'textLength="%s" lengthAdjust="spacingAndGlyphs">%s</text>' % (
                     fmt(cx + 22), 31.5, SANS, fmt(tw), name))
        t = VERDICT + 0.6 + 0.25 * k
        fr = [(0, "opacity:0;transform:scale(0)"), (t, "opacity:0;transform:scale(0)"),
              (t + 0.2, "opacity:1;transform:scale(1.12)"), (t + 0.32, "opacity:1;transform:scale(1)"),
              (OUTRO, "opacity:1;transform:scale(1)"), (OUTRO + 0.6, "opacity:0;transform:scale(1)"),
              (T, "opacity:0;transform:scale(1)")]
        a(pop(cx + cw / 2, 27, inner, t, fr))
        cx += cw + 8

    return "".join(o), "".join(KF)


def main():
    lang, out = sys.argv[1], sys.argv[2]
    body, css = build(lang)
    L = LANG[lang]
    style = (
        "rect{shape-rendering:crispEdges}"
        ".tw{animation:tw 2s linear infinite}"
        "@keyframes tw{0%{opacity:1}50%{opacity:.25}100%{opacity:1}}"
        + css +
        "@media (prefers-reduced-motion:reduce){*{animation:none!important}.tmp{display:none}}"
    )
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" '
           'aria-label="%s"><title>%s</title><defs><style>%s</style>'
           '<linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#000000"/>'
           '<stop offset="1" stop-color="#0b0b0e"/></linearGradient>'
           '<linearGradient id="beam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="%s" stop-opacity="0"/>'
           '<stop offset=".5" stop-color="%s" stop-opacity=".45"/><stop offset="1" stop-color="%s" stop-opacity="0"/>'
           '</linearGradient></defs>%s</svg>\n') % (W, H, W, H, L["label"], L["label"], style, GREEN, GREEN, GREEN, body)
    open(out, "w").write(svg)
    print(out, len(svg), "bytes")


if __name__ == "__main__":
    main()
