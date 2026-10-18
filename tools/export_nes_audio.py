#!/usr/bin/env python3
"""Export NES Tetris music/sfx bytecode into a C header for the PSP port.

Parses:
  - audio/music/*.asm  : labels defined as ".byte" streams (routine data)
  - main.asm           : musicDataTable (track headers), script pointer tables,
                         noteToWaveTable, noteDurationTable,
                         musicChanVolControlTable + envelopes, noises_table,
                         sound effect init data blobs.

Emits psp/source/data/audio_assets.h with plain C arrays and a small
descriptor layout that the runtime bytecode interpreter consumes.
"""
import os, re, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "psp", "source", "data", "audio_assets.h")

TOKEN_RE = re.compile(r"\$[0-9A-Fa-f]+|%-?[01]+%|\b\d+\b|>[A-Za-z_][\w]*|<[A-Za-z_][\w]*|[A-Za-z_][\w]*")

def eval_token(tok, syms):
    t = tok
    if t.startswith("$"):
        return int(t[1:], 16)
    if t.startswith("%") and t.endswith("%"):
        return int(t[1:-1].replace("_",""), 2)
    hi = False; lo = False
    if t.startswith(">"): hi, t = True, t[1:]
    elif t.startswith("<"): lo, t = True, t[1:]
    if re.fullmatch(r"\d+", t):
        v = int(t)
    else:
        # label value = byte offset recorded during scan
        if t not in syms:
            raise KeyError("unknown symbol: " + t)
        v = syms[t]
    if hi: return (v >> 8) & 0xFF
    if lo: return v & 0xFF
    return v & 0xFFFF

class AsmDataParser:
    """Scans .asm text for label definitions made of .byte/.word/.addr/.dbyt
    directives and .include statements; resolves forward/backward refs."""
    def __init__(self):
        self.data = bytearray()
        self.syms = {}          # label -> offset
        self.fixups = []        # (offset, kind, symname) kind in w,h,l,a(dbyt)

    def load_file(self, path, base_offset=None):
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        i = 0
        pending_label = None
        while i < len(lines):
            line = lines[i]
            i += 1
            # strip comments
            code = line.split(";")[0].rstrip()
            if not code.strip():
                continue
            m = re.match(r"^([A-Za-z_][\w]*):\s*(.*)$", code)
            if m:
                label, rest = m.group(1), m.group(2)
                if label not in self.syms:
                    self.syms[label] = len(self.data)
                code = rest
            inc = re.search(r'\.include\s+"([^"]+)"', code, re.I)
            if inc:
                sub = os.path.normpath(os.path.join(os.path.dirname(path), inc.group(1)))
                self.load_file(sub)
                continue
            mb = re.search(r'\.incbin\s+"([^"]+)"', code, re.I)
            if mb:
                p = os.path.normpath(os.path.join(ROOT, mb.group(1)))
                if os.path.exists(p):
                    self.data.extend(open(p, "rb").read())
                continue
            for d in re.finditer(r"\.(byte|char|dbyt|word|addr)\s+([^\.]*)", code, re.I):
                kind = d.group(1).lower()
                argstr = d.group(2)
                args = [a for a in TOKEN_RE.findall(argstr)]
                if not args: continue
                if kind == "dbyt":
                    # reversed word(s)
                    for a in args:
                        v = eval_token(a, self.syms)
                        self._emit_fixup("l", a)
                        self._emit_fixup("h", a)
                elif kind in ("word", "addr"):
                    for a in args:
                        self._emit_fixup("lo", a)
                        self._emit_fixup("hi", a)
                else:
                    for a in args:
                        try:
                            v = eval_token(a, self.syms)
                        except KeyError:
                            self._emit_fixup("byte", a)
                            self.data.append(0)
                        else:
                            self.data.append(v & 0xFF)
        # resolve fixups now that all symbols known
        out = bytearray(self.data)
        unresolved = []
        for off, kind, sym in self.fixups:
            if sym not in self.syms:
                unresolved.append(sym)
                continue
            v = self.syms[sym]
            if kind in ("lo", "byte"): out[off] = v & 0xFF
            elif kind == "hi": out[off] = (v >> 8) & 0xFF
            elif kind == "l": out[off] = v & 0xFF
            elif kind == "h": out[off] = (v >> 8) & 0xFF
        self.data = out
        self.fixups = []

    def _emit_fixup(self, kind, sym):
        self.fixups.append((len(self.data), kind, sym))
        self.data.append(0)

def c_array(name, arr, per_line=16):
    s = f"static const unsigned char {name}[{len(arr)}] = {{\n"
    for i in range(0, len(arr), per_line):
        chunk = arr[i:i+per_line]
        s += "    " + ",".join(str(b) for b in chunk) + ",\n"
    s += "};\n"
    return s

def main():
    p = AsmDataParser()
    p.load_file(os.path.join(ROOT, "main.asm"))
    data, syms = p.data, p.syms

    def grab(label, length):
        return bytes(data[syms[label]:syms[label] + length])

    # ---- track table ----
    mdti = grab("musicDataTableIndex", 10)      # 10 entries
    hdrs = []
    for k in range(10):
        off = mdti[k]
        note_off = data[off]; tempo = data[off+1]
        chans = []
        for ch in range(4):
            ptr = data[off+2+ch*2] | (data[off+3+ch*2] << 8)
            chans.append(ptr)
        hdrs.append((note_off, tempo, chans))

    # For each channel script pointer: list of routine pointers until $FFFF or 0000
    scripts = []   # each: list of int offsets (terminated by 0 sentinel meaning end-of-list marker from FF FF)
    for note_off, tempo, chans in hdrs:
        for ch in range(4):
            ptr = chans[ch]
            if ptr == 0xFFFF or ptr == 0:
                scripts.append(None)
                continue
            lst = []
            i = ptr
            while True:
                w = data[i] | (data[i+1] << 8)
                if w == 0xFFFF or w == 0x0000:
                    break
                lst.append(w)
                i += 2
            scripts.append(lst)

    # Build dedup blob of routine byte-strings. A routine runs until next script
    # entry boundary; we measure length by scanning to the start of the *next*
    # routine in the same script, else use a generous cap and rely on the
    # interpreter's own terminator ($00/$FF instruction handling is not part of
    # data) -- instead: routines are contiguous; determine bounds by sorting all
    # routine starts globally and taking next-start as end (safe: they are
    # emitted back-to-back in ROM).
    all_starts = sorted({r for s in scripts if s for r in s})
    next_start = {}
    for idx in range(len(all_starts) - 1):
        next_start[all_starts[idx]] = all_starts[idx + 1]

    blob = bytearray()
    map_off = {}
    for st in all_starts:
        end = next_start.get(st, st + 4096)
        chunk = data[st:end]
        # trim trailing padding zeros? keep exact
        map_off[st] = len(blob)
        blob.extend(chunk)

    # Emit per-track structure
    tracks = []
    si = 0
    for (note_off, tempo, chans) in hdrs:
        tchans = []
        for ch in range(4):
            s = scripts[si]; si += 1
            if s is None:
                tchans.append([])
            else:
                tchans.append([map_off[r] for r in s])
        tracks.append((note_off, tempo, tchans))

    # ---- tables ----
    nwt = grab("noteToWaveTable", 0x9C * 2)     # indices 0..0x9B pairs
    ndt = grab("noteDurationTable", 0x60)       # NTSC durations (96 bytes)
    voltab_syms = ["LEA76","LEA82","LEA8B","LEA91","LEA9A","LEAA2","LEAA5","LEAA8",
                   "LEAAC","LEABA","LEAC7","LEAD4","LEADE","LEAE8","LEAF2","LEAF7",
                   "LEAFC","LEB01","LEB05","LEB0A","LEB0D","LEB10"]
    envelopes = []
    for s in voltab_syms:
        st = syms[s]
        env = bytearray()
        while st < len(data) and data[st] != 0x00:
            env.append(data[st])
            if data[st] in (0xF0, 0xFF):  # release / sustain terminators
                break
            st += 1
        envelopes.append(bytes(env))

    noises = grab("noises_table", 0x1F)

    # ---- sound effects: raw 4-byte APU register blobs referenced by "<label"
    sfx_blobs = [
        "soundEffectSlot0_gameOverCurtainInitData",
        "soundEffectSlot0_endingRocketInitData",
        "soundEffectSlot1_rotateTetriminoInitData",
        "soundEffectSlot1Playing_rotateTetriminoStage3",
        "soundEffectSlot1_levelUpInitData",
        "soundEffectSlot1_lockTetriminoInitData",
        "soundEffectSlot1_menuOptionSelectInitData",
        "soundEffectSlot1Playing_menuOptionSelectStage2",
        "soundEffectSlot1_menuScreenSelectInitData",
        "soundEffectSlot1_tetrisAchievedInitData",
        "soundEffectSlot1_lineCompletedInitData",
        "soundEffectSlot1_lineClearingInitData",
        "soundEffectSlot1_chirpChirpSq1Vol_table",
        "soundEffectSlot1Playing_chirpChirpStage2",
        "soundEffectSlot1_shiftTetriminoInitData",
        "soundEffectSlot3_fallingAlienInitData",
        "soundEffectSlot3_donkInitData",
        "music_pause_sq1_even",
        "music_pause_sq1_odd",
    ]
    blob_offsets = {}
    sblob = bytearray()
    for s in sfx_blobs:
        st = syms[s]
        ln = 4
        if s.endswith("chirpChirpSq1Vol_table"): ln = 4
        blob_offsets[s] = len(sblob)
        sblob.extend(data[st:st+ln])

    # line-clearing melody/vol tables
    lc_lo = grab("soundEffectSlot1_lineClearing_lo", 16) if "soundEffectSlot1_lineClearing_lo" in syms else b""
    lc_vol = grab("soundEffectSlot1_lineClearing_vol", 8) if "soundEffectSlot1_lineClearing_vol" in syms else b""

    with open(OUT, "w") as f:
        f.write("/* Auto-generated by tools/export_nes_audio.py -- do not edit.\n"
                "   NES Tetris music/sfx bytecode exported for the PSP native port. */\n"
                "#ifndef AUDIO_ASSETS_H\n#define AUDIO_ASSETS_H\n\n")
        f.write(c_array("mus_blob", blob))
        f.write("\n/* Track headers: note offset, tempo index, 4 channel script lists */\n")
        f.write("typedef struct {\n  unsigned char noteOffset;\n  unsigned char tempo;\n"
                "  unsigned short chanStart[4];\n  unsigned char chanLen[4];\n} mus_track_t;\n\n")
        f.write("static const unsigned short mus_script[] = {\n")
        total = 0
        offs = []
        for (no, tp, tchans) in tracks:
            o = []
            for ch in range(4):
                o.append(total); total += len(tchans[ch])
            offs.append(o)
        flat = []
        for (no, tp, tchans) in tracks:
            flat.extend(tchans[0] + [-1]); 
        # build one flat array with sentinels -1
        flat = []
        layout = []
        for (no, tp, tchans) in tracks:
            row = []
            for ch in range(4):
                row.append(len(flat))
                flat.extend(tchans[ch]); flat.append(0xFFFF)
            layout.append(row)
        for v in flat:
            f.write("    %d,\n" % v)
        f.write("};\n\n")
        f.write("static const mus_track_t mus_tracks[10] = {\n")
        for i, (no, tp, tchans) in enumerate(tracks):
            row = layout[i]
            lens = [len(tchans[ch]) for ch in range(4)]
            f.write("  {%d,%d,{%d,%d,%d,%d},{%d,%d,%d,%d}},\n" %
                    (no, tp, row[0], row[1], row[2], row[3], *lens))
        f.write("};\n\n")
        f.write(c_array("note_to_wave", nwt))
        f.write(c_array("note_duration", ndt))
        f.write("\nstatic const unsigned char *const vol_envs[22] = {\n")
        eblob = bytearray(); eoffs = []
        for e in envelopes:
            eoffs.append(len(eblob)); eblob.extend(e); eblob.append(0)
        f.write(c_array("vol_env_blob", eblob).replace("static const unsigned char vol_env_blob", "static const unsigned char vol_env_blob"))
        f.write("/* envelope nibble strings, NUL terminated */\n")
        f.write("#define VOL_ENV(i) (vol_env_blob + %s[i])\n" % "")
        # simpler: emit explicit offsets
        f.write("static const unsigned short vol_env_off[22] = {%s};\n\n" %
                ",".join(str(x) for x in eoffs))
        f.write(c_array("noises_table", noises))
        f.write(c_array("sfx_blob", sblob))
        f.write("/* sfx blob offsets */\n")
        for s in sfx_blobs:
            f.write("#define SFXO_%s %d\n" % (s.upper(), blob_offsets[s]))
        if lc_lo: f.write(c_array("lc_lo", lc_lo))
        if lc_vol: f.write(c_array("lc_vol", lc_vol))
        f.write("\n#endif\n")
    print("wrote", OUT, "blob", len(blob), "flat", )

if __name__ == "__main__":
    main()
