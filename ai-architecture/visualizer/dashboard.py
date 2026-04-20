"""
AI-IDS SOC Dashboard — TUI/Cyberpunk aesthetic
Wired to the real pipeline via run.py. Not intended to run standalone.
Keys: Q / ESC → quit
"""
import pygame
import threading
import time
import math
import sys
import os
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Palette ───────────────────────────────────────────────────
BG       = (8,   13,  19)
BG2      = (13,  21,  32)
BG3      = (17,  30,  46)
BG4      = (22,  38,  58)
BORDER   = (30,  53,  80)
BORDER2  = (42,  74, 106)
TXT      = (176, 200, 216)
TXT_DIM  = (74,  106, 128)
TXT_HEAD = (111, 168, 200)
GREEN    = (0,   229, 122)
CYAN     = (0,   200, 255)
YELLOW   = (240, 200,  50)
ORANGE   = (255, 120,  32)
RED      = (255,  58,  58)
PURPLE   = (176,  80, 255)
PINK     = (255,  80, 180)
TEAL     = (0,   216, 180)
LIME     = (144, 224,  32)
WHITE    = (220, 230, 240)

DECISION_COL = {
    "Ignore":   TXT_DIM,
    "Log":      CYAN,
    "Alert":    YELLOW,
    "Block":    RED,
    "Escalate": PURPLE,
}
DEC_SLICES = ["Ignore", "Log", "Alert", "Block", "Escalate"]
DEC_COLORS = [TXT_DIM, CYAN, YELLOW, RED, PURPLE]
CLS_COLORS = [GREEN, CYAN, YELLOW, ORANGE, RED, PURPLE, PINK, TEAL, LIME]
PRO_COLORS = [CYAN, GREEN, YELLOW, ORANGE, RED, PURPLE]

# ── State ─────────────────────────────────────────────────────
lock = threading.RLock()

def _fresh_state():
    return {
        "running":       True,
        "frame_id":      0,
        "pkts":          0,
        "ids_pkts":      0,
        "alerts":        0,
        "blocks":        0,
        "esc":           0,
        "db_size":       0,
        "q_depth":       0,
        "dec_counts":    [0, 0, 0, 0, 0],
        "cls":           {},
        "proto":         {},
        "conf_trend":    deque(maxlen=80),
        "alert_terms":   [],
        "top_sources":   [],
        "flow_log":      deque(maxlen=60),
        "timeline":      [],
        "tl_live":       {"total":0,"alert":0,"block":0,"log":0,"ignore":0,"t":""},
        "tl_last":       time.time(),
        "atk": {
            "enabled":  False,
            "sent":     0,
            "blocked":  0,
            "evaded":   0,
            "gen":      0,
            "profile":  "—",
            "decision": "—",
            "target":   "—",
            "top":      "—",
        },
        "ids_connected": False,
        "ids_interface": "—",
    }

state = _fresh_state()

# ── Pipeline callbacks ────────────────────────────────────────
def _record(dec, src, atk, proto, conf):
    with lock:
        s = state
        s["pkts"] += 1
        if dec == "Alert":    s["alerts"] += 1
        if dec == "Block":    s["blocks"] += 1
        if dec == "Escalate": s["esc"]    += 1

        idx = DEC_SLICES.index(dec) if dec in DEC_SLICES else 0
        s["dec_counts"][idx] += 1
        if atk and atk != "none":
            s["cls"][atk]     = s["cls"].get(atk, 0) + 1
        s["proto"][proto] = s["proto"].get(proto, 0) + 1
        s["conf_trend"].append(conf)

        s["flow_log"].appendleft({
            "tag":   f"[{dec[:3].upper()}]",
            "msg":   f"{src[:16]}  {atk}  {conf:.2f}",
            "color": DECISION_COL.get(dec, TXT_DIM),
        })

        found = False
        for e in s["top_sources"]:
            if e["src"] == src:
                e["count"] += 1; e["decision"] = dec; found = True; break
        if not found:
            s["top_sources"].append({"src": src, "count": 1, "decision": dec})
        s["top_sources"].sort(key=lambda x: -x["count"])
        s["top_sources"] = s["top_sources"][:8]

        if dec in ("Alert", "Block") and atk not in ("none", "—", ""):
            for t in s["alert_terms"]:
                if t["term"] == atk:
                    t["count"] += 1; break
            else:
                s["alert_terms"].append({"term": atk, "count": 1})
            s["alert_terms"].sort(key=lambda x: -x["count"])
            s["alert_terms"] = s["alert_terms"][:12]

        now = time.time()
        s["tl_live"]["total"] += 1
        key = dec.lower()
        if key in s["tl_live"]:
            s["tl_live"][key] += 1
        else:
            s["tl_live"]["ignore"] += 1
        s["tl_live"]["t"] = time.strftime("%H:%M")
        if now - s["tl_last"] > 1.0:   # was 3.0 — flush every second
            s["timeline"].append(dict(s["tl_live"]))
            if len(s["timeline"]) > 32:
                s["timeline"].pop(0)
            s["tl_live"] = {"total":0,"alert":0,"block":0,"log":0,"ignore":0,"t":time.strftime("%H:%M")}
            s["tl_last"] = now

        s["_gen"] = s.get("_gen", 0) + 1   # signal render loop to re-snapshot

def on_cnn_layer(data):
    pass

def on_cnn_features(data):
    with lock:
        state["frame_id"] = data.get("frame_id", state["frame_id"])
        state["_gen"] = state.get("_gen", 0) + 1

def on_rnn_context(data):
    pass

def on_decoder_output(data):
    dec   = data.get("decision", "Ignore")
    src   = data.get("source", "—")
    atk   = data.get("attack_class", "none")
    conf  = data.get("confidence", 0.0)
    proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(data.get("protocol", 0), "Other")
    with lock:
        # frame_id advances on every decoded output, not just CNN features
        if "frame_id" in data:
            state["frame_id"] = data["frame_id"]
            state["pkts"] = data["frame_id"]
        _record(dec, src, atk, proto, conf)

def on_db_logged(data):
    with lock:
        state["db_size"] = data.get("db_size", state["db_size"])
        # Increment generation to trigger re-render
        state["_gen"] = state.get("_gen", 0) + 1

def on_db_retrieved(data):
    with lock:
        state["decoder_db_hits"] = data.get("count", state.get("decoder_db_hits", 0))
        state["decoder_mem"] = data.get("count", 0) > 0
        state["_gen"] = state.get("_gen", 0) + 1

def on_ids_export(data):
    pass

# ── Drawing helpers ───────────────────────────────────────────
def _panel(surf, r, title, fonts, title_col=TXT_HEAD):
    pygame.draw.rect(surf, BG2, r, border_radius=3)
    pygame.draw.rect(surf, BORDER, r, width=1, border_radius=3)
    if title:
        hdr = pygame.Rect(r.x, r.y, r.w, 20)
        pygame.draw.rect(surf, BG3, hdr, border_radius=3)
        pygame.draw.line(surf, BORDER2, (r.x, r.y+20), (r.right, r.y+20), 1)
        surf.blit(fonts["sm"].render(title, True, title_col), (r.x+7, r.y+3))
        pygame.draw.rect(surf, title_col, (r.x+1, r.y+6, 4, 8), border_radius=1)

def _trunc(font, text, max_w):
    if font.size(text)[0] <= max_w:
        return text
    # Binary search for the longest prefix that fits
    lo, hi = 0, len(text)
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if font.size(text[:mid] + "…")[0] <= max_w:
            lo = mid
        else:
            hi = mid
    return text[:lo] + "…" if lo > 0 else "…"

def _hbar(surf, x, y, w, h, val, col):
    val = max(0.0, min(1.0, val))
    pygame.draw.rect(surf, BG4, (x, y, w, h), border_radius=2)
    fw = int(val * w)
    if fw > 1:
        pygame.draw.rect(surf, col, (x, y, fw, h), border_radius=2)

def _donut(surf, cx, cy, r_out, r_in, slices, colors, fonts, center_label=""):
    total = sum(slices) or 1
    angle = -math.pi / 2
    for i, val in enumerate(slices):
        if val <= 0:
            continue
        sweep = (val / total) * 2 * math.pi
        col   = colors[i % len(colors)]
        steps = max(6, int(sweep * 24))
        pts_out, pts_in = [], []
        for s in range(steps + 1):
            a = angle + s * sweep / steps
            pts_out.append((cx + r_out * math.cos(a), cy + r_out * math.sin(a)))
            pts_in.append( (cx + r_in  * math.cos(a), cy + r_in  * math.sin(a)))
        poly = pts_out + list(reversed(pts_in))
        if len(poly) >= 3:
            pygame.draw.polygon(surf, col, poly)
        angle += sweep
    pygame.draw.circle(surf, BG2, (int(cx), int(cy)), int(r_in)-1)
    if center_label and fonts:
        lbl = fonts["xs"].render(center_label, True, TXT)
        surf.blit(lbl, (cx - lbl.get_width()//2, cy - lbl.get_height()//2))

def _sparkline(surf, r, data, col, fill_alpha=30):
    if len(data) < 2:
        return
    pts = list(data)
    mn, mx = min(pts), max(pts)
    rng  = max(mx - mn, 1e-6)
    step = r.w / max(len(pts)-1, 1)
    coords = []
    for i, v in enumerate(pts):
        px = r.x + int(i * step)
        py = r.y + r.h - int(((v-mn)/rng) * (r.h-4)) - 2
        coords.append((px, py))
    # Dim solid fill — no SRCALPHA surface allocation
    fill_col = tuple(max(0, c // (100 // max(fill_alpha, 1))) for c in col)
    fill_pts = [(coords[0][0], r.bottom)] + coords + [(coords[-1][0], r.bottom)]
    if len(fill_pts) >= 3:
        pygame.draw.polygon(surf, fill_col, fill_pts)
    if len(coords) >= 2:
        pygame.draw.lines(surf, col, False, coords, 2)
    pygame.draw.circle(surf, WHITE, coords[-1], 3)

# ── Layout ────────────────────────────────────────────────────
def _layout(W, H):
    P   = 5
    TOP = 26
    R1H = int((H - TOP - 4*P) * 0.37)
    R2H = int((H - TOP - 4*P) * 0.31)
    R3H = H - TOP - R1H - R2H - 4*P
    y1  = TOP + P;  y2 = y1 + R1H + P;  y3 = y2 + R2H + P
    UW  = W - 2*P
    tw  = int(UW * 0.56);  aw  = int(UW * 0.22);  trw = UW - tw - aw - 2*P
    dw  = int(UW * 0.155); sw  = int(UW * 0.21);  cw  = UW - 3*dw - sw - 4*P
    lw  = int(UW * 0.64);  akw = UW - lw - P
    return {
        "topbar":    pygame.Rect(0,                       0,  W,   TOP),
        "timeline":  pygame.Rect(P,                       y1, tw,  R1H),
        "alerts":    pygame.Rect(P+tw+P,                  y1, aw,  R1H),
        "terms":     pygame.Rect(P+tw+P+aw+P,             y1, trw, R1H),
        "donut_dec": pygame.Rect(P,                       y2, dw,  R2H),
        "donut_cls": pygame.Rect(P+dw+P,                  y2, dw,  R2H),
        "donut_pro": pygame.Rect(P+2*(dw+P),              y2, dw,  R2H),
        "conf":      pygame.Rect(P+3*(dw+P),              y2, cw,  R2H),
        "sources":   pygame.Rect(P+3*(dw+P)+cw+P,         y2, sw,  R2H),
        "log":       pygame.Rect(P,                       y3, lw,  R3H),
        "attacker":  pygame.Rect(P+lw+P,                  y3, akw, R3H),
    }

def _make_scanline(W, H):
    surf = pygame.Surface((W, H), pygame.SRCALPHA)
    for y in range(0, H, 4):
        pygame.draw.line(surf, (0, 200, 255, 6), (0, y), (W, y), 1)
    return surf

def _make_fonts(H):
    base = max(9, min(13, H // 72))
    return {
        "xs":   pygame.font.SysFont("Consolas,Courier New,monospace", max(8, base-1)),
        "sm":   pygame.font.SysFont("Consolas,Courier New,monospace", base),
        "md":   pygame.font.SysFont("Consolas,Courier New,monospace", base+3, bold=True),
        "lg":   pygame.font.SysFont("Consolas,Courier New,monospace", base+8, bold=True),
        "logo": pygame.font.SysFont("Consolas,Courier New,monospace", base+2, bold=True),
        "card": pygame.font.SysFont("Consolas,Courier New,monospace", base,   bold=True),
    }

# ── Panel renderers ───────────────────────────────────────────
def _draw_topbar(surf, s, fonts, W):
    pygame.draw.rect(surf, BG3, (0, 0, W, 26))
    pygame.draw.line(surf, BORDER2, (0, 25), (W, 25), 1)
    logo = fonts["logo"].render("AI-IDS", True, CYAN)
    surf.blit(logo, (10, 4))
    pygame.draw.line(surf, BORDER, (10+logo.get_width()+8, 5), (10+logo.get_width()+8, 21), 1)
    pulse_col = GREEN if s["ids_connected"] else RED
    t = time.time()
    # Pulse by modulating brightness — no per-frame surface allocation
    factor = 0.5 + 0.5 * math.sin(t * 3)
    p_col  = tuple(int(c * (0.5 + 0.5 * factor)) for c in pulse_col)
    pygame.draw.circle(surf, p_col, (logo.get_width()+24, 13), 4)
    mode = "LIVE" if s["ids_connected"] else "SYNTHETIC"
    surf.blit(fonts["xs"].render(f"{mode} · {s['ids_interface']}", True, GREEN if s["ids_connected"] else YELLOW),
              (logo.get_width()+34, 8))
    surf.blit(fonts["xs"].render(time.strftime("%H:%M:%S"), True, TXT_DIM), (logo.get_width()+160, 8))
    q = s["q_depth"]
    q_col = RED if q > 500 else (YELLOW if q > 100 else TEAL)
    cards = [
        ("FRAMES", str(s["frame_id"]),  CYAN),
        ("PROC",   str(s["pkts"]),      TXT_HEAD),
        ("CAP",    str(s["ids_pkts"]),  TXT_DIM),
        ("ALERTS", str(s["alerts"]),    YELLOW),
        ("BLOCKS", str(s["blocks"]),    RED),
        ("ESC",    str(s["esc"]),       PURPLE),
        ("DB",     str(s["db_size"]),   PURPLE),
        ("Q",      str(q),              q_col),
    ]
    x = W - 8
    for lbl, val, col in reversed(cards):
        vs = fonts["card"].render(val, True, col)
        ls = fonts["xs"].render(lbl, True, TXT_DIM)
        tw = max(vs.get_width(), ls.get_width()) + 16
        x -= tw
        surf.blit(ls, (x + (tw-ls.get_width())//2, 3))
        surf.blit(vs, (x + (tw-vs.get_width())//2, 12))
        pygame.draw.line(surf, BORDER, (x-1, 4), (x-1, 22), 1)

def _draw_timeline(surf, r, s, fonts):
    _panel(surf, r, "EVENTS OVER TIME", fonts, CYAN)
    tl = list(s["timeline"])
    if s["tl_live"]["total"] > 0:
        tl = tl + [s["tl_live"]]
    if not tl:
        surf.blit(fonts["sm"].render("waiting for events…", True, TXT_DIM), (r.x+10, r.y+34))
        # legend still shown
    else:
        inner = pygame.Rect(r.x+6, r.y+24, r.w-12, r.h-32)
        keys  = ["total","alert","block","log","ignore"]
        cols  = [CYAN, YELLOW, RED, GREEN, TXT_DIM]
        max_v = max((b.get("total",0) for b in tl), default=1) or 1
        step  = inner.w / max(len(tl)-1, 1) if len(tl) > 1 else inner.w
        for key, col in zip(keys, cols):
            pts = []
            for i, b in enumerate(tl):
                px = inner.x + int(i*step) if len(tl) > 1 else inner.x
                py = inner.bottom - int((b.get(key,0)/max_v)*(inner.h-6)) - 2
                pts.append((px, py))
            if len(pts) >= 2:
                # Use dim solid color fill — no SRCALPHA surface allocation
                fill_col = tuple(max(0, c // 8) for c in col)
                fp = [(pts[0][0], inner.bottom)] + pts + [(pts[-1][0], inner.bottom)]
                if len(fp) >= 3:
                    pygame.draw.polygon(surf, fill_col, fp)
                pygame.draw.lines(surf, col, False, pts, 1)
            elif len(pts) == 1:
                bh = int((tl[0].get(key,0)/max_v)*(inner.h-6))
                if bh > 0:
                    pygame.draw.rect(surf, col, (inner.x, inner.bottom-bh, 3, bh))
        step_lbl = max(1, len(tl)//7)
        for i, b in enumerate(tl):
            if i % step_lbl == 0 or i == len(tl)-1:
                px  = inner.x + int(i*step) if len(tl) > 1 else inner.x
                lbl = fonts["xs"].render(b.get("t",""), True, TXT_DIM)
                surf.blit(lbl, (max(inner.x, min(px-lbl.get_width()//2, inner.right-lbl.get_width())), inner.bottom+2))
        if tl:
            lx2 = inner.x + int((len(tl)-1)*step) if len(tl) > 1 else inner.x
            ly2 = inner.bottom - int((tl[-1].get("total",0)/max_v)*(inner.h-6)) - 2
            # Pulse by brightness modulation — no per-frame surface
            t_now = time.time()
            factor = 0.5 + 0.5 * math.sin(t_now * 4)
            dot_col = tuple(int(c * (0.4 + 0.6 * factor)) for c in CYAN)
            pygame.draw.circle(surf, dot_col, (lx2, ly2), 5)
            pygame.draw.circle(surf, WHITE, (lx2, ly2), 2)
    # legend in header
    title_w = fonts["sm"].size("EVENTS OVER TIME")[0] + 20
    lx = r.x + title_w
    for key, col in zip(["total","alert","block","log","ign"], [CYAN,YELLOW,RED,GREEN,TXT_DIM]):
        pygame.draw.rect(surf, col, (lx, r.y+7, 6, 6), border_radius=1)
        lbl = fonts["xs"].render(key, True, TXT_DIM)
        surf.blit(lbl, (lx+8, r.y+6))
        lx += lbl.get_width() + 16
        if lx > r.right - 10:
            break

def _draw_alerts(surf, r, s, fonts):
    _panel(surf, r, "ALERTS", fonts, YELLOW)
    terms = s["alert_terms"]
    lh = fonts["sm"].get_height() + 3
    y  = r.y + 24
    surf.blit(fonts["xs"].render("Term",  True, TXT_HEAD), (r.x+6,      y))
    surf.blit(fonts["xs"].render("Count", True, TXT_HEAD), (r.right-42, y))
    y += lh
    pygame.draw.line(surf, BORDER, (r.x+3, y-2), (r.right-3, y-2), 1)
    if not terms:
        surf.blit(fonts["sm"].render("no alerts yet", True, TXT_DIM), (r.x+6, y+4))
        return
    max_c = max((t["count"] for t in terms), default=1) or 1
    for t in terms:
        if y + lh > r.bottom - 3:
            break
        bw = int((t["count"]/max_c)*(r.w-12))
        pygame.draw.rect(surf, (60, 50, 10), (r.x+3, y, bw, lh-2), border_radius=1)
        surf.blit(fonts["sm"].render(_trunc(fonts["sm"], t["term"], r.w-55), True, TXT),    (r.x+6,      y+1))
        surf.blit(fonts["sm"].render(str(t["count"]),                        True, YELLOW), (r.right-42, y+1))
        y += lh

def _draw_terms(surf, r, s, fonts):
    _panel(surf, r, "TOP CLASSES", fonts, LIME)
    classes = sorted(s["cls"].items(), key=lambda x: -x[1])[:9]
    lh = fonts["sm"].get_height() + 3
    y  = r.y + 24
    surf.blit(fonts["xs"].render("Class", True, TXT_HEAD), (r.x+6,      y))
    surf.blit(fonts["xs"].render("Cnt",   True, TXT_HEAD), (r.right-28, y))
    y += lh
    pygame.draw.line(surf, BORDER, (r.x+3, y-2), (r.right-3, y-2), 1)
    if not classes:
        surf.blit(fonts["sm"].render("no data yet", True, TXT_DIM), (r.x+6, y+4))
        return
    max_c = max((c for _, c in classes), default=1) or 1
    for i, (cls, cnt) in enumerate(classes):
        if y + lh > r.bottom - 3:
            break
        col = CLS_COLORS[i % len(CLS_COLORS)]
        bw  = int((cnt/max_c)*(r.w-12))
        # dim version of col for bar background (no SRCALPHA surface needed)
        bar_col = (col[0]//5, col[1]//5, col[2]//5)
        pygame.draw.rect(surf, bar_col, (r.x+3, y, bw, lh-1), border_radius=1)
        pygame.draw.rect(surf, col, (r.x+3, y, 3, lh-1), border_radius=1)
        surf.blit(fonts["sm"].render(_trunc(fonts["sm"], cls, r.w-38), True, col), (r.x+9,      y+1))
        surf.blit(fonts["sm"].render(str(cnt),                         True, TXT_DIM), (r.right-28, y+1))
        y += lh

def _draw_donut_panel(surf, r, title, slices, colors, labels, fonts, total_label=""):
    _panel(surf, r, title, fonts)
    ro = min(r.w, r.h-22)//2 - 6
    ri = int(ro * 0.54)
    cx = r.x + r.w//2
    cy = r.y + 22 + ro + 6
    _donut(surf, cx, cy, ro, ri, slices, colors, fonts, total_label)
    total = sum(slices) or 1
    ly = cy + ro + 6
    for i, (lbl, val) in enumerate(zip(labels, slices)):
        if val <= 0 or ly + fonts["xs"].get_height() > r.bottom - 1:
            continue
        col = colors[i % len(colors)]
        pygame.draw.rect(surf, col, (r.x+4, ly+2, 5, 5), border_radius=1)
        surf.blit(fonts["xs"].render(_trunc(fonts["xs"], f"{lbl} {val/total:.0%}", r.w-14), True, TXT_DIM), (r.x+12, ly))
        ly += fonts["xs"].get_height() + 2

def _draw_conf(surf, r, s, fonts):
    _panel(surf, r, "CONFIDENCE", fonts, TEAL)
    inner = pygame.Rect(r.x+6, r.y+24, r.w-12, r.h-32)
    data  = list(s["conf_trend"])
    if not data:
        surf.blit(fonts["sm"].render("waiting…", True, TXT_DIM), (r.x+6, r.y+28))
        return
    if len(data) >= 2:
        _sparkline(surf, inner, data, TEAL, fill_alpha=22)
    vs = fonts["md"].render(f"{data[-1]:.1%}", True, TEAL)
    surf.blit(vs, (r.x + r.w//2 - vs.get_width()//2, r.y+26))
    if len(data) > 1:
        mn, mx = min(data), max(data)
        avg = sum(data)/len(data)
        ay  = inner.bottom - int(((avg-mn)/max(mx-mn,1e-6))*(inner.h-4)) - 2
        pygame.draw.line(surf, (*YELLOW, 160), (inner.x, ay), (inner.right, ay), 1)
        surf.blit(fonts["xs"].render(f"avg {avg:.1%}", True, YELLOW), (inner.x+2, ay-10))

def _draw_sources(surf, r, s, fonts):
    _panel(surf, r, "TOP SOURCES", fonts, ORANGE)
    sources = s["top_sources"]
    lh = fonts["sm"].get_height() + 3
    y  = r.y + 24
    surf.blit(fonts["xs"].render("Source IP", True, TXT_HEAD), (r.x+6,      y))
    surf.blit(fonts["xs"].render("Cnt",       True, TXT_HEAD), (r.right-28, y))
    y += lh
    pygame.draw.line(surf, BORDER, (r.x+3, y-2), (r.right-3, y-2), 1)
    if not sources:
        surf.blit(fonts["sm"].render("no sources yet", True, TXT_DIM), (r.x+6, y+4))
        return
    max_c = max((e["count"] for e in sources), default=1) or 1
    for e in sources:
        if y + lh > r.bottom - 3:
            break
        col = DECISION_COL.get(e.get("decision","Ignore"), TXT_DIM)
        bw  = int((e["count"]/max_c)*(r.w-12))
        bar_col = (col[0]//6, col[1]//6, col[2]//6)
        pygame.draw.rect(surf, bar_col, (r.x+3, y, bw, lh-1), border_radius=1)
        surf.blit(fonts["sm"].render(_trunc(fonts["sm"], e["src"], r.w-38), True, col),     (r.x+6,      y+1))
        surf.blit(fonts["sm"].render(str(e["count"]),                       True, TXT_DIM), (r.right-28, y+1))
        y += lh

def _draw_log(surf, r, s, fonts):
    _panel(surf, r, "LIVE EVENT STREAM", fonts, TXT_HEAD)
    logs = list(s["flow_log"])
    lh   = fonts["sm"].get_height() + 2
    y    = r.y + 24
    mw   = r.w - 14
    if not logs:
        surf.blit(fonts["sm"].render("waiting for events…", True, TXT_DIM), (r.x+6, y))
        return
    for entry in logs:
        if y + lh > r.bottom - 2:
            break
        col = entry.get("color", TXT_DIM)
        ts  = fonts["sm"].render(entry["tag"], True, col)
        surf.blit(ts, (r.x+6, y))
        surf.blit(fonts["sm"].render(_trunc(fonts["sm"], entry["msg"], mw-ts.get_width()-6), True, TXT_DIM),
                  (r.x+6+ts.get_width()+4, y))
        y += lh

def _draw_attacker(surf, r, s, fonts):
    a       = s["atk"]
    enabled = a.get("enabled", False)
    col     = ORANGE if enabled else TXT_DIM
    _panel(surf, r, "ATTACK ENGINE", fonts, col)
    x, y = r.x+6, r.y+24
    mw   = r.w - 12
    lh   = fonts["sm"].get_height() + 4
    if not enabled:
        surf.blit(fonts["sm"].render("run with --attack to enable", True, TXT_DIM), (x, y))
        return
    cw3 = mw // 3
    for i, (lbl, val, vc) in enumerate([("Sent", a["sent"], TXT), ("Blocked", a["blocked"], RED), ("Evaded", a["evaded"], GREEN)]):
        cx = x + i*cw3
        surf.blit(fonts["xs"].render(lbl,      True, TXT_DIM), (cx, y))
        surf.blit(fonts["md"].render(str(val), True, vc),      (cx, y+lh-2))
    y += lh*2 + 4
    pygame.draw.line(surf, BORDER, (r.x+3, y-2), (r.right-3, y-2), 1)
    for k, v in [("Gen", str(a["gen"])), ("Decision", a["decision"]),
                 ("Profile", a["profile"]), ("Target", a["target"]), ("Best", a["top"])]:
        if y + lh > r.bottom - 20:
            break
        ks = fonts["xs"].render(f"{k:<9}", True, TXT_DIM)
        surf.blit(ks, (x, y))
        surf.blit(fonts["sm"].render(_trunc(fonts["sm"], str(v), mw-ks.get_width()-4), True, ORANGE),
                  (x+ks.get_width()+2, y))
        y += lh
    if y + 14 < r.bottom - 3 and a["sent"] > 0:
        rate = a["evaded"] / max(a["sent"], 1)
        surf.blit(fonts["xs"].render("Evasion", True, TXT_DIM), (x, y+1))
        _hbar(surf, x+54, y+2, mw-54, 8, rate, GREEN)
        surf.blit(fonts["xs"].render(f"{rate:.0%}", True, GREEN), (r.right-28, y+1))

# ── Main ──────────────────────────────────────────────────────
def main(bus=None, cnn=None, rnn=None, decoder=None, db=None,
         bridge=None, attacker=None):
    # Wait briefly for state initialization
    time.sleep(0.5)

    # Reset to clean state
    with lock:
        state.clear()
        state.update(_fresh_state())

    # Subscribe to pipeline events
    if bus is not None:
        bus.subscribe("cnn_features",   on_cnn_features)
        bus.subscribe("decoder_output", on_decoder_output)
        bus.subscribe("db_logged",      on_db_logged)
        bus.subscribe("db_retrieved",   on_db_retrieved)

    # Launch PyGame natively
    pygame.init()
    screen    = pygame.display.set_mode((1440, 860), pygame.RESIZABLE)
    pygame.display.set_caption("AI-IDS  |  SOC Dashboard")
    clock     = pygame.time.Clock()
    fonts     = _make_fonts(screen.get_height())
    last_size = screen.get_size()
    scanline  = _make_scanline(*screen.get_size())
    panels    = _layout(*screen.get_size())
    
    # We must explicitly pump PyGame events in the main thread to avoid OS "Not Responding" freeze
    running = [True]

    def _poll():
        while running[0]:
            if bridge:
                st = bridge.stats
                with lock:
                    state["ids_connected"] = bridge.connected
                    state["ids_interface"] = st.get("interface", "—")
                    # ids_pkts = raw capture count from bridge (separate from pipeline pkts)
                    state["ids_pkts"]      = st.get("packets_received", 0)
            if bus:
                with lock:
                    state["q_depth"] = bus.queue_depth
            if attacker:
                st = attacker.stats
                with lock:
                    a = state["atk"]
                    a["enabled"]  = True
                    a["sent"]     = st.get("total_sent",    0)
                    a["blocked"]  = st.get("total_blocked", 0)
                    a["evaded"]   = st.get("total_evaded",  0)
                    a["gen"]      = st.get("generation",    0)
                    a["top"]      = st.get("top_profile",   "—")
                    a["decision"] = st.get("last_decision", "—")
                    a["target"]   = st.get("last_target",   "—")
                    a["profile"]  = st.get("last_profile",  "—")
                    state["_gen"] = state.get("_gen", 0) + 1
            time.sleep(0.1)   # was 0.5 — poll 10x/s so stats feel live
            
    threading.Thread(target=_poll, daemon=True).start()

    s         = _fresh_state()   # last rendered snapshot
    last_gen = -1
    last_draw_time = time.time()

    # Helper to check if the background attack thread is still running
    def is_attacker_alive():
        if attacker is None: return False
        return getattr(attacker, '_running', False)

    while running[0]:
        clock.tick(60) # Bump to 60 for smoother OS events
        
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running[0] = False
                break
            elif event.type == pygame.KEYDOWN:
                if event.key in (pygame.K_q, pygame.K_ESCAPE):
                    running[0] = False
                    break
        
        if not running[0]:
            break

        # Also exit if the main attacker session has naturally concluded
        if attacker is not None and getattr(attacker, '_duration_s', None):
            # If attacker was given a hard duration, check if it's exceeded
            elapsed = time.time() - attacker._start_time
            if elapsed > attacker._duration_s:
                # Give UI 1 second to draw final state
                time.sleep(1)
                running[0] = False
                break
        elif attacker is not None and not getattr(attacker, '_running', False):
            # If manually stopped
            time.sleep(1)
            running[0] = False
            break

        W, H = screen.get_size()
        if (W, H) != last_size:
            last_size = (W, H)
            panels    = _layout(W, H)
            fonts     = _make_fonts(H)
            scanline  = _make_scanline(W, H)

        # Only redraw if the data generation has advanced, or every 0.25s (to keep pulse anims active)
        now = time.time()
        
        # Don't use a timeout block on the main UI thread. It causes starvation.
        # Just safely attempt a lock. If false, try next frame.
        got_lock = lock.acquire(blocking=False)
        if not got_lock:
            continue
            
        try:
            gen = state.get("_gen", 0)
            
            if gen != last_gen or now - last_draw_time > 0.25:
                last_gen = gen
                last_draw_time = now
                s = {
                    "frame_id":      state.get("frame_id", 0),
                    "pkts":          state.get("pkts", 0),
                    "ids_pkts":      state.get("ids_pkts", 0),
                    "alerts":        state.get("alerts", 0),
                    "blocks":        state.get("blocks", 0),
                    "esc":           state.get("esc", 0),
                    "db_size":       state.get("db_size", 0),
                    "decoder_db_hits": state.get("decoder_db_hits", 0),
                    "db_sigs_exported": state.get("db_sigs_exported", 0),
                    "db_top_label":  state.get("db_top_label", "—"),
                    "ids_alerts_sent": state.get("ids_alerts_sent", 0),
                    "q_depth":       state.get("q_depth", 0),
                    "dec_counts":    list(state.get("dec_counts", [])),
                    "cls":           dict(state.get("cls", {})),
                    "proto":         dict(state.get("proto", {})),
                    "conf_trend":    list(state.get("conf_trend", [])),
                    "alert_terms":   list(state.get("alert_terms", [])),
                    "top_sources":   list(state.get("top_sources", [])),
                    "flow_log":      list(state.get("flow_log", [])),
                    "timeline":      list(state.get("timeline", [])),
                    "tl_live":       dict(state.get("tl_live", {})),
                    "atk":           dict(state.get("atk", {})),
                    "ids_connected": state.get("ids_connected", False),
                    "ids_interface": state.get("ids_interface", "—"),
                }
                redraw = True
            else:
                redraw = False
        except Exception as e:
            print(f"[dashboard] State dict sync error: {e}")
            redraw = False
        finally:
            lock.release()

        if redraw:
            screen.fill(BG)
            _draw_topbar(screen, s, fonts, W)
            _draw_timeline(screen, panels["timeline"], s, fonts)
            _draw_alerts(screen,   panels["alerts"],   s, fonts)
            _draw_terms(screen,    panels["terms"],     s, fonts)
    
            dec_vals  = s["dec_counts"]
            _draw_donut_panel(screen, panels["donut_dec"], "DECISIONS",
                              dec_vals, DEC_COLORS, DEC_SLICES, fonts,
                              str(sum(dec_vals)))
    
            cls_items = sorted(s["cls"].items(), key=lambda x: -x[1])[:6]
            _draw_donut_panel(screen, panels["donut_cls"], "ATTACK CLASSES",
                              [v for _,v in cls_items] or [1], CLS_COLORS,
                              [k for k,_ in cls_items] or ["none"], fonts,
                              str(len(cls_items)) + " cls")
    
            pro_items = sorted(s["proto"].items(), key=lambda x: -x[1])[:6]
            _draw_donut_panel(screen, panels["donut_pro"], "PROTOCOLS",
                              [v for _,v in pro_items] or [1], PRO_COLORS,
                              [k for k,_ in pro_items] or ["—"], fonts,
                              str(len(pro_items)) + " pro")
    
            _draw_conf(screen,     panels["conf"],     s, fonts)
            _draw_sources(screen,  panels["sources"],  s, fonts)
            _draw_log(screen,      panels["log"],      s, fonts)
            
            def _draw_db_stats(surf, r, state_dict, fonts):
                _panel(surf, r, "REFINED DB → IDS", fonts, PURPLE)
                x, y = r.x + 10, r.y + 30
                dy = 18
                
                # Connection status
                ids_live = state_dict.get("ids_connected", False)
                status_color = GREEN if ids_live else TXT_DIM
                status_text = "● LIVE NETWORK" if ids_live else "● SYNTHETIC"
                surf.blit(fonts["sm"].render(status_text, True, status_color), (x, y))
                y += dy + 5
                
                items = [
                    ("DB Size",   str(state_dict.get("db_size", 0))),
                    ("DB Hits",   str(state_dict.get("decoder_db_hits", 0))),
                    ("Sigs→IDS",  str(state_dict.get("db_sigs_exported", 0))),
                    ("Top Class", state_dict.get("db_top_label", "—")[:18]),
                    ("Pkts",      str(state_dict.get("ids_pkts", 0))),
                    ("Alerts→IDS",str(state_dict.get("ids_alerts_sent", 0)))
                ]
                for label, val in items:
                    surf.blit(fonts["sm"].render(f"{label:<12}", True, TXT_DIM), (x, y))
                    surf.blit(fonts["sm"].render(val, True, PURPLE), (x + 110, y))
                    y += dy
    
            _draw_db_stats(screen, panels["attacker"], s, fonts)
    
            screen.blit(scanline, (0, 0))
            pygame.display.flip()

    pygame.quit()
