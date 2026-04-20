"""
Network Setup Screen — pygame UI for picking interface + BPF filter
before the main dashboard launches.
Returns: { interface, filter, mode } or None if user quit.
"""
import pygame
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from network.net_config import (
    discover_interfaces, FILTER_PRESETS, save_config, load_config
)

W, H   = 900, 620
BG     = (10, 12, 20)
C_PANEL= (18, 22, 38)
C_BORDER=(40, 48, 72)
C_WHITE= (230, 230, 230)
C_DIM  = (80, 85, 100)
C_CYAN = (0, 200, 255)
C_GREEN= (0, 255, 140)
C_RED  = (255, 80, 80)
C_YELLOW=(255, 200, 0)
C_SEL  = (30, 40, 70)
C_HOVER= (25, 32, 58)


def _rect_btn(surf, rect, text, font, color, hover=False, selected=False):
    bg = C_SEL if selected else (C_HOVER if hover else C_PANEL)
    pygame.draw.rect(surf, bg, rect, border_radius=6)
    pygame.draw.rect(surf, color if selected else C_BORDER, rect, width=1, border_radius=6)
    t = font.render(text, True, color if selected else C_WHITE)
    surf.blit(t, (rect.x + rect.w // 2 - t.get_width() // 2,
                  rect.y + rect.h // 2 - t.get_height() // 2))


def run_setup(skip_if_saved: bool = False) -> dict | None:
    """
    Show the setup screen and return chosen config.
    If skip_if_saved=True and a saved config exists, return it immediately.
    Falls back to a tkinter setup dialog if pygame is not installed.
    """
    saved = load_config()
    if skip_if_saved and saved:
        return saved

    try:
        import pygame
    except ImportError:
        return _run_setup_tk(saved)

    return _run_setup_pygame(saved)


def _run_setup_tk(saved: dict | None) -> dict | None:
    """Tkinter setup dialog — works on Python 3.14 without pygame."""
    import tkinter as tk
    from tkinter import ttk

    interfaces  = discover_interfaces()
    filter_names = list(FILTER_PRESETS.keys())
    result = [None]

    root = tk.Tk()
    root.title("AI-IDS — Network Setup")
    root.configure(bg="#0a0c14")
    root.geometry("700x500")
    root.resizable(False, False)

    BG, FG, SEL = "#0a0c14", "#e6e6e6", "#00c8ff"

    tk.Label(root, text="◈  AI-IDS  Network Setup",
             fg=SEL, bg=BG, font=("Consolas", 16, "bold")).pack(pady=12)

    frame = tk.Frame(root, bg=BG)
    frame.pack(fill="both", expand=True, padx=16)
    frame.columnconfigure(0, weight=1)
    frame.columnconfigure(1, weight=1)

    # Interface list
    tk.Label(frame, text="NETWORK INTERFACE", fg=SEL, bg=BG,
             font=("Consolas", 11, "bold")).grid(row=0, column=0, sticky="w", pady=4)
    iface_var = tk.StringVar()
    iface_lb  = tk.Listbox(frame, listvariable=iface_var, height=10,
                            bg="#121626", fg=FG, selectbackground=SEL,
                            font=("Consolas", 10), relief="flat")
    iface_lb.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
    for ifc in interfaces:
        status = "▲" if ifc.get("is_up") else "▼"
        iface_lb.insert("end", f"{status} {ifc['name'][:20]:<20} {ifc.get('ip','')}")
    if saved:
        for i, ifc in enumerate(interfaces):
            if ifc["name"] == saved.get("interface"):
                iface_lb.selection_set(i)
                break
    else:
        iface_lb.selection_set(0)

    # Filter list
    tk.Label(frame, text="BPF CAPTURE FILTER", fg="#ffc800", bg=BG,
             font=("Consolas", 11, "bold")).grid(row=0, column=1, sticky="w", pady=4)
    filter_lb = tk.Listbox(frame, height=10, bg="#121626", fg=FG,
                            selectbackground="#ffc800", font=("Consolas", 10), relief="flat")
    filter_lb.grid(row=1, column=1, sticky="nsew")
    for name in filter_names:
        filter_lb.insert("end", name)
    filter_lb.selection_set(0)

    # Custom filter
    tk.Label(frame, text="Custom BPF:", fg="#505564", bg=BG,
             font=("Consolas", 10)).grid(row=2, column=1, sticky="w", pady=(6, 0))
    custom_var = tk.StringVar()
    tk.Entry(frame, textvariable=custom_var, bg="#121626", fg=FG,
             font=("Consolas", 10), relief="flat",
             insertbackground=FG).grid(row=3, column=1, sticky="ew")

    # Mode
    mode_var = tk.StringVar(value=saved.get("mode", "synthetic") if saved else "synthetic")
    btn_frame = tk.Frame(root, bg=BG)
    btn_frame.pack(pady=8)
    tk.Radiobutton(btn_frame, text="🟢 LIVE CAPTURE", variable=mode_var,
                   value="direct", fg="#00ff8c", bg=BG, selectcolor=BG,
                   font=("Consolas", 11, "bold"), activebackground=BG).pack(side="left", padx=8)
    tk.Radiobutton(btn_frame, text="🔴 SYNTHETIC", variable=mode_var,
                   value="synthetic", fg="#ff5050", bg=BG, selectcolor=BG,
                   font=("Consolas", 11, "bold"), activebackground=BG).pack(side="left", padx=8)

    def launch():
        sel = iface_lb.curselection()
        ifc = interfaces[sel[0]] if sel and interfaces else {"name": "", "scapy_name": ""}
        fsel = filter_lb.curselection()
        bpf  = custom_var.get().strip() or (
            FILTER_PRESETS[filter_names[fsel[0]]] if fsel else "")
        result[0] = save_config(
            ifc.get("name", ""),
            ifc.get("scapy_name", ifc.get("name", "")),
            bpf,
            mode_var.get()
        )
        root.destroy()

    tk.Button(root, text="▶  LAUNCH", command=launch,
              bg=SEL, fg="#0a0c14", font=("Consolas", 13, "bold"),
              relief="flat", padx=20, pady=6).pack(pady=8)

    root.mainloop()
    return result[0]


def _run_setup_pygame(saved: dict | None) -> dict | None:
    """Original pygame setup loop."""
    import pygame

    pygame.init()
    screen = pygame.display.set_mode((W, H))
    pygame.display.set_caption("AI-IDS — Network Setup")
    clk = pygame.time.Clock()

    font_xl = pygame.font.SysFont("Consolas", 26, bold=True)
    font_md = pygame.font.SysFont("Consolas", 14)
    font_sm = pygame.font.SysFont("Consolas", 12)

    interfaces   = discover_interfaces()
    filter_names = list(FILTER_PRESETS.keys())

    sel_iface    = 0
    sel_filter   = 0
    custom_filter= saved.get("filter", "") if saved else ""
    custom_active= False
    mode         = saved.get("mode", "synthetic") if saved else "synthetic"

    # Pre-select saved interface
    if saved:
        for i, ifc in enumerate(interfaces):
            if ifc["name"] == saved.get("interface"):
                sel_iface = i
                break

    while True:
        clk.tick(60)
        mx, my = pygame.mouse.get_pos()

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                return None
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    pygame.quit()
                    return None
                if custom_active:
                    if event.key == pygame.K_BACKSPACE:
                        custom_filter = custom_filter[:-1]
                    elif event.key == pygame.K_RETURN:
                        custom_active = False
                    elif event.key == pygame.K_ESCAPE:
                        custom_active = False
                    else:
                        custom_filter += event.unicode
            if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                # Interface list
                for i, ifc in enumerate(interfaces[:10]):
                    r = pygame.Rect(30, 120 + i * 36, 380, 32)
                    if r.collidepoint(mx, my):
                        sel_iface = i
                # Filter list
                for i, fname in enumerate(filter_names):
                    r = pygame.Rect(440, 120 + i * 32, 420, 28)
                    if r.collidepoint(mx, my):
                        sel_filter = i
                        custom_active = False
                # Custom filter box
                custom_rect = pygame.Rect(440, 120 + len(filter_names) * 32 + 10, 420, 30)
                if custom_rect.collidepoint(mx, my):
                    custom_active = True
                    sel_filter = -1
                # Mode buttons
                live_btn = pygame.Rect(30, H - 90, 160, 36)
                syn_btn  = pygame.Rect(200, H - 90, 160, 36)
                if live_btn.collidepoint(mx, my):
                    mode = "live"
                if syn_btn.collidepoint(mx, my):
                    mode = "synthetic"
                # Launch button
                launch_btn = pygame.Rect(W - 200, H - 90, 170, 36)
                if launch_btn.collidepoint(mx, my):
                    iface      = interfaces[sel_iface]["name"]       if interfaces else "eth0"
                    scapy_name = interfaces[sel_iface].get("scapy_name", iface) if interfaces else iface
                    bpf        = custom_filter if sel_filter == -1 else FILTER_PRESETS[filter_names[sel_filter]]
                    result     = save_config(iface, scapy_name, bpf, mode)
                    pygame.quit()
                    return result

        # Draw
        screen.fill(BG)

        # Grid dots
        for gx in range(0, W, 40):
            for gy in range(0, H, 40):
                pygame.draw.circle(screen, (22, 26, 42), (gx, gy), 1)

        # Title
        t = font_xl.render("◈  AI-IDS  Network Setup", True, C_CYAN)
        screen.blit(t, (W // 2 - t.get_width() // 2, 18))
        pygame.draw.line(screen, C_BORDER, (20, 56), (W - 20, 56), 1)

        # Interface panel
        pygame.draw.rect(screen, C_PANEL, (20, 65, 400, 430), border_radius=10)
        pygame.draw.rect(screen, C_BORDER, (20, 65, 400, 430), width=1, border_radius=10)
        screen.blit(font_md.render("NETWORK INTERFACE", True, C_CYAN), (34, 74))
        pygame.draw.line(screen, C_BORDER, (30, 94), (410, 94), 1)

        for i, ifc in enumerate(interfaces[:10]):
            r = pygame.Rect(30, 100 + i * 36, 380, 32)
            hover = r.collidepoint(mx, my)
            selected = (i == sel_iface)
            bg = C_SEL if selected else (C_HOVER if hover else (18, 22, 38))
            pygame.draw.rect(screen, bg, r, border_radius=5)
            if selected:
                pygame.draw.rect(screen, C_CYAN, r, width=1, border_radius=5)

            # Status dot
            dot_col = C_GREEN if ifc.get("is_up") else C_RED
            pygame.draw.circle(screen, dot_col, (r.x + 12, r.y + 16), 5)

            # Name + IP
            name_col = C_CYAN if selected else C_WHITE
            screen.blit(font_md.render(ifc["name"][:18], True, name_col), (r.x + 24, r.y + 4))
            ip_str = ifc.get("ip", "") or "no IP"
            spd    = f"  {ifc.get('speed_mbps',0)}Mbps" if ifc.get("speed_mbps") else ""
            screen.blit(font_sm.render(f"{ip_str}{spd}", True, C_DIM), (r.x + 24, r.y + 18))

            # Loopback tag
            if ifc.get("is_loopback"):
                tag = font_sm.render("loopback", True, C_DIM)
                screen.blit(tag, (r.right - tag.get_width() - 8, r.y + 10))

        if not interfaces:
            screen.blit(font_md.render("No interfaces found", True, C_RED), (40, 130))
            screen.blit(font_sm.render("Install psutil:  pip install psutil", True, C_DIM), (40, 155))

        # Filter panel
        pygame.draw.rect(screen, C_PANEL, (430, 65, 450, 430), border_radius=10)
        pygame.draw.rect(screen, C_BORDER, (430, 65, 450, 430), width=1, border_radius=10)
        screen.blit(font_md.render("BPF CAPTURE FILTER", True, C_YELLOW), (444, 74))
        pygame.draw.line(screen, C_BORDER, (440, 94), (870, 94), 1)

        for i, fname in enumerate(filter_names):
            r = pygame.Rect(440, 100 + i * 30, 420, 26)
            hover    = r.collidepoint(mx, my)
            selected = (i == sel_filter)
            bg = C_SEL if selected else (C_HOVER if hover else (18, 22, 38))
            pygame.draw.rect(screen, bg, r, border_radius=4)
            if selected:
                pygame.draw.rect(screen, C_YELLOW, r, width=1, border_radius=4)
            name_col = C_YELLOW if selected else C_WHITE
            screen.blit(font_sm.render(fname, True, name_col), (r.x + 8, r.y + 5))
            bpf_val = FILTER_PRESETS[fname]
            if bpf_val:
                bpf_surf = font_sm.render(bpf_val[:38], True, C_DIM)
                screen.blit(bpf_surf, (r.right - bpf_surf.get_width() - 6, r.y + 5))

        # Custom filter input
        cy = 100 + len(filter_names) * 30 + 8
        custom_rect = pygame.Rect(440, cy, 420, 28)
        border_col  = C_CYAN if custom_active else (C_YELLOW if sel_filter == -1 else C_BORDER)
        pygame.draw.rect(screen, C_PANEL, custom_rect, border_radius=4)
        pygame.draw.rect(screen, border_col, custom_rect, width=1, border_radius=4)
        placeholder = custom_filter if custom_filter else "custom BPF filter..."
        txt_col = C_WHITE if custom_filter else C_DIM
        screen.blit(font_sm.render(placeholder[:52], True, txt_col), (custom_rect.x + 8, custom_rect.y + 6))
        if custom_active:
            # Cursor blink
            import time
            if int(time.time() * 2) % 2:
                cx_pos = custom_rect.x + 8 + font_sm.size(placeholder[:52])[0]
                pygame.draw.line(screen, C_WHITE, (cx_pos, cy + 4), (cx_pos, cy + 22), 1)

        # Bottom bar
        pygame.draw.line(screen, C_BORDER, (20, H - 110), (W - 20, H - 110), 1)

        # Mode buttons
        live_btn = pygame.Rect(30, H - 90, 160, 36)
        syn_btn  = pygame.Rect(200, H - 90, 160, 36)
        _rect_btn(screen, live_btn, "🟢  LIVE CAPTURE", font_sm, C_GREEN,
                  hover=live_btn.collidepoint(mx, my), selected=(mode == "live"))
        _rect_btn(screen, syn_btn,  "🔴  SYNTHETIC",    font_sm, C_RED,
                  hover=syn_btn.collidepoint(mx, my),  selected=(mode == "synthetic"))

        # Selected summary
        if interfaces and sel_iface < len(interfaces):
            ifc = interfaces[sel_iface]
            bpf = custom_filter if sel_filter == -1 else FILTER_PRESETS.get(filter_names[sel_filter] if sel_filter >= 0 else "", "")
            summary = f"iface: {ifc['name']}  |  filter: \"{bpf or 'all'}\"  |  mode: {mode}"
            screen.blit(font_sm.render(summary[:90], True, C_DIM), (30, H - 46))

        # Launch button
        launch_btn = pygame.Rect(W - 200, H - 90, 170, 36)
        launch_hover = launch_btn.collidepoint(mx, my)
        pygame.draw.rect(screen, C_CYAN if launch_hover else C_PANEL, launch_btn, border_radius=8)
        pygame.draw.rect(screen, C_CYAN, launch_btn, width=2, border_radius=8)
        lt = font_md.render("▶  LAUNCH", True, BG if launch_hover else C_CYAN)
        screen.blit(lt, (launch_btn.x + launch_btn.w // 2 - lt.get_width() // 2,
                         launch_btn.y + launch_btn.h // 2 - lt.get_height() // 2))

        # Hint
        screen.blit(font_sm.render("ESC — quit   |   click interface + filter, then LAUNCH", True, C_DIM),
                    (W // 2 - 200, H - 18))

        pygame.display.flip()

    pygame.quit()
    return None
