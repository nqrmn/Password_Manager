import os
import sys
import json
import base64
import ctypes
import ctypes.util
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ======================================================================
#  VERSCHLÜSSELUNG / SPEICHERUNG  (unverändert)
# ======================================================================
from pathlib import Path


class CryptoVault:
    """Verwaltet die Verschlüsselung und das Speichern in der JSON-Datei."""

    def __init__(self):
        # Fester Speicherort unter: /Users/DeinName/Library/Application Support/PasswortManager/
        app_dir = Path.home() / "Library" / "Application Support" / "PasswortManager"
        app_dir.mkdir(parents=True, exist_ok=True)
        self.filepath = app_dir / "vault.json"

        self.salt = None
        self.key = None
        self.entries = []  # Liste aus Dictionaries: [{"site": "...", "password": "..."}]

    def exists(self) -> bool:
        return os.path.exists(self.filepath)

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Leitet aus dem Master-Passwort und dem Salt einen 32-Byte-Schlüssel ab."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

    def initialize_vault(self, master_password: str):
        """Erstellt einen neuen Tresor beim allerersten Start."""
        self.salt = os.urandom(16)
        self.key = self._derive_key(master_password, self.salt)
        self.entries = []
        self.save()

    def unlock(self, master_password: str) -> bool:
        """Versucht den Tresor zu entsperren. Gibt True zurück, wenn das Passwort stimmt."""
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.salt = base64.b64decode(data["salt"])
            ciphertext = data["vault"].encode("utf-8")
            self.key = self._derive_key(master_password, self.salt)

            # Entschlüsselung testen
            fernet = Fernet(self.key)
            decrypted_bytes = fernet.decrypt(ciphertext)
            self.entries = json.loads(decrypted_bytes.decode("utf-8"))
            return True

        except (InvalidToken, KeyError, json.JSONDecodeError):
            return False

    def save(self):
        """Verschlüsselt die aktuelle Liste und speichert sie als JSON."""
        fernet = Fernet(self.key)
        raw_json = json.dumps(self.entries).encode("utf-8")
        encrypted_data = fernet.encrypt(raw_json).decode("utf-8")

        vault_structure = {
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "vault": encrypted_data
        }

        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(vault_structure, f, indent=4)

    def add_entry(self, site: str, password: str):
        self.entries.append({"site": site, "password": password})
        self.save()

    def remove_entry(self, index: int):
        if 0 <= index < len(self.entries):
            self.entries.pop(index)
            self.save()


# ======================================================================
#  DESIGN
# ======================================================================
class Theme:
    BG = "#000000"
    CARD = "#1C1C1E"
    BORDER = "#3A3A3C"
    TEXT = "#FFFFFF"
    MUTED = "#FFFFFF"

    ACCENT = "#0A84FF"
    ACCENT_HOVER = "#409CFF"
    ACCENT_SOFT = "#17375E"
    ACCENT_SOFT_HOVER = "#1F4A7D"

    NEUTRAL_SOFT = "#2C2C2E"
    NEUTRAL_SOFT_HOVER = "#3A3A3C"

    DANGER = "#FF3B30"
    DANGER_SOFT = "#3A1A19"
    DANGER_SOFT_HOVER = "#512321"

    SUCCESS_TEXT = "#FFFFFF"
    SUCCESS_SOFT = "#1B3D28"
    SUCCESS_SOFT_HOVER = "#245234"

    ALPHA = 0.5  # Deckkraft des schwarzen Hintergrunds (0.5 = 50 % Transparenz)
    NATIVE_TRANSLUCENT = True  # macOS: nur Hintergrund transparent, Schrift bleibt deckend

    FONT = "Helvetica"
    MONO = "Courier"


def pick_fonts():
    """Wählt die passende System-Schrift (SF Pro / Segoe UI) und eine Mono-Schrift."""
    available = set(tkfont.families())
    for name in ("SF Pro Display", "SF Pro Text", "Segoe UI Variable Display",
                 "Segoe UI", "Helvetica Neue", "Helvetica"):
        if name in available:
            Theme.FONT = name
            break
    for name in ("SF Mono", "Cascadia Mono", "Consolas", "Menlo", "Courier New"):
        if name in available:
            Theme.MONO = name
            break


def F(size, weight="normal", mono=False):
    return (Theme.MONO if mono else Theme.FONT, size, weight)


def setup_styles(root):
    """Schlanke, dezente Scrollbar im Apple-Stil."""
    style = ttk.Style(root)
    style.theme_use("clam")
    name = "Modern.Vertical.TScrollbar"
    style.layout(name, [("Vertical.Scrollbar.trough", {
        "sticky": "ns",
        "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]
    })])
    style.configure(name, troughcolor=Theme.BG, background="#48484A", bordercolor=Theme.BG,
                    lightcolor="#48484A", darkcolor="#48484A", gripcount=0, relief="flat")
    style.map(name, background=[("active", "#8E8E93")],
              lightcolor=[("active", "#8E8E93")], darkcolor=[("active", "#8E8E93")])


def round_rect(canvas, x1, y1, x2, y2, r, **kw):
    """Zeichnet ein Rechteck mit abgerundeten Ecken auf ein Canvas."""
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


def _msg(lib, obj, sel, *args, argtypes=(), restype=ctypes.c_void_p):
    """Kleiner Wrapper um objc_msgSend (Objective-C-Aufruf per ctypes)."""
    fn = lib.objc_msgSend
    fn.restype = restype
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, *argtypes]
    return fn(obj, lib.sel_registerName(sel.encode()), *args)


def apply_native_translucency(alpha):
    """macOS: Setzt den Fensterhintergrund auf Schwarz mit `alpha` Deckkraft.
    Die Widgets sind 'systemTransparent', die Schrift bleibt dadurch voll deckend."""
    lib = ctypes.cdll.LoadLibrary(ctypes.util.find_library("objc") or "/usr/lib/libobjc.A.dylib")
    ctypes.cdll.LoadLibrary("/System/Library/Frameworks/AppKit.framework/AppKit")
    lib.objc_getClass.restype = ctypes.c_void_p
    lib.objc_getClass.argtypes = [ctypes.c_char_p]
    lib.sel_registerName.restype = ctypes.c_void_p
    lib.sel_registerName.argtypes = [ctypes.c_char_p]

    app = _msg(lib, lib.objc_getClass(b"NSApplication"), "sharedApplication")
    color = _msg(lib, lib.objc_getClass(b"NSColor"), "colorWithWhite:alpha:", 0.0, alpha,
                 argtypes=(ctypes.c_double, ctypes.c_double))
    windows = _msg(lib, app, "windows")
    count = _msg(lib, windows, "count", restype=ctypes.c_ulong)
    for i in range(count):
        win = _msg(lib, windows, "objectAtIndex:", i, argtypes=(ctypes.c_ulong,))
        if _msg(lib, win, "isVisible", restype=ctypes.c_bool):
            _msg(lib, win, "setOpaque:", False, argtypes=(ctypes.c_bool,), restype=None)
            _msg(lib, win, "setBackgroundColor:", color, argtypes=(ctypes.c_void_p,), restype=None)


def setup_translucent(root):
    """Aktiviert den transparenten Hintergrund. True = nativer Modus (Schrift deckend),
    False = Fallback auf Fenster-Alpha (dann ist auch die Schrift durchscheinend)."""
    if sys.platform == "darwin" and Theme.NATIVE_TRANSLUCENT:
        try:
            root.attributes("-transparent", True)
            tk.Frame(root, bg="systemTransparent").destroy()  # kennt Tk die Farbe?
            Theme.BG = "systemTransparent"
            root.update()
            apply_native_translucency(Theme.ALPHA)
            return True
        except Exception:
            Theme.BG = "#000000"
            try:
                root.attributes("-transparent", False)
            except tk.TclError:
                pass
    root.attributes("-alpha", Theme.ALPHA)
    return False


def center_window(win, parent=None, w=None, h=None):
    win.update_idletasks()
    w = w or win.winfo_reqwidth()
    h = h or win.winfo_reqheight()
    if parent is not None:
        x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    else:
        x = (win.winfo_screenwidth() - w) // 2
        y = (win.winfo_screenheight() - h) // 3
    win.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")


# ======================================================================
#  EIGENE WIDGETS (abgerundet, plattformunabhängig)
# ======================================================================
class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, bg, hover, fg="white", font=None,
                 radius=10, padx=18, pady=9, width=None, height=None, measure_with=None):
        self.font = font or F(11, "bold")
        measure = tkfont.Font(font=self.font)
        self.bw = width or measure.measure(measure_with or text) + 2 * padx
        self.bh = height or measure.metrics("linespace") + 2 * pady
        super().__init__(parent, width=self.bw, height=self.bh, bg=parent.cget("bg"),
                         highlightthickness=0, bd=0, cursor="hand2")
        self.text, self.color, self.hover_color, self.fg_color = text, bg, hover, fg
        self.radius, self.command, self.hovering = radius, command, False
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", self._release)
        self._draw()

    def _set_hover(self, state):
        self.hovering = state
        self._draw()

    def _release(self, event):
        if 0 <= event.x <= self.bw and 0 <= event.y <= self.bh and self.command:
            self.command()

    def restyle(self, text=None, color=None, hover=None, fg=None):
        self.text = text if text is not None else self.text
        self.color = color or self.color
        self.hover_color = hover or self.hover_color
        self.fg_color = fg or self.fg_color
        self._draw()

    def _draw(self):
        self.delete("all")
        fill = self.hover_color if self.hovering else self.color
        round_rect(self, 1, 1, self.bw - 1, self.bh - 1, self.radius, fill=fill, outline="")
        self.create_text(self.bw / 2, self.bh / 2, text=self.text, fill=self.fg_color, font=self.font)


class RoundedEntry(tk.Canvas):
    """Eingabefeld mit runden Ecken und blauem Fokus-Rahmen."""

    def __init__(self, parent, width=300, height=44, show="", radius=12):
        super().__init__(parent, width=width, height=height, bg=parent.cget("bg"),
                         highlightthickness=0, bd=0)
        self.radius, self.focused = radius, False
        self.entry = tk.Entry(
            self, show=show, font=F(12), bd=0, relief="flat", highlightthickness=0,
            bg=Theme.CARD, fg=Theme.TEXT, insertbackground=Theme.TEXT,
            selectbackground=Theme.ACCENT, selectforeground="white"
        )
        self.win = self.create_window(14, height // 2, window=self.entry, anchor="w")
        self.bind("<Configure>", self._on_resize)
        self.bind("<Button-1>", lambda e: self.entry.focus_set())
        self.entry.bind("<FocusIn>", lambda e: self._set_focus(True))
        self.entry.bind("<FocusOut>", lambda e: self._set_focus(False))

    def _on_resize(self, event):
        self.itemconfigure(self.win, width=max(event.width - 28, 10))
        self._draw()

    def _set_focus(self, state):
        self.focused = state
        self._draw()

    def _draw(self):
        self.delete("bg")
        w, h = self.winfo_width(), self.winfo_height()
        round_rect(self, 2, 2, w - 2, h - 2, self.radius, tags="bg", fill=Theme.CARD,
                   outline=Theme.ACCENT if self.focused else Theme.BORDER,
                   width=2 if self.focused else 1)
        self.tag_lower("bg")

    def get(self):
        return self.entry.get()

    def clear(self):
        self.entry.delete(0, tk.END)

    def focus_entry(self):
        self.entry.focus_set()

    def set_show(self, char):
        self.entry.configure(show=char)

    def bind_return(self, callback):
        self.entry.bind("<Return>", callback)


class RoundedFrame(tk.Frame):
    """Karte mit runden Ecken. Inhalt kommt in `.inner`.

    Die Höhe ergibt sich automatisch aus dem Inhalt; das abgerundete Rechteck
    wird als Hintergrund-Canvas dahinter gezeichnet.
    """

    def __init__(self, parent, bg=Theme.CARD, radius=16, border=Theme.BORDER, padding=14):
        super().__init__(parent, bg=parent.cget("bg"))
        self.fill, self.radius, self.border = bg, radius, border
        self.backdrop = tk.Canvas(self, bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self.backdrop.place(x=0, y=0, relwidth=1, relheight=1)
        self.inner = tk.Frame(self, bg=bg)
        self.inner.pack(fill="both", expand=True, padx=padding, pady=padding)
        self.backdrop.bind("<Configure>", self._draw)

    def _draw(self, event):
        self.backdrop.delete("all")
        round_rect(self.backdrop, 1, 1, event.width - 1, event.height - 1, self.radius,
                   fill=self.fill, outline=self.border)


class ScrollFrame(tk.Frame):
    """Scrollbarer Bereich (Mausrad + dezente Scrollbar, die sich bei Bedarf einblendet)."""

    def __init__(self, parent, bg=Theme.BG):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview,
                                 style="Modern.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self._on_scroll)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.win = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfigure(self.win, width=e.width))
        self.bind_all("<MouseWheel>", self._wheel, add="+")
        self.bind_all("<Button-4>", self._wheel, add="+")
        self.bind_all("<Button-5>", self._wheel, add="+")

    def _on_scroll(self, first, last):
        if float(first) <= 0.0 and float(last) >= 1.0:
            self.bar.pack_forget()
        else:
            self.bar.pack(side="right", fill="y", before=self.canvas)
        self.bar.set(first, last)

    def _wheel(self, event):
        try:
            under = self.winfo_containing(event.x_root, event.y_root)
        except (tk.TclError, KeyError):
            return
        if under is None or not str(under).startswith(str(self)):
            return
        if self.inner.winfo_reqheight() <= self.canvas.winfo_height():
            return
        if event.num == 4:
            step = -2
        elif event.num == 5:
            step = 2
        elif sys.platform == "darwin":
            step = -event.delta
        else:
            step = -int(event.delta / 120) * 2
        self.canvas.yview_scroll(step, "units")


# ======================================================================
#  APP
# ======================================================================
class PasswordManagerApp:
    MASK = "••••••••••"
    CLIPBOARD_CLEAR_MS = 30_000

    def __init__(self, root: tk.Tk):
        self.root = root
        pick_fonts()
        setup_styles(root)
        self.root.title("Passwort-Tresor")
        self.root.minsize(460, 520)
        center_window(self.root, w=540, h=680)
        self.translucent = setup_translucent(self.root)
        self.root.configure(bg=Theme.BG)

        self.vault = CryptoVault()
        self.show_auth_screen()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # --- 1. LOGIN / SETUP ---------------------------------------------
    def show_auth_screen(self):
        self.clear_window()
        is_new = not self.vault.exists()

        box = tk.Frame(self.root, bg=Theme.BG)
        box.pack(expand=True)

        # App-Icon (Schloss)
        icon = tk.Canvas(box, width=72, height=72, bg=Theme.BG, highlightthickness=0, bd=0)
        round_rect(icon, 1, 1, 71, 71, 18, fill=Theme.ACCENT, outline="")
        round_rect(icon, 22, 35, 50, 56, 5, fill="white", outline="")
        icon.create_arc(27, 17, 45, 43, start=0, extent=180, style="arc", outline="white", width=4)
        icon.create_line(27, 30, 27, 36, fill="white", width=4)
        icon.create_line(45, 30, 45, 36, fill="white", width=4)
        icon.create_oval(33, 42, 39, 48, fill=Theme.ACCENT, outline="")
        icon.pack(pady=(0, 22))

        tk.Label(box, text="Willkommen" if is_new else "Tresor entsperren",
                 font=F(22, "bold"), bg=Theme.BG, fg=Theme.TEXT).pack()
        tk.Label(box,
                 text=("Lege ein Master-Passwort fest.\nEs kann nicht wiederhergestellt werden."
                       if is_new else "Gib dein Master-Passwort ein."),
                 font=F(11), bg=Theme.BG, fg=Theme.MUTED, justify="center").pack(pady=(6, 24))

        self.pw_entry = RoundedEntry(box, width=340, show="•")
        self.pw_entry.pack(pady=(0, 8))
        self.pw_entry.bind_return(lambda e: self.handle_auth(is_new))

        self.auth_error = tk.Label(box, text="", font=F(10), bg=Theme.BG, fg=Theme.TEXT)
        self.auth_error.pack(pady=(0, 8))

        RoundedButton(box, "Tresor erstellen" if is_new else "Entsperren",
                      lambda: self.handle_auth(is_new), bg=Theme.ACCENT, hover=Theme.ACCENT_HOVER,
                      font=F(12, "bold"), radius=12, width=340, height=46).pack()

        self.root.after(100, self.pw_entry.focus_entry)

    def handle_auth(self, is_new: bool):
        password = self.pw_entry.get().strip()
        if not password:
            self.auth_error.config(text="Bitte ein Passwort eingeben.")
            return

        if is_new:
            self.vault.initialize_vault(password)
            self.show_main_screen()
        elif self.vault.unlock(password):
            self.show_main_screen()
        else:
            self.auth_error.config(text="Falsches Master-Passwort.")
            self.pw_entry.clear()

    # --- 2. HAUPTÜBERSICHT --------------------------------------------
    def show_main_screen(self):
        self.clear_window()

        header = tk.Frame(self.root, bg=Theme.BG, padx=24, pady=22)
        header.pack(fill="x")

        titles = tk.Frame(header, bg=Theme.BG)
        titles.pack(side="left")
        tk.Label(titles, text="Passwörter", font=F(24, "bold"),
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor="w")
        self.count_label = tk.Label(titles, text="", font=F(11), bg=Theme.BG, fg=Theme.MUTED)
        self.count_label.pack(anchor="w")

        RoundedButton(header, "+  Neu", self.open_add_dialog, bg=Theme.ACCENT,
                      hover=Theme.ACCENT_HOVER, radius=12, padx=20, pady=10).pack(side="right")

        list_wrap = tk.Frame(self.root, bg=Theme.BG, padx=24)
        list_wrap.pack(expand=True, fill="both", pady=(0, 14))
        self.scroll = ScrollFrame(list_wrap, bg=Theme.BG)
        self.scroll.pack(expand=True, fill="both")
        self.render_entries()

    def render_entries(self):
        for widget in self.scroll.inner.winfo_children():
            widget.destroy()

        n = len(self.vault.entries)
        self.count_label.config(text="1 Eintrag" if n == 1 else f"{n} Einträge")

        if n == 0:
            empty = tk.Frame(self.scroll.inner, bg=Theme.BG, pady=70)
            empty.pack(fill="x")
            tk.Label(empty, text="Noch keine Einträge", font=F(14, "bold"),
                     bg=Theme.BG, fg=Theme.TEXT).pack()
            tk.Label(empty, text="Tippe auf „+ Neu“, um dein erstes Passwort zu speichern.",
                     font=F(11), bg=Theme.BG, fg=Theme.MUTED).pack(pady=(6, 0))
            return

        for idx, item in enumerate(self.vault.entries):
            self._build_row(idx, item)

    def _build_row(self, idx, item):
        card = RoundedFrame(self.scroll.inner, bg=Theme.CARD, radius=16,
                            border=Theme.BORDER, padding=14)
        card.pack(fill="x", pady=(0, 10))
        inner = card.inner

        buttons = tk.Frame(inner, bg=Theme.CARD)
        buttons.pack(side="right", padx=(10, 0))
        info = tk.Frame(inner, bg=Theme.CARD)
        info.pack(side="left", fill="x", expand=True)

        tk.Label(info, text=item["site"], font=F(12, "bold"), bg=Theme.CARD,
                 fg=Theme.TEXT, anchor="w").pack(fill="x")
        pw_label = tk.Label(info, text=self.MASK, font=F(11, mono=True), bg=Theme.CARD,
                            fg=Theme.MUTED, anchor="w")
        pw_label.pack(fill="x", pady=(3, 0))

        state = {"visible": False}

        def toggle():
            state["visible"] = not state["visible"]
            pw_label.config(text=item["password"] if state["visible"] else self.MASK,
                            fg=Theme.TEXT if state["visible"] else Theme.MUTED)
            show_btn.restyle(text="Verbergen" if state["visible"] else "Anzeigen")

        small = F(10, "bold")
        copy_btn = RoundedButton(
            buttons, "Kopieren", lambda: self.copy_password(item["password"], copy_btn),
            bg=Theme.ACCENT_SOFT, hover=Theme.ACCENT_SOFT_HOVER, fg=Theme.TEXT,
            font=small, radius=9, padx=14, pady=7, measure_with="Kopiert ✓")
        show_btn = RoundedButton(
            buttons, "Anzeigen", toggle, bg=Theme.NEUTRAL_SOFT, hover=Theme.NEUTRAL_SOFT_HOVER,
            fg=Theme.TEXT, font=small, radius=9, padx=14, pady=7, measure_with="Verbergen")
        del_btn = RoundedButton(
            buttons, "✕", lambda i=idx: self.delete_entry(i), bg=Theme.DANGER_SOFT,
            hover=Theme.DANGER_SOFT_HOVER, fg=Theme.DANGER, font=small, radius=9,
            padx=11, pady=7)

        copy_btn.pack(side="left")
        show_btn.pack(side="left", padx=6)
        del_btn.pack(side="left")

    # --- AKTIONEN -----------------------------------------------------
    def copy_password(self, password: str, button: RoundedButton):
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()

        button.restyle(text="Kopiert ✓", color=Theme.SUCCESS_SOFT,
                       hover=Theme.SUCCESS_SOFT_HOVER, fg=Theme.SUCCESS_TEXT)

        def reset():
            if button.winfo_exists():
                button.restyle(text="Kopieren", color=Theme.ACCENT_SOFT,
                               hover=Theme.ACCENT_SOFT_HOVER, fg=Theme.TEXT)

        self.root.after(1500, reset)
        # Zwischenablage nach 30 Sekunden leeren, falls noch das Passwort drin steht
        self.root.after(self.CLIPBOARD_CLEAR_MS, lambda: self._clear_clipboard(password))

    def _clear_clipboard(self, password: str):
        try:
            if self.root.clipboard_get() == password:
                self.root.clipboard_clear()
        except tk.TclError:
            pass

    def delete_entry(self, index: int):
        site = self.vault.entries[index]["site"]
        if messagebox.askyesno("Eintrag löschen", f"„{site}“ wirklich löschen?"):
            self.vault.remove_entry(index)
            self.render_entries()

    # --- 3. DIALOG ZUM HINZUFÜGEN -------------------------------------
    def open_add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Neuer Eintrag")
        if self.translucent:
            dialog.attributes("-transparent", True)
        else:
            dialog.attributes("-alpha", Theme.ALPHA)
        dialog.configure(bg=Theme.BG)
        dialog.resizable(False, False)
        dialog.transient(self.root)

        body = tk.Frame(dialog, bg=Theme.BG, padx=28, pady=26)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Neuer Eintrag", font=F(18, "bold"),
                 bg=Theme.BG, fg=Theme.TEXT).pack(anchor="w", pady=(0, 18))

        tk.Label(body, text="Verwendungsort (Website, App, Bank)", font=F(10, "bold"),
                 bg=Theme.BG, fg=Theme.MUTED).pack(anchor="w", pady=(0, 6))
        site_entry = RoundedEntry(body, width=340)
        site_entry.pack(fill="x")

        pw_row = tk.Frame(body, bg=Theme.BG)
        pw_row.pack(fill="x", pady=(16, 6))
        tk.Label(pw_row, text="Passwort", font=F(10, "bold"),
                 bg=Theme.BG, fg=Theme.MUTED).pack(side="left")
        pw_entry = RoundedEntry(body, width=340, show="•")
        pw_entry.pack(fill="x")

        visible = {"on": False}

        def toggle_visibility():
            visible["on"] = not visible["on"]
            pw_entry.set_show("" if visible["on"] else "•")
            eye_btn.restyle(text="Verbergen" if visible["on"] else "Anzeigen")

        eye_btn = RoundedButton(pw_row, "Anzeigen", toggle_visibility, bg=Theme.NEUTRAL_SOFT,
                                hover=Theme.NEUTRAL_SOFT_HOVER, fg=Theme.TEXT, font=F(9, "bold"),
                                radius=8, padx=10, pady=3, measure_with="Verbergen")
        eye_btn.pack(side="right")

        error = tk.Label(body, text="", font=F(10), bg=Theme.BG, fg=Theme.TEXT)
        error.pack(anchor="w", pady=(10, 0))

        def save_new():
            site = site_entry.get().strip()
            pw = pw_entry.get().strip()
            if not (site and pw):
                error.config(text="Bitte beide Felder ausfüllen.")
                return
            self.vault.add_entry(site, pw)
            self.render_entries()
            dialog.destroy()

        actions = tk.Frame(body, bg=Theme.BG)
        actions.pack(fill="x", pady=(12, 0))
        RoundedButton(actions, "Speichern", save_new, bg=Theme.ACCENT, hover=Theme.ACCENT_HOVER,
                      radius=11, padx=22, pady=10).pack(side="right")
        RoundedButton(actions, "Abbrechen", dialog.destroy, bg=Theme.NEUTRAL_SOFT,
                      hover=Theme.NEUTRAL_SOFT_HOVER, fg=Theme.TEXT, radius=11,
                      padx=22, pady=10).pack(side="right", padx=(0, 10))

        site_entry.bind_return(lambda e: pw_entry.focus_entry())
        pw_entry.bind_return(lambda e: save_new())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        center_window(dialog, self.root)
        dialog.wait_visibility()
        dialog.grab_set()
        if self.translucent:
            try:
                apply_native_translucency(Theme.ALPHA)
            except Exception:
                pass
        dialog.after(50, site_entry.focus_entry)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
