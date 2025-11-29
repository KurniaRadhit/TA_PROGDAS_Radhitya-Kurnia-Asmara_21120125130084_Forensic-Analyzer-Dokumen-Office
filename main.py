import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from analyze import analyze_office, extract_vba_code
from stegano import embed_stegano_office, extract_stegano_office
from identify import guess_extension

ZIP_EOCD = b"PK\x05\x06"

class StyleManager:
    @staticmethod
    def apply_modern_theme(root):
        style = ttk.Style(root)
        style.theme_use("clam")
        for widget, config in [
            ("TFrame", {"background": "#F4F4F4"}),
            ("TLabel", {"background": "#F4F4F4", "font": ("Segoe UI", 10)}),
            ("TButton", {"font": ("Segoe UI", 10), "padding": 6}),
            ("TCombobox", {"padding": 4, "font": ("Segoe UI", 10)})
        ]:
            style.configure(widget, **config)
        style.map("TButton", background=[("active", "#E0E0E0")])
    
    @staticmethod
    def style_textbox(widget):
        widget.config(bg="#FFFFFF", fg="#222", insertbackground="#000", relief="flat",
                     highlightthickness=1, highlightcolor="#BBBBBB", font=("Consolas", 11))

class ZipFooterAnalyzer:
    @staticmethod
    def find_footer_end(data: bytes) -> int | None:
        if (idx := data.rfind(ZIP_EOCD)) == -1:
            return None
        try:
            comment_len = int.from_bytes(data[idx + 20:idx + 22], "little")
            return end if (end := idx + 22 + comment_len) <= len(data) else None
        except:
            return None

class FormatHelper:
    @staticmethod
    def format_dict(d, indent=0):
        lines, pad = [], " " * indent
        for k, v in d.items():
            if isinstance(v, dict):
                lines.extend([f"{pad}{k}:", FormatHelper.format_dict(v, indent + 2)])
            elif isinstance(v, list):
                lines.append(f"{pad}{k}:")
                lines.extend(f"{pad}  - {item}" for item in v)
            else:
                lines.append(f"{pad}{k}: {v}")
        return "\n".join(lines)

class BasePanel:
    def __init__(self, parent, file_path_var, title=None):
        self.file_path = file_path_var
        self.frame = ttk.Frame(parent)
        if title:
            ttk.Label(self.frame, text=title, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 8))
    
    def check_file_selected(self, silent=False):
        if not self.file_path.get():
            if not silent:
                messagebox.showwarning("Peringatan", 
                    "Silakan pilih file .docx • .docm • .dotx • .dotm terlebih dahulu!")
            return False
        return True
    
    def on_file_changed(self):
        pass

class AnalyzerPanel(BasePanel):
    def __init__(self, parent, file_path_var):
        super().__init__(parent, file_path_var, "Hasil Analisa Dokumen")
        self.txt_output = tk.Text(self.frame, height=32)
        StyleManager.style_textbox(self.txt_output)
        self.txt_output.pack(fill="both", expand=True)
    
    def on_show(self):
        self.txt_output.delete("1.0", tk.END)
        if self.check_file_selected():
            try:
                self.txt_output.insert(tk.END, FormatHelper.format_dict(analyze_office(self.file_path.get())))
            except Exception as e:
                messagebox.showerror("Error", str(e))

class SteganographyPanel(BasePanel):
    def __init__(self, parent, file_path_var):
        super().__init__(parent, file_path_var, title=None)
        self.file_out = tk.StringVar()
        self.mode = tk.StringVar(value="TEXT")
        self._build_ui()
    
    def on_show(self):
        self.txt_payload.delete("1.0", tk.END)
        self.file_out.set("")
        self.check_file_selected()
    
    def on_file_changed(self):
        self.txt_payload.delete("1.0", tk.END)
        self.file_out.set("")
    
    def _build_ui(self):
        ttk.Label(self.frame, text="Steganography Tools", 
                 font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Label(self.frame, text="Output File:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(self.frame, textvariable=self.file_out, width=70).grid(row=1, column=1, padx=4)
        ttk.Button(self.frame, text="Browse", command=self._browse_output).grid(row=1, column=2)
        ttk.Label(self.frame, text="Mode Payload:").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Combobox(self.frame, textvariable=self.mode, values=["TEXT", "HASH", "JSON"], 
                    width=10).grid(row=2, column=1, sticky="w")
        ttk.Label(self.frame, text="Payload / Pesan Rahasia:").grid(row=3, column=0, sticky="nw", pady=5)
        self.txt_payload = tk.Text(self.frame, height=12)
        StyleManager.style_textbox(self.txt_payload)
        self.txt_payload.grid(row=3, column=1, columnspan=2, pady=5)
        btns = ttk.Frame(self.frame)
        btns.grid(row=4, column=1, sticky="e", pady=8)
        ttk.Button(btns, text="Embed", command=self.embed).pack(side="left", padx=5)
        ttk.Button(btns, text="Extract", command=self.extract).pack(side="left")
    
    def _browse_output(self):
        ext = os.path.splitext(self.file_path.get())[1] or ".docx"
        if path := filedialog.asksaveasfilename(title="Simpan hasil", defaultextension=ext,
                                               filetypes=[("Document", f"*{ext}")]):
            self.file_out.set(path)
    
    def embed(self):
        if not self.file_path.get() or not self.file_out.get():
            messagebox.showwarning("Peringatan", "Pilih file input & output.")
            return
        if not (val := self.txt_payload.get("1.0", tk.END).strip()):
            messagebox.showwarning("Peringatan", "Isi payload dulu.")
            return
        try:
            embed_stegano_office(self.file_path.get(), self.file_out.get(), val, self.mode.get())
            messagebox.showinfo("Sukses", f"Payload berhasil di-embed:\n{self.file_out.get()}")
            self.txt_payload.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def extract(self):
        if not self.check_file_selected():
            return
        try:
            msg = extract_stegano_office(self.file_path.get())
            self.txt_payload.delete("1.0", tk.END)
            if msg:
                self.txt_payload.insert(tk.END, msg)
            else:
                messagebox.showinfo("Info", "Tidak ada payload stego.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

class ExtractorPanel(BasePanel):
    def __init__(self, parent, file_path_var):
        super().__init__(parent, file_path_var, "Macro & Hidden Payload After ZIP Footer")
        self._build_ui()
    
    def on_show(self):
        self.txt_embedded.delete("1.0", tk.END)
        if self.check_file_selected():
            self._display_vba_macros()
            self._display_hidden_payload()
    
    def _build_ui(self):
        ttk.Button(self.frame, text="Save Hidden Payload", 
                  command=self.save_payload).pack(anchor="w", pady=(0, 10))
        wrapper = ttk.Frame(self.frame)
        wrapper.pack(fill="both", expand=True)
        self.txt_embedded = tk.Text(wrapper, height=28)
        StyleManager.style_textbox(self.txt_embedded)
        self.txt_embedded.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(wrapper, command=self.txt_embedded.yview)
        scrollbar.pack(side="right", fill="y")
        self.txt_embedded.config(yscrollcommand=scrollbar.set)
    
    def _display_vba_macros(self):
        self.txt_embedded.insert(tk.END, "[VBA Macro - vbaProject.bin]\n" + "-" * 100 + "\n")
        try:
            self.txt_embedded.insert(tk.END, extract_vba_code(self.file_path.get()) + "\n\n")
        except Exception as e:
            self.txt_embedded.insert(tk.END, f"Gagal mengekstrak VBA: {e}\n\n")
    
    def _display_hidden_payload(self):
        self.txt_embedded.insert(tk.END, "[Hidden Payload After ZIP Footer]\n" + "-" * 100 + "\n")
        try:
            with open(self.file_path.get(), "rb") as f:
                raw = f.read()
        except Exception as e:
            self.txt_embedded.insert(tk.END, f"Gagal membaca raw data: {e}\n")
            return
        footer_end = ZipFooterAnalyzer.find_footer_end(raw)
        if not footer_end or footer_end >= len(raw):
            self.txt_embedded.insert(tk.END, "Tidak ditemukan data setelah footer ZIP/dokumen.\n")
            return
        payload = raw[footer_end:]
        if not payload:
            self.txt_embedded.insert(tk.END, "Data setelah footer ZIP berukuran 0 byte.\n")
            return
        ext_guess = guess_extension(payload) or ".bin"
        magic_hex = payload[:16].hex(" ").upper() 
        self.txt_embedded.insert(tk.END, 
            f"Ukuran payload : {len(payload)} byte\n"
            f"Tebakan ekstensi: {ext_guess}\n"
            f"Magic bytes     : {magic_hex}\n\n")
        preview = payload[:512]
        try:
            text = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' 
                          for c in preview.decode("utf-8", errors="ignore"))
            self.txt_embedded.insert(tk.END, text)
            if len(payload) > 512:
                self.txt_embedded.insert(tk.END, "\n... (truncated preview)")
        except:
            self.txt_embedded.insert(tk.END, "[Binary preview tidak dapat didekode]\n")
    
    def save_payload(self):
        if not self.check_file_selected():
            return
        if not (out_dir := filedialog.askdirectory(title="Pilih folder output hidden payload (after footer)")):
            return
        try:
            with open(self.file_path.get(), "rb") as f:
                raw = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membaca raw data: {e}")
            return
        footer_end = ZipFooterAnalyzer.find_footer_end(raw)
        if not footer_end or footer_end >= len(raw):
            messagebox.showinfo("Info", "Tidak ditemukan data setelah footer ZIP/dokumen.")
            return
        payload = raw[footer_end:]
        if len(payload) < 32:
            messagebox.showinfo("Info", f"Data setelah footer ZIP hanya {len(payload)} byte.")
            return
        ext_guess = guess_extension(payload) or ".bin"
        base = os.path.splitext(os.path.basename(self.file_path.get()))[0]
        out_path = os.path.join(out_dir, f"{base}_after_footer{ext_guess}")
        try:
            with open(out_path, "wb") as out:
                out.write(payload)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyimpan payload: {e}")
            return
        magic_hex = payload[:16].hex(" ").upper()
        messagebox.showinfo("Sukses",
            f"Payload setelah footer ZIP berhasil disimpan.\n\n"
            f"Lokasi   : {out_path}\n"
            f"Ukuran   : {len(payload)} byte\n"
            f"Tebakan  : {ext_guess}\n"
            f"Magic    : {magic_hex}")
        self.txt_embedded.insert(tk.END, 
            f"\n[Save Hidden Payload (After ZIP Footer)]\n"
            f"Output file : {out_path}\n"
            f"Ukuran      : {len(payload)} byte\n"
            f"Ekstensi    : {ext_guess}\n"
            f"Magic bytes : {magic_hex}\n")

class ForensicAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Analyzer Dokumen Office")
        self.root.geometry("1080x720")
        self.root.minsize(1000, 650)
        StyleManager.apply_modern_theme(self.root)
        self.file_path = tk.StringVar()
        self.is_first_load = True
        self._build_ui()
        self.file_path.trace_add("write", self._on_file_path_changed)
    
    def _on_file_path_changed(self, *args):
        for panel in self.panels:
            if hasattr(panel, 'on_file_changed'):
                panel.on_file_changed()
    
    def _build_ui(self):
        top = ttk.Frame(self.root, padding=15)
        top.pack(fill="x")
        ttk.Label(top, text="File:", font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Entry(top, textvariable=self.file_path, width=70).pack(side="left", padx=8)
        ttk.Button(top, text="Browse", command=self._browse_file).pack(side="left", padx=4)
        nav = ttk.Frame(self.root, padding=10)
        nav.pack(fill="x")
        content = ttk.Frame(self.root, padding=10)
        content.pack(fill="both", expand=True)
        content.pack_propagate(False)
        self.panels = [
            AnalyzerPanel(content, self.file_path),
            SteganographyPanel(content, self.file_path),
            ExtractorPanel(content, self.file_path)
        ]
        for text, panel in zip(["Analisa Dokumen", "Stegano", "Extractor Embedded"], self.panels):
            ttk.Button(nav, text=text, 
                      command=lambda p=panel: self.show_panel(p)).pack(side="left", padx=6)
        self.show_panel(self.panels[0])
    
    def _browse_file(self):
        if path := filedialog.askopenfilename(title="Pilih dokumen",
                filetypes=[("Word Documents", "*.docx *.docm *.dotm *.dotx")]):
            self.file_path.set(path)
    
    def show_panel(self, panel):
        for p in self.panels:
            p.frame.pack_forget()
        panel.frame.pack(fill="both", expand=True)
        if not self.is_first_load and hasattr(panel, 'on_show'):
            panel.on_show()
        self.is_first_load = False
    
    def run(self):
        self.root.mainloop()

def main():
    ForensicAnalyzerApp(tk.Tk()).run()

if __name__ == "__main__":
    main()
