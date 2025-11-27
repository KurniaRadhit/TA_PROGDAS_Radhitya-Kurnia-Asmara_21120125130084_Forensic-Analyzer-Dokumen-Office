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
        idx = data.rfind(ZIP_EOCD)
        if idx == -1:
            return None
        try:
            comment_len = int.from_bytes(data[idx + 20:idx + 22], "little")
            end = idx + 22 + comment_len
            return end if end <= len(data) else None
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
                lines.extend([f"{pad}  - {item}" for item in v])
            else:
                lines.append(f"{pad}{k}: {v}")
        return "\n".join(lines)

class FileDialogHelper:
    @staticmethod
    def browse_file(var, title, filetypes):
        if path := filedialog.askopenfilename(title=title, filetypes=filetypes):
            var.set(path)
    
    @staticmethod
    def browse_save(var, default_ext):
        if path := filedialog.asksaveasfilename(title="Simpan hasil", defaultextension=default_ext,
                                                filetypes=[("Document", f"*{default_ext}")]):
            var.set(path)

class AnalyzerPanel:
    def __init__(self, parent, file_path_var):
        self.file_path = file_path_var
        self.frame = ttk.Frame(parent)
        ttk.Label(self.frame, text="Hasil Analisa Dokumen", 
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 8))
        self.txt_output = tk.Text(self.frame, height=32)
        StyleManager.style_textbox(self.txt_output)
        self.txt_output.pack(fill="both", expand=True)
    
    def analyze(self, silent=False):
        if not self.file_path.get():
            if not silent:
                messagebox.showwarning("Peringatan", "Pilih file dulu.")
            return
        try:
            self.txt_output.delete("1.0", tk.END)
            self.txt_output.insert(tk.END, FormatHelper.format_dict(analyze_office(self.file_path.get())))
        except Exception as e:
            messagebox.showerror("Error", str(e))

class SteganographyPanel:
    def __init__(self, parent, file_path_var):
        self.file_path = file_path_var
        self.file_out = tk.StringVar()
        self.mode = tk.StringVar(value="TEXT")
        self.frame = ttk.Frame(parent)
        self._build_ui()
    
    def _build_ui(self):
        ttk.Label(self.frame, text="Steganography Tools", 
                 font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        
        for i, (label, var, cmd) in enumerate([
            ("Output File:", self.file_out, lambda: FileDialogHelper.browse_save(
                self.file_out, os.path.splitext(self.file_path.get())[1] or ".docx")),
            ("Mode Payload:", self.mode, None)
        ], 1):
            ttk.Label(self.frame, text=label).grid(row=i, column=0, sticky="w", pady=5)
            if cmd:
                ttk.Entry(self.frame, textvariable=var, width=70).grid(row=i, column=1, padx=4)
                ttk.Button(self.frame, text="Browse", command=cmd).grid(row=i, column=2)
            else:
                ttk.Combobox(self.frame, textvariable=var, values=["TEXT", "HASH", "JSON"], 
                           width=10).grid(row=i, column=1, sticky="w")
        ttk.Label(self.frame, text="Payload / Pesan Rahasia:").grid(row=3, column=0, sticky="nw", pady=5)
        self.txt_payload = tk.Text(self.frame, height=12)
        StyleManager.style_textbox(self.txt_payload)
        self.txt_payload.grid(row=3, column=1, columnspan=2, pady=5)
        btns = ttk.Frame(self.frame)
        btns.grid(row=4, column=1, sticky="e", pady=8)
        ttk.Button(btns, text="Embed", command=self.embed).pack(side="left", padx=5)
        ttk.Button(btns, text="Extract", command=self.extract).pack(side="left")
    
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
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def extract(self):
        if not self.file_path.get():
            messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
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

class ExtractorPanel:
    def __init__(self, parent, file_path_var):
        self.file_path = file_path_var
        self.frame = ttk.Frame(parent)
        self._build_ui()
    
    def _build_ui(self):
        ttk.Label(self.frame, text=" Macro & Hidden Payload After ZIP Footer", 
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 10))
        btn_bar = ttk.Frame(self.frame)
        btn_bar.pack(anchor="w", pady=(0, 10))
        ttk.Button(btn_bar, text="Tampilkan Macro & Hidden Payload", 
                  command=self.show_embedded).pack(side="left", padx=(0, 8))
        ttk.Button(btn_bar, text="Save Hidden Payload", 
                  command=self.save_payload).pack(side="left")
        wrapper = ttk.Frame(self.frame)
        wrapper.pack(fill="both", expand=True)
        self.txt_embedded = tk.Text(wrapper, height=28)
        StyleManager.style_textbox(self.txt_embedded)
        self.txt_embedded.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(wrapper, command=self.txt_embedded.yview)
        scrollbar.pack(side="right", fill="y")
        self.txt_embedded.config(yscrollcommand=scrollbar.set)
    
    def show_embedded(self):
        if not self.file_path.get():
            messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
            return
        self.txt_embedded.delete("1.0", tk.END)
        self._display_vba_macros()
        self._display_hidden_payload()
    
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
        if len(payload) < 1:
            self.txt_embedded.insert(tk.END, "Data setelah footer ZIP berukuran 0 byte.\n")
            return
        ext_guess = guess_extension(payload) or ".bin"
        magic_bytes_hex = payload[:16].hex(" ").upper()
        self.txt_embedded.insert(tk.END, 
            f"Ukuran payload : {len(payload)} byte\n"
            f"Tebakan ekstensi: {ext_guess}\n"
            f"Magic bytes     : {magic_bytes_hex}\n\n"
        )
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
        if not self.file_path.get():
            messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
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
        magic_bytes_hex = payload[:16].hex(" ").upper()
        messagebox.showinfo("Sukses",
            f"Payload setelah footer ZIP berhasil disimpan.\n\n"
            f"Lokasi   : {out_path}\n"
            f"Ukuran   : {len(payload)} byte\n"
            f"Tebakan  : {ext_guess}\n"
            f"Magic    : {magic_bytes_hex}"
        )
        self.txt_embedded.insert(tk.END, 
            f"\n[Save Hidden Payload (After ZIP Footer)]\n"
            f"Output file : {out_path}\n"
            f"Ukuran      : {len(payload)} byte\n"
            f"Ekstensi    : {ext_guess}\n"
            f"Magic bytes : {magic_bytes_hex}\n"
        )

class ForensicAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Analyzer Dokumen Office")
        self.root.geometry("1080x720")
        self.root.minsize(1000, 650)
        StyleManager.apply_modern_theme(self.root)
        self.file_path = tk.StringVar()
        self._build_ui()
    
    def _build_ui(self):
        top = ttk.Frame(self.root, padding=15)
        top.pack(fill="x")
        ttk.Label(top, text="File:", font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Entry(top, textvariable=self.file_path, width=70).pack(side="left", padx=8)
        ttk.Button(top, text="Browse", 
                  command=lambda: FileDialogHelper.browse_file(
                      self.file_path, "Pilih dokumen",
                      [("Word Documents", "*.docx *.docm *.dotm *.dotx")]
                  )).pack(side="left", padx=4)
        nav = ttk.Frame(self.root, padding=10)
        nav.pack(fill="x")
        for text, cmd in [
            ("Analisa Dokumen", lambda: [self.show_frame(self.analyzer_panel.frame), self.analyzer_panel.analyze()]),
            ("Stegano", lambda: self.show_frame(self.stego_panel.frame)),
            ("Extractor Embedded", lambda: self.show_frame(self.extractor_panel.frame))
        ]:
            ttk.Button(nav, text=text, command=cmd).pack(side="left", padx=6)
        content = ttk.Frame(self.root, padding=10)
        content.pack(fill="both", expand=True)
        content.pack_propagate(False)
        self.analyzer_panel = AnalyzerPanel(content, self.file_path)
        self.stego_panel = SteganographyPanel(content, self.file_path)
        self.extractor_panel = ExtractorPanel(content, self.file_path)
        self.panels = [self.analyzer_panel.frame, self.stego_panel.frame, self.extractor_panel.frame]
        self.show_frame(self.analyzer_panel.frame)
    
    def show_frame(self, frame):
        for panel in self.panels:
            panel.pack_forget()
        frame.pack(fill="both", expand=True)
    
    def run(self):
        self.root.mainloop()

def main():
    ForensicAnalyzerApp(tk.Tk()).run()

if __name__ == "__main__":
    main()
