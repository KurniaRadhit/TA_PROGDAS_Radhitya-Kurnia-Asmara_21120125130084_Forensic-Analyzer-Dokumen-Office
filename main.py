import os
import zipfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from analyze import analyze_office, extract_vba_code
from stegano import embed_stegano_office, extract_stegano_office
from identify import guess_extension  
ZIP_EOCD = b"PK\x05\x06"
def _find_zip_footer_end(data: bytes) -> int | None:
    idx = data.rfind(ZIP_EOCD)
    if idx == -1:
        return None
    try:
        comment_len = int.from_bytes(data[idx + 20: idx + 22], "little")
        end = idx + 22 + comment_len
        return end if end <= len(data) else None
    except Exception:
        return None

def apply_modern_style(root):
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure("TFrame", background="#F4F4F4")
    style.configure("TLabel", background="#F4F4F4", font=("Segoe UI", 10))
    style.configure("TButton", font=("Segoe UI", 10), padding=6)
    style.configure("TCombobox", padding=4, font=("Segoe UI", 10))
    style.map("TButton", background=[("active", "#E0E0E0")])

def modern_textbox(widget):
    widget.config(
        bg="#FFFFFF",
        fg="#222",
        insertbackground="#000",
        relief="flat",
        highlightthickness=1,
        highlightcolor="#BBBBBB",
        font=("Consolas", 11),
    )

def format_dict(d, indent=0):
    lines = []
    pad = " " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(format_dict(v, indent + 2))
        elif isinstance(v, list):
            lines.append(f"{pad}{k}:")
            for item in v:
                lines.append(f"{pad}  - {item}")
        else:
            lines.append(f"{pad}{k}: {v}")
    return "\n".join(lines)


def browse_file(var, title, filetypes):
    path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    if path:
        var.set(path)


def browse_save(var, default_ext):
    path = filedialog.asksaveasfilename(
        title="Simpan hasil",
        defaultextension=default_ext,
        filetypes=[("Document", f"*{default_ext}")]
    )
    if path:
        var.set(path)
def main():
    root = tk.Tk()
    root.title("Forensic Analyzer Dokumen Office")
    root.geometry("1080x720")
    root.minsize(1000, 650)

    apply_modern_style(root)

    file_path = tk.StringVar()
    file_out_stego = tk.StringVar()
    mode_stego = tk.StringVar(value="TEXT")
    top = ttk.Frame(root, padding=15)
    top.pack(fill="x")

    ttk.Label(top, text="File:", font=("Segoe UI", 11, "bold")).pack(side="left")
    entry = ttk.Entry(top, textvariable=file_path, width=70)
    entry.pack(side="left", padx=8)

    ttk.Button(
        top, text="Browse",
        command=lambda: browse_file(
            file_path,
            "Pilih dokumen",
            [("Word Documents", "*.docx *.docm *.dotm *.dotx")]
        )
    ).pack(side="left", padx=4)
    nav = ttk.Frame(root, padding=10)
    nav.pack(fill="x")

    content = ttk.Frame(root, padding=10)
    content.pack(fill="both", expand=True)
    content.pack_propagate(False)
    analyze_frame = ttk.Frame(content)

    header1 = ttk.Label(
        analyze_frame,
        text="Hasil Analisa Dokumen",
        font=("Segoe UI", 12, "bold")
    )
    header1.pack(anchor="w", pady=(0, 8))

    txt_output = tk.Text(analyze_frame, height=32)
    modern_textbox(txt_output)
    txt_output.pack(fill="both", expand=True)

    def do_analyze():
        if not file_path.get():
            messagebox.showwarning("Peringatan", "Pilih file dulu.")
            return

        try:
            txt_output.delete("1.0", tk.END)
            results = analyze_office(file_path.get())
            txt_output.insert(tk.END, format_dict(results))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    stego_frame = ttk.Frame(content)

    ttk.Label(
        stego_frame,
        text="Steganography Tools",
        font=("Segoe UI", 12, "bold")
    ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

    ttk.Label(stego_frame, text="Output File:").grid(row=1, column=0, sticky="w")
    ttk.Entry(stego_frame, textvariable=file_out_stego, width=70)\
        .grid(row=1, column=1, padx=4)

    ttk.Button(
        stego_frame,
        text="Browse",
        command=lambda: browse_save(
            file_out_stego,
            os.path.splitext(file_path.get())[1] or ".docx"
        )
    ).grid(row=1, column=2)

    ttk.Label(stego_frame, text="Mode Payload:").grid(row=2, column=0, sticky="w", pady=5)
    ttk.Combobox(
        stego_frame,
        textvariable=mode_stego,
        values=["TEXT", "HASH", "JSON"],
        width=10
    ).grid(row=2, column=1, sticky="w")

    ttk.Label(stego_frame, text="Payload / Pesan Rahasia:").grid(row=3, column=0, sticky="nw", pady=5)

    txt_payload = tk.Text(stego_frame, height=12)
    modern_textbox(txt_payload)
    txt_payload.grid(row=3, column=1, columnspan=2, pady=5)

    def do_embed_stego():
        if not file_path.get() or not file_out_stego.get():
            messagebox.showwarning("Peringatan", "Pilih file input & output.")
            return

        val = txt_payload.get("1.0", tk.END).strip()
        if not val:
            messagebox.showwarning("Peringatan", "Isi payload dulu.")
            return

        try:
            embed_stegano_office(
                file_path.get(),
                file_out_stego.get(),
                val,
                mode_stego.get()
            )
            messagebox.showinfo("Sukses", f"Payload berhasil di-embed:\n{file_out_stego.get()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_extract_stego():
        if not file_path.get():
            messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
            return

        try:
            msg = extract_stegano_office(file_path.get())
            txt_payload.delete("1.0", tk.END)

            if msg:
                txt_payload.insert(tk.END, msg)
            else:
                messagebox.showinfo("Info", "Tidak ada payload stego.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    btns = ttk.Frame(stego_frame)
    btns.grid(row=4, column=1, sticky="e", pady=8)

    ttk.Button(btns, text="Embed", command=do_embed_stego).pack(side="left", padx=5)
    ttk.Button(btns, text="Extract", command=do_extract_stego).pack(side="left")
    extractor_frame = ttk.Frame(content)

    ttk.Label(
        extractor_frame,
        text=" Macro & Hidden Payload After ZIP Footer",
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", pady=(0, 10))

    btn_bar = ttk.Frame(extractor_frame)
    btn_bar.pack(anchor="w", pady=(0, 10))

    btn_extract = ttk.Button(
        btn_bar,
        text="Tampilkan Macro & Hidden Payload"
    )
    btn_extract.pack(side="left", padx=(0, 8))

    btn_save = ttk.Button(
        btn_bar,
        text="Save Hidden Payload"
    )
    btn_save.pack(side="left")

    wrapper = ttk.Frame(extractor_frame)
    wrapper.pack(fill="both", expand=True)

    txt_embedded = tk.Text(wrapper, height=28)
    modern_textbox(txt_embedded)
    txt_embedded.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(wrapper, command=txt_embedded.yview)
    scrollbar.pack(side="right", fill="y")
    txt_embedded.config(yscrollcommand=scrollbar.set)
    def show_embedded_objects():
        if not file_path.get():
            messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
            return

        txt_embedded.delete("1.0", tk.END)

        txt_embedded.insert(tk.END, "[VBA Macro - vbaProject.bin]\n")
        txt_embedded.insert(tk.END, "-" * 100 + "\n")

        try:
            macro_text = extract_vba_code(file_path.get())
            txt_embedded.insert(tk.END, macro_text + "\n\n")
        except Exception as e:
            txt_embedded.insert(tk.END, f"Gagal mengekstrak VBA: {e}\n\n")

        txt_embedded.insert(tk.END, "[Hidden Payload After ZIP Footer]\n")
        txt_embedded.insert(tk.END, "-" * 100 + "\n")

        try:
            with open(file_path.get(), "rb") as f:
                raw = f.read()
        except Exception as e:
            txt_embedded.insert(tk.END, f"Gagal membaca raw data: {e}\n")
            return

        if not raw:
            txt_embedded.insert(tk.END, "Raw data kosong / gagal dibaca.\n")
            return

        footer_end = _find_zip_footer_end(raw)
        if not footer_end or footer_end >= len(raw):
            txt_embedded.insert(tk.END, "Tidak ditemukan data setelah footer ZIP/dokumen.\n")
            return

        payload = raw[footer_end:]
        payload_len = len(payload)

        if payload_len < 1:
            txt_embedded.insert(tk.END, "Data setelah footer ZIP berukuran 0 byte.\n")
            return

        ext_guess = guess_extension(payload) or ".bin"
        magic_bytes_hex = payload[:16].hex(" ").upper()

        txt_embedded.insert(
            tk.END,
            f"Ukuran payload : {payload_len} byte\n"
            f"Tebakan ekstensi: {ext_guess}\n"
            f"Magic bytes     : {magic_bytes_hex}\n\n"
        )

        preview = payload[:512]
        try:
            text = preview.decode("utf-8", errors="ignore")
            text = ''.join(
                c if c.isprintable() or c in '\n\r\t' else '.'
                for c in text
            )
            txt_embedded.insert(tk.END, text)
            if payload_len > 512:
                txt_embedded.insert(tk.END, "\n... (truncated preview)")
        except Exception:
            txt_embedded.insert(tk.END, "[Binary preview tidak dapat didekode]\n")
    btn_extract.config(command=show_embedded_objects)
    def save_carved_payloads():
        if not file_path.get():
            messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
            return
        out_dir = filedialog.askdirectory(
            title="Pilih folder output hidden payload (after footer)")
        if not out_dir:
            return
        try:
            with open(file_path.get(), "rb") as f:
                raw = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membaca raw data: {e}")
            return
        if not raw:
            messagebox.showinfo("Info", "Raw data kosong, tidak ada yang dapat diekstrak.")
            return
        footer_end = _find_zip_footer_end(raw)
        if not footer_end or footer_end >= len(raw):
            messagebox.showinfo(
                "Info",
                "Tidak ditemukan data setelah footer ZIP/dokumen. "
                "Kemungkinan bukan polyglot file."
            )
            return
        payload = raw[footer_end:]
        payload_len = len(payload)
        if payload_len < 32:
            messagebox.showinfo(
                "Info",
                f"Data setelah footer ZIP hanya {payload_len} byte; "
                "terlalu kecil untuk diekstrak sebagai file terpisah."
            )
            return
        ext_guess = guess_extension(payload) or ".bin"
        base = os.path.splitext(os.path.basename(file_path.get()))[0]
        out_path = os.path.join(out_dir, f"{base}_after_footer{ext_guess}")
        try:
            with open(out_path, "wb") as out:
                out.write(payload)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyimpan payload: {e}")
            return
        magic_bytes_hex = payload[:16].hex(" ").upper()
        messagebox.showinfo(
            "Sukses",
            "Payload setelah footer ZIP berhasil disimpan.\n\n"
            f"Lokasi   : {out_path}\n"
            f"Ukuran   : {payload_len} byte\n"
            f"Tebakan  : {ext_guess}\n"
            f"Magic    : {magic_bytes_hex}"
        )
        txt_embedded.insert(tk.END, "\n[Save Hidden Payload (After ZIP Footer)]\n")
        txt_embedded.insert(tk.END, f"Output file : {out_path}\n")
        txt_embedded.insert(tk.END, f"Ukuran      : {payload_len} byte\n")
        txt_embedded.insert(tk.END, f"Ekstensi    : {ext_guess}\n")
        txt_embedded.insert(tk.END, f"Magic bytes : {magic_bytes_hex}\n")
    btn_save.config(command=save_carved_payloads)
    def show_frame(frame):
        for f in (analyze_frame, stego_frame, extractor_frame):
            f.pack_forget()
        frame.pack(fill="both", expand=True)
    ttk.Button(
        nav, text="Analisa Dokumen",
        command=lambda: [show_frame(analyze_frame), do_analyze()]
    ).pack(side="left", padx=6)
    ttk.Button(
        nav, text="Stegano",
        command=lambda: show_frame(stego_frame)
    ).pack(side="left", padx=6)
    ttk.Button(
        nav, text="Extractor Embedded",
        command=lambda: show_frame(extractor_frame)
    ).pack(side="left", padx=6)
    show_frame(analyze_frame)
    root.mainloop()

if __name__ == "__main__":
    main()
