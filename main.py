import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from analyze import analyze_office, extract_embedded_objects, extract_hidden_after_footer, carve_from_raw
from stegano import embed_stegano_office, extract_stegano_office

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
    root.title("Forensic Analyzer Dokumen Office - DOCX/DOCM/DOTM/DOTX")
    root.geometry("980x620")
    
    try:
        ttk.Style(root).theme_use("clam")
    except:
        pass
    
    # Variable untuk satu file input saja
    file_path = tk.StringVar()
    file_out_stego = tk.StringVar()
    mode_stego = tk.StringVar(value="TEXT")

    WORD_TYPES = [("Word Documents", "*.docx *.docm *.dotm *.dotx")]
    
    # Frame untuk input file (digunakan semua fitur)
    top_frame = ttk.Frame(root, padding=10)
    top_frame.pack(fill="x")
    ttk.Label(top_frame, text="File:").pack(side="left")
    ttk.Entry(top_frame, textvariable=file_path, width=60).pack(side="left", padx=5)
    ttk.Button(top_frame, text="Browse", 
               command=lambda: browse_file(file_path, "Pilih dokumen", 
                                          [("Supported", "*.docx *.docm *.dotm *.dotx")] + WORD_TYPES)).pack(side="left")
    
    # Frame untuk tombol navigasi
    btn_frame = ttk.Frame(root, padding=10)
    btn_frame.pack(fill="x")
    
    # Frame untuk konten
    content_frame = ttk.Frame(root, padding=10)
    content_frame.pack(fill="both", expand=True)
    
    # ===== FRAME 1: ANALISA DOKUMEN =====
    analyze_frame = ttk.Frame(content_frame)
    txt_output = tk.Text(analyze_frame, wrap="word")
    txt_output.pack(fill="both", expand=True)

    def do_analyze():
        if not file_path.get():
            return messagebox.showwarning("Peringatan", "Pilih file dulu.")
        try:
            show_frame(analyze_frame)
            txt_output.delete("1.0", tk.END)
            txt_output.insert(tk.END, format_dict(analyze_office(file_path.get())))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # ===== FRAME 2: STEGO =====
    stego_frame = ttk.Frame(content_frame)
    
    ttk.Label(stego_frame, text="Output (Embed):").grid(row=0, column=0, sticky="w", pady=5)
    ttk.Entry(stego_frame, textvariable=file_out_stego, width=60).grid(row=0, column=1, padx=5, pady=5)
    ttk.Button(stego_frame, text="Browse", 
               command=lambda: browse_save(file_out_stego, os.path.splitext(file_path.get())[1] or ".docx")).grid(row=0, column=2)

    ttk.Label(stego_frame, text="Mode Payload:").grid(row=1, column=0, sticky="w", pady=5)
    ttk.Combobox(stego_frame, textvariable=mode_stego, values=["TEXT", "HASH", "JSON"], width=10).grid(row=1, column=1, sticky="w", pady=5)

    ttk.Label(stego_frame, text="Payload / Watermark:").grid(row=2, column=0, sticky="nw", pady=5)
    txt_payload = tk.Text(stego_frame, width=70, height=12)
    txt_payload.grid(row=2, column=1, columnspan=2, pady=5)

    def do_embed_stego():
        if not file_path.get() or not file_out_stego.get():
            return messagebox.showwarning("Peringatan", "Pilih file input dan output dokumen.")
        text_val = txt_payload.get("1.0", tk.END).strip()
        if not text_val:
            return messagebox.showwarning("Peringatan", "Isi payload dulu.")
        try:
            embed_stegano_office(file_path.get(), file_out_stego.get(), text_val, mode_stego.get())
            messagebox.showinfo("Sukses", f"Payload berhasil di-embed ke:\n{file_out_stego.get()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_extract_stego():
        if not file_path.get():
            return messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
        try:
            msg = extract_stegano_office(file_path.get())
            txt_payload.delete("1.0", tk.END)
            if msg:
                txt_payload.insert(tk.END, msg)
            else:
                messagebox.showinfo("Info", "Tidak ada payload stego.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    btn_stego_frame = ttk.Frame(stego_frame)
    btn_stego_frame.grid(row=3, column=1, columnspan=2, pady=10, sticky="e")
    ttk.Button(btn_stego_frame, text="Embed", command=do_embed_stego).pack(side="left", padx=5)
    ttk.Button(btn_stego_frame, text="Extract", command=do_extract_stego).pack(side="left", padx=5)
    
    # ===== FRAME 3: EXTRACTOR =====
    extractor_frame = ttk.Frame(content_frame)

    def do_extract(func, title, not_found_msg):
        if not file_path.get():
            return messagebox.showwarning("Peringatan", "Pilih dokumen dulu.")
        out_dir = filedialog.askdirectory(title=f"Pilih folder untuk menyimpan {title}")
        if not out_dir:
            return
        try:
            outputs = func(file_path.get(), out_dir)
            msg = f"Berhasil mengekstrak {title}:\n" + "\n".join(outputs) if outputs else f"Tidak ditemukan {not_found_msg}."
            messagebox.showinfo(f"Hasil Extract {title.title()}", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(extractor_frame, text="Extract Embedded Objects", 
               command=lambda: do_extract(extract_embedded_objects, "embedded objects", "embedded objects")).pack(pady=10)
    ttk.Button(extractor_frame, text="Extract Hidden Payload After Footer", 
               command=lambda: do_extract(extract_hidden_after_footer, "hidden payload", "payload setelah footer ZIP")).pack(pady=10)
    ttk.Button(extractor_frame, text="Carve From Raw (Signatures)", 
               command=lambda: do_extract(carve_from_raw, "file carving", "signature yang cocok")).pack(pady=10)
    
    # Fungsi untuk berpindah frame
    def show_frame(frame):
        for f in (analyze_frame, stego_frame, extractor_frame):
            f.pack_forget()
        frame.pack(fill="both", expand=True)
    
    # Tombol navigasi
    ttk.Button(btn_frame, text="Analisa Dokumen", command=do_analyze).pack(side="left", padx=5)
    ttk.Button(btn_frame, text="Stego (Embed/Extract Payload)", 
               command=lambda: show_frame(stego_frame)).pack(side="left", padx=5)
    ttk.Button(btn_frame, text="Extractor (Embedded & Hidden Payload)", 
               command=lambda: show_frame(extractor_frame)).pack(side="left", padx=5)

    show_frame(analyze_frame)
    root.mainloop()

if __name__ == "__main__":
    main()