# 🕵️ Forensic Analyzer Dokumen Office (OOXML)

---

## 📌 Deskripsi Singkat
Aplikasi **GUI Python** untuk melakukan **analisis forensik dan keamanan** pada dokumen **Microsoft Office berformat OOXML**, yang mampu mendeteksi **macro malware**, **file tersembunyi**, **embedded objects**, dan **payload polyglot** yang sering digunakan dalam serangan siber berbasis dokumen.

**Format yang didukung:**  
`.docx` • `.docm` • `.dotx` • `.dotm`

---

## 🖼 Preview Aplikasi
![Preview Aplikasi](https://raw.githubusercontent.com/KurniaRadhit/TA_PROGDAS_Radhitya-Kurnia-Asmara_21120125130084_Forensic-Analyzer-Dokumen-Office/main/preview.png)


---

## ✨ Fitur Utama
- 🔍 Deteksi macro & keyword berbahaya  
- 📦 Ekstraksi embedded objects (EXE, DLL, ZIP, JS, dll.)  
- 🕵️ Hidden payload detection (polyglot after ZIP footer)  
- 📑 Metadata & struktur internal dokumen  
- 📈 Entropy analysis & risk scoring  
- 🗃 File carving dari raw binary dokumen  
- 🖥 Antarmuka GUI Python (Tkinter)

---

## 📚 Teknologi yang Digunakan
| Teknologi               | Fungsi                           |
| ----------------------- | -------------------------------- |
| Python                  | Bahasa pemrograman utama         |
| Tkinter                 | GUI Desktop interaktif           |
| Oletools / VBA_Parser   | Ekstraksi & analisis macro       |
| Zipfile & XML Parser    | Analisis struktur dokumen Office |
| Signature & Magic Bytes | File carving & payload detection |
| Entropy analysis        | Penilaian risiko keamanan        |

---

## 📦 Requirements & Cara Menjalankan
```bash
# Install dependencies
pip install oletools
pip install pillow

# Clone repository
git clone https://github.com/<username>/TA_PROGDAS_Radhitya-Kurnia-Asmara_21120125130084_Forensic-Analyzer-Dokumen-Office.git
cd TA_PROGDAS_Radhitya-Kurnia-Asmara_21120125130084_Forensic-Analyzer-Dokumen-Office

# Run program
python main.py
