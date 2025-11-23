# Forensic Analyzer Dokumen Office (OOXML)

---

## Deskripsi Singkat
Program GUI Python untuk melakukan analisis forensik dan keamanan pada dokumen Microsoft Office berformat OOXML yang dapat mendeteksi macro malware, file tersembunyi, embedded objects, dan payload polyglot yang sering digunakan dalam serangan siber berbasis dokumen.

Format yang didukung:
`.docx` • `.docm` • `.dotx` • `.dotm`

---

## Preview Program
![Preview Aplikasi](https://raw.githubusercontent.com/KurniaRadhit/TA_PROGDAS_Radhitya-Kurnia-Asmara_21120125130084_Forensic-Analyzer-Dokumen-Office/main/preview.png)

---

## Fitur Utama
- Deteksi macro dan keyword berbahaya
- Ekstraksi embedded objects (EXE, DLL, ZIP, JS, dan lain-lain)
- Deteksi payload tersembunyi (polyglot after ZIP footer)
- Analisis metadata dan struktur internal dokumen
- Perhitungan entropy dan risk scoring
- File carving dari raw binary dokumen
- Antarmuka GUI Python (Tkinter)

---

## Teknologi yang Digunakan
| Teknologi | Fungsi |
|-----------|--------|
| Python | Bahasa pemrograman utama |
| Tkinter | GUI desktop interaktif |
| Oletools / VBA_Parser | Ekstraksi dan analisis macro |
| Zipfile & XML Parser | Analisis struktur dokumen Office |
| Signature & Magic Bytes | File carving dan payload detection |
| Entropy Analysis | Penilaian risiko keamanan |

---

## Requirements & Cara Menjalankan

```bash
# Install dependencies
pip install oletools

# Clone repository
git clone https://github.com/<username>/TA_PROGDAS_Radhitya-Kurnia-Asmara_21120125130084_Forensic-Analyzer-Dokumen-Office.git
cd TA_PROGDAS_Radhitya-Kurnia-Asmara_21120125130084_Forensic-Analyzer-Dokumen-Office

# Run program
python main.py
