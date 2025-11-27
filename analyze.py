import os
import zipfile
from typing import Dict, Any, List
from xml.etree import ElementTree as ET
from oletools.olevba import VBA_Parser
from identify import guess_extension

class DocumentAnalyzer:
    SUSPICIOUS_EXT = [".exe", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".jar", ".scr"]
    WATERMARK_WORDS = ["WATERMARK", "CONFIDENTIAL", "DRAFT", "RAHASIA"]
    SUSPICIOUS_MACRO_KW = [
        "CreateObject", "WScript.Shell", "Shell(", "powershell", "cmd.exe",
        "URLDownloadToFile", "DownloadString", "Run", "WriteAllBytes"
    ]
    ZIP_EOCD = b"PK\x05\x06"

    def __init__(self, path: str):
        self.path = path
        self.result = {
            "path": path, "filesize_bytes": 0, "basic_info": {}, "metadata": {},
            "compression": {}, "watermark": {}, "embedded_files": [],
            "macro_info": {}, "polyglot": {"has_trailing_data": False}, "risk_flags": []
        }
        self._validate_file()
    
    def _validate_file(self):
        ext = os.path.splitext(self.path)[1].lower()
        if ext not in (".docx", ".docm", ".dotm", ".dotx"):
            raise ValueError("Hanya mendukung DOCX/DOCM/DOTM/DOTX (OOXML).")
        self.result["filesize_bytes"] = os.path.getsize(self.path) if os.path.exists(self.path) else 0
    
    def _find_zip_footer_end(self, data: bytes) -> int | None:
        idx = data.rfind(self.ZIP_EOCD)
        if idx == -1:
            return None
        try:
            comment_len = int.from_bytes(data[idx + 20:idx + 22], "little")
            return idx + 22 + comment_len
        except:
            return None
    
    def _analyze_polyglot(self) -> List[str]:
        suspicious = []
        try:
            with open(self.path, "rb") as f:
                raw_data = f.read()
            footer_end = self._find_zip_footer_end(raw_data)
            if footer_end and footer_end < len(raw_data):
                trailing = raw_data[footer_end:]
                if len(trailing) > 32:
                    guessed_ext = guess_extension(trailing)
                    self.result["polyglot"] = {
                        "has_trailing_data": True, "trailing_bytes": len(trailing),
                        "guessed_extension": guessed_ext,
                        "note": f"Data tersembunyi ditemukan setelah footer ZIP (kemungkinan: {guessed_ext})"
                    }
                    suspicious.append(f"Polyglot terdeteksi: {len(trailing)} byte setelah footer ZIP → kemungkinan file {guessed_ext}.")
                else:
                    self.result["polyglot"] = {
                        "has_trailing_data": True, "trailing_bytes": len(trailing),
                        "note": "Data setelah footer ZIP terlalu kecil untuk dianalisis."
                    }
        except:
            pass
        return suspicious
    
    def _analyze_compression(self, zf: zipfile.ZipFile) -> float:
        info_list = zf.infolist()
        total_uncompressed = sum(info.file_size for info in info_list)
        total_compressed = sum(info.compress_size for info in info_list)
        ratio = 1 - (total_compressed / total_uncompressed) if total_uncompressed > 0 else 0.0
        self.result["compression"] = {
            "total_uncompressed_bytes": total_uncompressed,
            "total_compressed_bytes": total_compressed,
            "approx_compression_ratio": round(ratio, 3)
        }
        return ratio
    
    def _analyze_macros(self, zf: zipfile.ZipFile, namelist: List[str]) -> tuple:
        has_macro = any("vbaproject.bin" in n.lower() for n in namelist)
        suspicious_kw, suspicious = [], []
        if has_macro:
            suspicious.append("vbaProject.bin ditemukan (macro terdeteksi).")
            for name in (n for n in namelist if "vbaproject.bin" in n.lower()):
                try:
                    text = zf.read(name).decode("latin-1", errors="ignore").lower()
                    suspicious_kw = [kw for kw in self.SUSPICIOUS_MACRO_KW if kw.lower() in text]
                    if suspicious_kw:
                        suspicious.append(f"Macro mengandung keyword mencurigakan: {', '.join(sorted(set(suspicious_kw)))}")
                    break
                except:
                    pass
        self.result["macro_info"] = {"has_macro": has_macro, "suspicious_keywords": suspicious_kw}
        return has_macro, suspicious_kw, suspicious
    
    def _analyze_embedded_files(self, namelist: List[str]) -> tuple:
        embedded = [n for n in namelist if any(x in n.lower() for x in ["embeddings/", "object", "vbaproject.bin"])]
        suspicious = [f"Embedded file berisiko tinggi: {e}" for e in embedded if any(e.lower().endswith(ext) for ext in self.SUSPICIOUS_EXT)]
        self.result["embedded_files"] = embedded
        return embedded, suspicious
    
    def _extract_metadata(self, zf: zipfile.ZipFile) -> Dict[str, str]:
        meta = {}
        try:
            with zf.open("docProps/core.xml") as f:
                root = ET.fromstring(f.read())
                ns = {
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    "dc": "http://purl.org/dc/elements/1.1/"
                }
                for tag in ["dc:title", "dc:creator", "cp:keywords", "dc:subject", "cp:lastModifiedBy"]:
                    elem = root.find(tag, ns)
                    if elem is not None and elem.text:
                        meta[tag.split(":")[-1]] = elem.text.strip()
        except:
            pass
        self.result["metadata"] = meta
        return meta
    
    def _analyze_external_links(self, zf: zipfile.ZipFile) -> List[str]:
        suspicious = []
        try:
            with zf.open("word/_rels/document.xml.rels") as f:
                root = ET.fromstring(f.read())
                for rel in root.findall(".//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                    if rel.get("TargetMode") == "External":
                        suspicious.append(f"External link terdeteksi: {rel.get('Target', '')}")
                        self.result["basic_info"]["has_external_links"] = True
                        break
        except:
            pass
        return suspicious
    
    def _detect_watermarks(self, zf: zipfile.ZipFile, namelist: List[str]):
        wm_found = []
        for name in (n for n in namelist if n.lower().startswith("word/header") and n.lower().endswith(".xml")):
            try:
                data = zf.read(name).upper()
                wm_found.extend([f"{w} di {name}" for w in self.WATERMARK_WORDS if w.encode() in data])
            except:
                pass
        self.result["watermark"] = {
            "candidates": wm_found,
            "note": "Deteksi watermark berdasarkan kata kunci di headerX.xml."
        }
    
    def _calculate_risk_score(self, has_macro: bool, suspicious_kw: List[str], embedded: List[str], ratio: float) -> tuple:
        score = sum([
            3 if has_macro else 0,
            3 if suspicious_kw else 0,
            3 if any(e.lower().endswith(tuple(self.SUSPICIOUS_EXT)) for e in embedded) else 0,
            2 if self.result["basic_info"].get("has_external_links") else 0,
            1 if ratio > 0.9 else 0,
            4 if self.result["polyglot"].get("has_trailing_data") else 0
        ])
        return score, "HIGH" if score >= 10 else "MEDIUM" if score >= 5 else "LOW"
    
    def analyze(self) -> Dict[str, Any]:
        suspicious = self._analyze_polyglot()
        with zipfile.ZipFile(self.path, "r") as zf:
            namelist = zf.namelist()
            ratio = self._analyze_compression(zf)
            has_macro, suspicious_kw, macro_susp = self._analyze_macros(zf, namelist)
            embedded, embed_susp = self._analyze_embedded_files(namelist)
            suspicious.extend(macro_susp + embed_susp)
            self.result["basic_info"] = {
                "extension": os.path.splitext(self.path)[1].lower(),
                "image_count": len([n for n in namelist if n.lower().startswith("word/media/")]),
                "embedded_count": len(embedded),
                "has_macro": has_macro
            }
            self._extract_metadata(zf)
            suspicious.extend(self._analyze_external_links(zf))
            self._detect_watermarks(zf, namelist)
        risk_score, risk_level = self._calculate_risk_score(has_macro, suspicious_kw, embedded, ratio)
        self.result["risk_flags"] = {"risk_score": risk_score, "risk_level": risk_level, "notes": suspicious}
        return self.result

class VBAExtractor:
    @staticmethod
    def extract(docx_path: str) -> str:
        try:
            vba = VBA_Parser(docx_path)
            if not vba.detect_vba_macros():
                return "Tidak ada macro VBA ditemukan."
            results = [f"===== {vba_filename} =====\n{vba_code}\n"
                      for (_, _, vba_filename, vba_code) in vba.extract_macros() if vba_code and vba_filename]
            return "\n".join(results) if results else "Macro ada tetapi tidak ada source code yang diekstrak."
        except Exception as e:
            return f"Error membaca VBA: {e}"

class EmbeddedObjectExtractor:
    @staticmethod
    def extract(path: str, output_dir: str) -> List[str]:
        outputs = []
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if any(x in name.lower() for x in ["embeddings/", "object", "vbaproject.bin"]):
                    out_path = os.path.join(output_dir, os.path.basename(name))
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, "wb") as f:
                        f.write(zf.read(name))
                    outputs.append(out_path)
        return outputs

def analyze_office(path: str) -> Dict[str, Any]:
    return DocumentAnalyzer(path).analyze()

def extract_vba_code(docx_path: str) -> str:
    return VBAExtractor.extract(docx_path)

def extract_embedded_objects(path: str, output_dir: str) -> List[str]:
    return EmbeddedObjectExtractor.extract(path, output_dir)
