import os
import zipfile
from typing import Dict, Any, List, Optional
from xml.etree import ElementTree as ET
from oletools.olevba import VBA_Parser
from identify import guess_extension, SIG_TABLE, calc_entropy

SUSPICIOUS_EXT = [".exe", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".jar", ".scr"]
WATERMARK_WORDS = ["WATERMARK", "CONFIDENTIAL", "DRAFT", "RAHASIA"]
SUSPICIOUS_MACRO_KW = ["CreateObject", "WScript.Shell", "Shell(", "powershell", "cmd.exe", 
                        "URLDownloadToFile", "DownloadString", "Run", "WriteAllBytes"]
ZIP_EOCD = b"PK\x05\x06"

def _safe_read_xml(zf: zipfile.ZipFile, name: str):
    try:
        with zf.open(name) as f:
            return f.read()
    except KeyError:
        return None

def _find_zip_footer_end(data: bytes) -> Optional[int]:
    idx = data.rfind(ZIP_EOCD)
    if idx == -1 or idx + 22 > len(data):
        return None
    comment_len = int.from_bytes(data[idx + 20: idx + 22], "little")
    end = idx + 22 + comment_len
    return end if end < len(data) else None

def analyze_office(path: str) -> Dict[str, Any]:
    result = {"path": path, "basic_info": {}, "metadata": {}, "compression": {}, 
              "watermark": {}, "embedded_files": [], "macro_info": {}, 
              "integrity": {}, "polyglot": {}, "risk_flags": []}
    
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".docx", ".docm", ".dotm", ".dotx"):
        raise ValueError("Hanya mendukung DOCX/DOCM/DOTM/DOTX (OOXML).")
    
    susp = []
    try:
        with open(path, "rb") as f:
            raw_data = f.read()
    except Exception as e:
        raw_data = b""
        susp.append(f"Gagal membaca raw binary file: {e}")
    
    file_size = len(raw_data)
    entropy = calc_entropy(raw_data) if raw_data else 0.0
    
    result["integrity"] = {
        "filesize_bytes": file_size,
        "entropy_bits_per_byte": round(entropy, 3),
        "note": "Entropy tinggi (~8) menunjukkan data sangat acak (encrypted/packed).",
    }
    
    if entropy > 7.5:
        susp.append("Entropy file sangat tinggi (indikasi packed/encrypted).")
    elif 0 < entropy < 3.5:
        susp.append("Entropy file sangat rendah (mostly text / pola repetitif).")

    footer_end = _find_zip_footer_end(raw_data) if raw_data else None
    polyglot_info = {"has_trailing_data": False}
    
    if footer_end and footer_end < file_size:
        trailing = raw_data[footer_end:]
        if len(trailing) > 32:
            guessed_ext = guess_extension(trailing)
            polyglot_info = {
                "has_trailing_data": True,
                "payload_size_bytes": len(trailing),
                "guessed_extension": guessed_ext,
            }
            susp.append(f"Polyglot terdeteksi: payload kedua setelah footer ZIP, terindikasi {guessed_ext}.")
    
    result["polyglot"] = polyglot_info

    with zipfile.ZipFile(path, "r") as zf:
        namelist = zf.namelist()
        total_uncompressed = sum(info.file_size for info in zf.infolist())
        total_compressed = sum(info.compress_size for info in zf.infolist())
        compression_ratio = 1 - (total_compressed / total_uncompressed) if total_uncompressed > 0 else 0.0
        
        result["compression"] = {
            "total_uncompressed_bytes": total_uncompressed,
            "total_compressed_bytes": total_compressed,
            "approx_compression_ratio": round(compression_ratio, 3),
        }
        has_macro = any("vbaproject.bin" in n.lower() for n in namelist)
        suspicious_kw = []
        
        if has_macro:
            susp.append("vbaProject.bin ditemukan (macro terdeteksi).")
            for name in namelist:
                if "vbaproject.bin" in name.lower():
                    try:
                        data = zf.read(name)
                        text = data.decode("latin-1", errors="ignore")
                        suspicious_kw = [kw for kw in SUSPICIOUS_MACRO_KW if kw.lower() in text.lower()]
                    except:
                        pass
                    break
        
        result["macro_info"] = {"has_macro": has_macro, "suspicious_keywords": suspicious_kw}
        
        if suspicious_kw:
            susp.append("Macro mengandung keyword mencurigakan: " + ", ".join(sorted(set(suspicious_kw))))
        embedded = [n for n in namelist if "embeddings/" in n.lower() or "object" in n.lower() or "vbaproject.bin" in n.lower()]
        
        for e in embedded:
            for ext_s in SUSPICIOUS_EXT:
                if e.lower().endswith(ext_s):
                    susp.append(f"Embedded file berisiko tinggi: {e} (ekstensi {ext_s})")
        
        image_count = len([n for n in namelist if n.lower().startswith("word/media/")])
        
        result["basic_info"] = {
            "extension": ext,
            "image_count": image_count,
            "embedded_count": len(embedded),
            "has_macro": has_macro,
        }
        result["embedded_files"] = embedded
        core_xml = _safe_read_xml(zf, "docProps/core.xml")
        meta = {}
        if core_xml:
            try:
                root = ET.fromstring(core_xml)
                ns = {
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    "dc": "http://purl.org/dc/elements/1.1/",
                }
                for tag in ["dc:title", "dc:creator", "cp:keywords", "dc:subject", "cp:lastModifiedBy"]:
                    elem = root.find(tag, ns)
                    if elem is not None and elem.text:
                        meta[tag] = elem.text
            except:
                pass
        result["metadata"] = meta
        rels_xml = _safe_read_xml(zf, "word/_rels/document.xml.rels")
        if rels_xml:
            try:
                root = ET.fromstring(rels_xml)
                for rel in root.findall(".//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                    if rel.attrib.get("TargetMode") == "External":
                        susp.append(f"External link terdeteksi: {rel.attrib.get('Target', '')}")
                        result["basic_info"]["has_external_links"] = True
                        break
            except:
                pass
        wm_found = []
        for name in namelist:
            if name.lower().startswith("word/header") and name.lower().endswith(".xml"):
                data = _safe_read_xml(zf, name)
                if data:
                    up = data.upper()
                    for w in WATERMARK_WORDS:
                        if w.encode("utf-8") in up:
                            wm_found.append(f"{w} di {name}")
        
        result["watermark"] = {
            "candidates": wm_found,
            "note": "Deteksi watermark berdasarkan kata kunci di headerX.xml.",
        }
    risk_score = 0
    risk_score += 3 if has_macro else 0
    risk_score += 3 if suspicious_kw else 0
    risk_score += 3 if any(e.lower().endswith(tuple(SUSPICIOUS_EXT)) for e in embedded) else 0
    risk_score += 2 if result["basic_info"].get("has_external_links") else 0
    risk_score += 1 if compression_ratio > 0.9 else 0
    risk_score += 2 if entropy > 7.5 else 0
    risk_score += 3 if polyglot_info.get("has_trailing_data") else 0
    
    risk_level = "HIGH" if risk_score >= 10 else "MEDIUM" if risk_score >= 5 else "LOW"
    
    result["risk_flags"] = {"risk_score": risk_score, "risk_level": risk_level, "notes": susp}
    
    return result

def extract_vba_code(docx_path: str) -> str:
    try:
        vba = VBA_Parser(docx_path)
        if not vba.detect_vba_macros():
            return "Tidak ada macro VBA ditemukan."
        results = [f"===== {vba_filename} =====\n{vba_code}\n" 
                   for (_, _, vba_filename, vba_code) in vba.extract_macros() if vba_code and vba_filename]
        return "\n".join(results) if results else "Macro ada tetapi tidak ada source code yang diekstrak."
    except Exception as e:
        return f"Error membaca VBA: {e}"

def extract_embedded_objects(path: str, output_dir: str) -> List[str]:
    outputs = []
    with zipfile.ZipFile(path, "r") as zf:
        for name in zf.namelist():
            lower = name.lower()
            if "embeddings/" in lower or "object" in lower or "vbaproject.bin" in lower:
                data = zf.read(name)
                base_name = os.path.basename(name)
                root, ext = os.path.splitext(base_name)
                if not ext or ext.lower() in (".bin", ".dat"):
                    ext = guess_extension(data)
                    base_name = root + ext
                out_path = os.path.join(output_dir, base_name)
                with open(out_path, "wb") as f:
                    f.write(data)
                outputs.append(out_path)
    return outputs

def extract_hidden_after_footer(path: str, output_dir: str) -> List[str]:
    with open(path, "rb") as f:
        data = f.read()
    footer_end = _find_zip_footer_end(data)
    if not footer_end or footer_end >= len(data):
        return []
    payload = data[footer_end:]
    if len(payload) < 16:
        return []
    guessed_ext = guess_extension(payload)
    base = os.path.splitext(os.path.basename(path))[0]
    out_path = os.path.join(output_dir, f"{base}_after_footer{guessed_ext}")
    with open(out_path, "wb") as out:
        out.write(payload)
    return [out_path]

def carve_from_raw(path: str, output_dir: str) -> List[str]:
    with open(path, "rb") as f:
        data = f.read()
    
    hits = []
    for sig, ext in SIG_TABLE.items():
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            hits.append((idx, ext))
            start = idx + 1
    
    if not hits:
        return []
    
    hits.sort()
    base = os.path.splitext(os.path.basename(path))[0]
    outputs = []
    
    for i, (start, ext) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(data)
        if end - start < 32:
            continue
        chunk = data[start:end]
        out_path = os.path.join(output_dir, f"{base}_carved_{i}{ext}")
        with open(out_path, "wb") as f:
            f.write(chunk)
        outputs.append(out_path)
    
    return outputs