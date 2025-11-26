import os
import zipfile
from typing import Dict, Any, List
from xml.etree import ElementTree as ET
from oletools.olevba import VBA_Parser
from identify import guess_extension

SUSPICIOUS_EXT = [".exe", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".jar", ".scr"]
WATERMARK_WORDS = ["WATERMARK", "CONFIDENTIAL", "DRAFT", "RAHASIA"]
SUSPICIOUS_MACRO_KW = [
    "CreateObject", "WScript.Shell", "Shell(", "powershell", "cmd.exe",
    "URLDownloadToFile", "DownloadString", "Run", "WriteAllBytes"
]
ZIP_EOCD = b"PK\x05\x06"

def _find_zip_footer_end(data: bytes) -> int | None:
    idx = data.rfind(ZIP_EOCD)
    if idx == -1:
        return None
    try:
        comment_len = int.from_bytes(data[idx + 20:idx + 22], "little")
        return idx + 22 + comment_len
    except Exception:
        return None

def _safe_read_xml(zf: zipfile.ZipFile, name: str):
    try:
        with zf.open(name) as f:
            return f.read()
    except KeyError:
        return None

def analyze_office(path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "path": path,
        "filesize_bytes": 0,
        "basic_info": {},
        "metadata": {},
        "compression": {},
        "watermark": {},
        "embedded_files": [],
        "macro_info": {},
        "polyglot": {"has_trailing_data": False},
        "risk_flags": []
    }

    try:
        result["filesize_bytes"] = os.path.getsize(path)
    except Exception:
        result["filesize_bytes"] = 0

    ext = os.path.splitext(path)[1].lower()
    if ext not in (".docx", ".docm", ".dotm", ".dotx"):
        raise ValueError("Hanya mendukung DOCX/DOCM/DOTM/DOTX (OOXML).")

    susp: List[str] = []
    try:
        with open(path, "rb") as f:
            raw_data = f.read()

        file_size = len(raw_data)
        footer_end = _find_zip_footer_end(raw_data)
        polyglot_info: Dict[str, Any] = {"has_trailing_data": False}

        if footer_end and footer_end < file_size:
            trailing = raw_data[footer_end:]
            if len(trailing) > 32:
                guessed_ext = guess_extension(trailing)

                polyglot_info = {
                    "has_trailing_data": True,
                    "trailing_bytes": len(trailing),
                    "guessed_extension": guessed_ext,
                    "note": (
                        f"Data tersembunyi ditemukan setelah footer ZIP "
                        f"(kemungkinan: {guessed_ext})"
                    ),
                }

                susp.append(
                    f"Polyglot terdeteksi: {len(trailing)} byte setelah footer ZIP "
                    f"→ kemungkinan file {guessed_ext}."
                )
            else:
                polyglot_info = {
                    "has_trailing_data": True,
                    "trailing_bytes": len(trailing),
                    "note": "Data setelah footer ZIP terlalu kecil untuk dianalisis.",
                }
        else:
            polyglot_info = {"has_trailing_data": False}

        result["polyglot"] = polyglot_info

    except Exception:
        result["polyglot"] = {"has_trailing_data": False}
    with zipfile.ZipFile(path, "r") as zf:
        namelist = zf.namelist()
        total_uncompressed = sum(info.file_size for info in zf.infolist())
        total_compressed = sum(info.compress_size for info in zf.infolist())
        ratio = (
            1 - (total_compressed / total_uncompressed)
            if total_uncompressed > 0
            else 0.0
        )

        result["compression"] = {
            "total_uncompressed_bytes": total_uncompressed,
            "total_compressed_bytes": total_compressed,
            "approx_compression_ratio": round(ratio, 3),
        }
        has_macro = any("vbaproject.bin" in n.lower() for n in namelist)
        suspicious_kw: List[str] = []

        if has_macro:
            susp.append("vbaProject.bin ditemukan (macro terdeteksi).")
            for name in namelist:
                if "vbaproject.bin" in name.lower():
                    try:
                        data = zf.read(name)
                        text = data.decode("latin-1", errors="ignore")
                        suspicious_kw = [
                            kw for kw in SUSPICIOUS_MACRO_KW
                            if kw.lower() in text.lower()
                        ]
                    except Exception:
                        pass
                    break

        result["macro_info"] = {
            "has_macro": has_macro,
            "suspicious_keywords": suspicious_kw,
        }
        if suspicious_kw:
            susp.append(
                "Macro mengandung keyword mencurigakan: "
                + ", ".join(sorted(set(suspicious_kw)))
            )
        embedded = [
            n for n in namelist
            if "embeddings/" in n.lower()
            or "object" in n.lower()
            or "vbaproject.bin" in n.lower()
        ]
        for e in embedded:
            for bad_ext in SUSPICIOUS_EXT:
                if e.lower().endswith(bad_ext):
                    susp.append(
                        f"Embedded file berisiko tinggi: {e} (ekstensi {bad_ext})"
                    )

        image_count = len(
            [n for n in namelist if n.lower().startswith("word/media/")]
        )

        result["basic_info"] = {
            "extension": ext,
            "image_count": image_count,
            "embedded_count": len(embedded),
            "has_macro": has_macro,
        }
        result["embedded_files"] = embedded
        core_xml = _safe_read_xml(zf, "docProps/core.xml")
        meta: Dict[str, Any] = {}
        if core_xml:
            try:
                root = ET.fromstring(core_xml)
                ns = {
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    "dc": "http://purl.org/dc/elements/1.1/",
                }
                for tag in [
                    "dc:title",
                    "dc:creator",
                    "cp:keywords",
                    "dc:subject",
                    "cp:lastModifiedBy",
                ]:
                    elem = root.find(tag, ns)
                    if elem is not None and elem.text:
                        meta[tag.split(":")[-1]] = elem.text.strip()
            except Exception:
                pass
        result["metadata"] = meta
        rels_xml = _safe_read_xml(zf, "word/_rels/document.xml.rels")
        if rels_xml:
            try:
                root = ET.fromstring(rels_xml)
                for rel in root.findall(
                    ".//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"
                ):
                    if rel.get("TargetMode") == "External":
                        target = rel.get("Target", "")
                        susp.append(f"External link terdeteksi: {target}")
                        result["basic_info"]["has_external_links"] = True
                        break
            except Exception:
                pass
        wm_found: List[str] = []
        for name in namelist:
            if name.lower().startswith("word/header") and name.lower().endswith(
                ".xml"
            ):
                data = _safe_read_xml(zf, name)
                if data:
                    up = data.upper()
                    for w in WATERMARK_WORDS:
                        if w.encode() in up:
                            wm_found.append(f"{w} di {name}")
        result["watermark"] = {
            "candidates": wm_found,
            "note": "Deteksi watermark berdasarkan kata kunci di headerX.xml.",
        }
    risk_score = 0
    risk_score += 3 if has_macro else 0
    risk_score += 3 if suspicious_kw else 0
    risk_score += 3 if any(
        e.lower().endswith(tuple(SUSPICIOUS_EXT)) for e in embedded
    ) else 0
    risk_score += 2 if result["basic_info"].get("has_external_links") else 0
    risk_score += 1 if ratio > 0.9 else 0
    risk_score += 4 if result["polyglot"].get("has_trailing_data") else 0

    risk_level = "HIGH" if risk_score >= 10 else "MEDIUM" if risk_score >= 5 else "LOW"

    result["risk_flags"] = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "notes": susp,
    }

    return result


def extract_vba_code(docx_path: str) -> str:
    try:
        vba = VBA_Parser(docx_path)
        if not vba.detect_vba_macros():
            return "Tidak ada macro VBA ditemukan."
        results = [
            f"===== {vba_filename} =====\n{vba_code}\n"
            for (_, _, vba_filename, vba_code) in vba.extract_macros()
            if vba_code and vba_filename
        ]
        return (
            "\n".join(results)
            if results
            else "Macro ada tetapi tidak ada source code yang diekstrak."
        )
    except Exception as e:
        return f"Error membaca VBA: {e}"


def extract_embedded_objects(path: str, output_dir: str) -> List[str]:
    outputs: List[str] = []
    with zipfile.ZipFile(path, "r") as zf:
        for name in zf.namelist():
            if any(
                x in name.lower()
                for x in ["embeddings/", "object", "vbaproject.bin"]
            ):
                data = zf.read(name)
                out_path = os.path.join(output_dir, os.path.basename(name))
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(data)
                outputs.append(out_path)
    return outputs
