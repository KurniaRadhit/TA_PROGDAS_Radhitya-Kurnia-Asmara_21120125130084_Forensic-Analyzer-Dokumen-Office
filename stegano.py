import zipfile
import hashlib
import json
import tempfile
import shutil
import os
from xml.sax.saxutils import escape, unescape

def build_payload_text(user_text: str, mode: str) -> str:
    mode = mode.upper()
    core = {
        "TEXT": user_text,
        "HASH": hashlib.sha256(user_text.encode("utf-8")).hexdigest(),
        "JSON": json.dumps({"mode": "JSON", "data": user_text}, ensure_ascii=False)
    }.get(mode)
    
    if core is None:
        raise ValueError("Mode tidak dikenali")
    
    return f"[MODE={mode}]::{core}"

def embed_stegano_office(input_path: str, output_path: str, user_text: str, mode="TEXT"):
    payload = escape(build_payload_text(user_text, mode))
    
    custom_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
 <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" name="HiddenStego">
   <vt:lpwstr>{payload}</vt:lpwstr>
 </property>
</Properties>
"""
    
    temp_dir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(input_path, 'r') as zin:
            zin.extractall(temp_dir)
        
        with open(os.path.join(temp_dir, "docProps/custom.xml"), "w", encoding="utf-8") as f:
            f.write(custom_xml)
        
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    p = os.path.join(root, file)
                    zout.write(p, os.path.relpath(p, temp_dir))
    finally:
        shutil.rmtree(temp_dir)

def extract_stegano_office(input_path: str):
    try:
        with zipfile.ZipFile(input_path, "r") as zf:
            if "docProps/custom.xml" not in zf.namelist():
                return None
            data = zf.read("docProps/custom.xml")
        
        from xml.etree import ElementTree as ET
        root = ET.fromstring(data)
        payload_elem = root.find(
            "{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}property/"
            "{http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes}lpwstr"
        )
        return unescape(payload_elem.text) if payload_elem is not None else None
    except:
        return None