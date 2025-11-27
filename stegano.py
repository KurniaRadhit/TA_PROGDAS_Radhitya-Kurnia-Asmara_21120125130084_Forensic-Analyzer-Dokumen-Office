import zipfile
import hashlib
import json
import tempfile
import shutil
import os
from xml.sax.saxutils import escape, unescape
from xml.etree import ElementTree as ET

class PayloadBuilder:
    MODE_HANDLERS = {
        "TEXT": lambda text: text,
        "HASH": lambda text: hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "JSON": lambda text: json.dumps({"mode": "JSON", "data": text}, ensure_ascii=False)
    }
    
    @classmethod
    def build(cls, user_text: str, mode: str) -> str:
        handler = cls.MODE_HANDLERS.get(mode.upper())
        if not handler:
            raise ValueError("Mode tidak dikenali")
        return f"[MODE={mode.upper()}]::{handler(user_text)}"

class SteganographyOffice:
    CUSTOM_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
 <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" name="HiddenStego">
   <vt:lpwstr>{payload}</vt:lpwstr>
 </property>
</Properties>
"""
    
    @classmethod
    def embed(cls, input_path: str, output_path: str, user_text: str, mode="TEXT"):
        payload = escape(PayloadBuilder.build(user_text, mode))
        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(input_path, 'r') as zin:
                zin.extractall(temp_dir)
            with open(os.path.join(temp_dir, "docProps/custom.xml"), "w", encoding="utf-8") as f:
                f.write(cls.CUSTOM_XML_TEMPLATE.format(payload=payload))
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        p = os.path.join(root, file)
                        zout.write(p, os.path.relpath(p, temp_dir))
        finally:
            shutil.rmtree(temp_dir)
    
    @classmethod
    def extract(cls, input_path: str):
        try:
            with zipfile.ZipFile(input_path, "r") as zf:
                if "docProps/custom.xml" not in zf.namelist():
                    return None
                root = ET.fromstring(zf.read("docProps/custom.xml"))
            payload_elem = root.find(
                "{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}property/"
                "{http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes}lpwstr"
            )
            return unescape(payload_elem.text) if payload_elem is not None else None
        except:
            return None

def build_payload_text(user_text: str, mode: str) -> str:
    return PayloadBuilder.build(user_text, mode)

def embed_stegano_office(input_path: str, output_path: str, user_text: str, mode="TEXT"):
    SteganographyOffice.embed(input_path, output_path, user_text, mode)

def extract_stegano_office(input_path: str):
    return SteganographyOffice.extract(input_path)
