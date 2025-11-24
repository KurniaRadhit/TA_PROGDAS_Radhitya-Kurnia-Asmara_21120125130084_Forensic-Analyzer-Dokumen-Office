import math
from collections import Counter

SIG_TABLE = {
    b"\x50\x4B\x03\x04": ".zip",
    b"\x1F\x8B": ".gz",
    b"\x42\x5A\x68": ".bz2",
    b"\x4D\x5A": ".exe",
    b"\x89PNG\r\n\x1A\n": ".png",
    b"\xFF\xD8\xFF": ".jpg",
    b"%PDF": ".pdf",
}

def guess_extension(data: bytes) -> str:
    if not data:
        return ".bin"

    for sig, ext in SIG_TABLE.items():
        if data.startswith(sig):
            return ext

    sample = data[:512]
    try:
        text = sample.decode("utf-8", errors="ignore").strip().lower()
    except:
        return ".bin"
    
    if any(x in text for x in ["function ", "var ", "let ", "const ", "console.log", "document.getelementbyid"]):
        return ".js"
    if "powershell" in text or "-encodedcommand" in text:
        return ".ps1"
    if text.startswith("@echo") or ".bat" in text:
        return ".bat"

    if all(32 <= b <= 126 or b in (9, 10, 13) for b in sample):
        return ".txt"
    
    return ".bin"

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())