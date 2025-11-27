import math
from collections import Counter

class FileSignatureAnalyzer:
    SIGNATURE_TABLE = {
        b"\x50\x4B\x03\x04": ".zip", b"\x1F\x8B": ".gz", b"\x42\x5A\x68": ".bz2",
        b"\x4D\x5A": ".exe", b"\x89PNG\r\n\x1A\n": ".png", b"\xFF\xD8\xFF": ".jpg",
        b"%PDF": ".pdf"
    }
    SCRIPT_INDICATORS = {
        ".js": ["function ", "var ", "let ", "const ", "console.log", "document.getelementbyid"],
        ".ps1": ["powershell", "-encodedcommand"],
        ".bat": ["@echo", ".bat"]
    }
    
    @classmethod
    def guess_extension(cls, data: bytes) -> str:
        if not data:
            return ".bin"
        return (cls._check_signatures(data) or cls._check_content(data) or 
                (".txt" if cls._is_printable_text(data[:512]) else ".bin"))
    
    @classmethod
    def _check_signatures(cls, data: bytes) -> str | None:
        return next((ext for sig, ext in cls.SIGNATURE_TABLE.items() if data.startswith(sig)), None)

    @classmethod
    def _check_content(cls, data: bytes) -> str | None:
        try:
            text = data[:512].decode("utf-8", errors="ignore").strip().lower()
            return next((ext for ext, indicators in cls.SCRIPT_INDICATORS.items() 
                        if any(ind in text for ind in indicators)), None)
        except:
            return None
    
    @staticmethod
    def _is_printable_text(sample: bytes) -> bool:
        return all(32 <= b <= 126 or b in (9, 10, 13) for b in sample)

class EntropyCalculator:
    @staticmethod
    def calculate(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

def guess_extension(data: bytes) -> str:
    return FileSignatureAnalyzer.guess_extension(data)

def calc_entropy(data: bytes) -> float:
    return EntropyCalculator.calculate(data)
