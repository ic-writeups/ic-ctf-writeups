# reconstruct.py
import re
from pathlib import Path

src = Path("bin.bin")
out = Path("reconstructed.bin")
out_pdf = Path("reconstructed.pdf")

text = src.read_text(encoding='latin1')
byte_vals = []
for line in text.splitlines():
    if ':' in line:
        part = line.split(':',1)[1]   # tomar lo que viene DESPUÉS del ':'
    else:
        part = line
    groups = re.findall(r'\b[01]{8}\b', part)
    for g in groups:
        byte_vals.append(int(g, 2))

b = bytes(byte_vals)
out.write_bytes(b)
print("Wrote", out, len(b), "bytes")

# si empieza con %PDF- lo guardo también con extensión .pdf para abrirlo
if b.startswith(b'%PDF-'):
    out_pdf.write_bytes(b)
    print("Detected PDF header — wrote", out_pdf)
else:
    print("No PDF header detected.")
