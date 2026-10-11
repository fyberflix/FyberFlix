"""Download the two ONNX models and pin their SHA-256.

First run:  python scripts/fetch_models.py --init   (writes models/SHA256SUMS; commit it)
Later runs: python scripts/fetch_models.py          (fails if a file's hash changed)
Verify each model's LICENSE in https://github.com/opencv/opencv_zoo before commercial use.
"""
import hashlib
import sys
import urllib.request
from pathlib import Path

BASE = "https://github.com/opencv/opencv_zoo/raw/main/models"
FILES = {
    "face_detection_yunet_2023mar.onnx": f"{BASE}/face_detection_yunet/face_detection_yunet_2023mar.onnx",
    "face_recognition_sface_2021dec.onnx": f"{BASE}/face_recognition_sface/face_recognition_sface_2021dec.onnx",
}
root = Path(__file__).resolve().parent.parent / "models"
sums = root / "SHA256SUMS"
init = "--init" in sys.argv
pinned = {} if init or not sums.exists() else dict(l.split()[::-1] for l in sums.read_text().splitlines() if l.strip())
if not init and not pinned:
    sys.exit("models/SHA256SUMS missing: run once with --init and commit it")
root.mkdir(exist_ok=True)
out = []
for name, url in FILES.items():
    data = urllib.request.urlopen(url, timeout=120).read()
    h = hashlib.sha256(data).hexdigest()
    if not init and pinned.get(name) != h:
        sys.exit(f"HASH MISMATCH for {name}: {h}")
    (root / name).write_bytes(data)
    out.append(f"{h}  {name}")
    print("ok", name, h)
if init:
    sums.write_text("\n".join(out) + "\n")
