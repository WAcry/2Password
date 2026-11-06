"""Regenerate the repository's vector-style Windows icon (Pillow, build-time only)."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parent.parent
assets = root / "assets"
assets.mkdir(exist_ok=True)
scale = 4
image = Image.new("RGBA", (256 * scale, 256 * scale))
draw = ImageDraw.Draw(image)

def box(values):
    return tuple(round(v * scale) for v in values)

ink, edge, paper, shackle = "#1e1c18", "#3b3832", "#f7f6f3", "#cdc9c1"
draw.rounded_rectangle(box((6, 6, 250, 250)), radius=58 * scale, fill=ink)
draw.rounded_rectangle(box((7, 7, 249, 249)), radius=57 * scale, outline=edge, width=2 * scale)
draw.arc(box((86, 44, 170, 128)), 180, 360, fill=shackle, width=15 * scale)
draw.rectangle(box((86, 86, 101, 124)), fill=shackle)
draw.rectangle(box((155, 86, 170, 124)), fill=shackle)
draw.rounded_rectangle(box((56, 106, 200, 216)), radius=27 * scale, fill=paper)
for x in (104, 152):
    draw.ellipse(box((x - 11, 139, x + 11, 161)), fill=ink)
    draw.rounded_rectangle(box((x - 5, 151, x + 5, 181)), radius=5 * scale, fill=ink)
image = image.resize((256, 256), Image.Resampling.LANCZOS)
image.save(assets / "app.png")
image.save(assets / "app.ico", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
print("Created assets/app.png and assets/app.ico")
