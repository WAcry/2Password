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

draw.rounded_rectangle(box((6, 6, 250, 250)), radius=58 * scale, fill="#101b29")
draw.rounded_rectangle(box((7, 7, 249, 249)), radius=57 * scale, outline="#294250", width=2 * scale)
draw.arc(box((78, 42, 178, 146)), 180, 360, fill="#9ce9d0", width=15 * scale)
draw.rectangle(box((78, 92, 93, 129)), fill="#9ce9d0")
draw.rectangle(box((163, 92, 178, 129)), fill="#9ce9d0")
draw.rounded_rectangle(box((56, 106, 200, 218)), radius=27 * scale, fill="#62d9bc")
draw.ellipse(box((93, 139, 115, 161)), fill="#101b29")
draw.rounded_rectangle(box((99, 151, 109, 181)), radius=5 * scale, fill="#101b29")
draw.ellipse(box((141, 139, 163, 161)), fill="#101b29")
draw.rounded_rectangle(box((147, 151, 157, 181)), radius=5 * scale, fill="#101b29")
image = image.resize((256, 256), Image.Resampling.LANCZOS)
image.save(assets / "app.png")
image.save(assets / "app.ico", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
print("Created assets/app.png and assets/app.ico")
