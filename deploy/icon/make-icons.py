#!/usr/bin/env python3
"""Все значки masquevpn из одного исходника — deploy/icon/source.png.

    python3 deploy/icon/make-icons.py        # из корня репозитория, нужен Pillow

Исходник — скруглённый квадрат с черепахой внутри внешней рамки. Отсюда:

  - «плитка» — квадрат без рамки, со своими прозрачными скруглёнными углами:
    значок программы на всех системах и логотип в шапке окна;
  - «плотная плитка» — то же, но черепаха крупнее (обрезка по её контуру):
    для 16–32 пикселей, где полная плитка превращается в зелёное пятно;
  - передний план адаптивного значка Android — черепаха на ровном фоне,
    уменьшенная так, чтобы целиком попасть в безопасную зону 66 dp;
  - значок Android для строки состояния — белый силуэт черепахи.

После запуска для Windows нужно ещё пересобрать ресурсы exe:
    cd cmd/masquevpn-win && go-winres make --arch amd64 --in winres/winres.json
"""
import os
from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "deploy", "icon", "source.png")

# Геометрия исходника (1254 px): рамка — 41 px по краям, радиус скругления
# внутреннего квадрата — 239 px. Режем на 3 px внутрь рамки, а радиус берём
# на те же 3 px меньше с тем же центром: так светлая кайма рамки не
# попадает на край плитки.
EDGE, RADIUS = 44, 236
# Контур черепахи внутри квадрата (в координатах 1024 px): для плотной
# обрезки. Квадрат 940 px с центром на черепахе, целиком внутри плитки.
TIGHT = (50, 22, 990, 962)
# Доля скругления у плотной плитки — как у полной.
TIGHT_RADIUS = 0.2
# Ширина черепахи в квадрате 1024 px и сколько dp из 108 она займёт в
# адаптивном значке: безопасная зона — 66 dp, берём с запасом.
TURTLE_W, ADAPTIVE_DP = 864, 52
# Значок в строке состояния: порог отличия от фона и сколько dp из 24
# занимает черепаха (Android советует поле в 1 dp с каждой стороны).
STATUS_THRESHOLD, STATUS_DP = 40, 22


def rounded(img, radius_frac):
    n, s = img.width, 4
    mask = Image.new("L", (n * s, n * s), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, n * s - 1, n * s - 1),
                                           radius=int(radius_frac * n * s), fill=255)
    out = img.convert("RGBA")
    out.putalpha(mask.resize((n, n), Image.LANCZOS))
    return out


def save(img, *parts, size=None):
    path = os.path.join(ROOT, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if size:
        img = img.resize((size, size), Image.LANCZOS)
    img.save(path, optimize=True)
    return path


src = Image.open(SRC).convert("RGB")
square = src.crop((EDGE, EDGE, src.width - EDGE, src.height - EDGE)).resize((1024, 1024), Image.LANCZOS)
full = rounded(square, RADIUS / (src.width - 2 * EDGE))
tight = rounded(square.crop(TIGHT).resize((1024, 1024), Image.LANCZOS), TIGHT_RADIUS)
bg = square.getpixel((512, 6))  # ровный фон плитки у края


def pick(size):
    return tight if size <= 32 else full


# --- общий логотип: шапка окна (Windows, Linux) и значок в трее ---
save(full, "internal", "gui", "logo", "logo-256.png", size=256)
save(tight, "internal", "gui", "logo", "logo-small-64.png", size=64)

# --- Windows: ресурсы exe и значок установщика ---
for s in (16, 24, 32, 48, 64, 128, 256):
    save(pick(s), "cmd", "masquevpn-win", "winres", f"icon-{s}.png", size=s)
ico_sizes = [16, 24, 32, 48, 64, 128, 256]
ico = [pick(s).resize((s, s), Image.LANCZOS) for s in ico_sizes]
ico[-1].save(os.path.join(ROOT, "deploy", "windows", "masquevpn.ico"),
             sizes=[(s, s) for s in ico_sizes], append_images=ico[:-1])

# --- Linux: значки hicolor ---
for s in (48, 64, 128, 256):
    save(pick(s), "deploy", "linux", "icons", f"masquevpn-{s}.png", size=s)

# --- Android ---
res = ("mobile", "android", "app", "src", "main", "res")
dens = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}
for d, k in dens.items():
    # Старый значок (Android 7): плитка целиком.
    save(full, *res, f"mipmap-{d}", "ic_launcher.png", size=int(48 * k))
    # Адаптивный (Android 8+): передний план 108 dp. Черепаха — на ровном
    # фоне цвета плитки; система сама обрежет круг, скругление или квадрат.
    n = int(108 * k)
    canvas = Image.new("RGBA", (n, n), bg + (255,))
    tile = round(ADAPTIVE_DP * k * 1024 / TURTLE_W)
    t = square.resize((tile, tile), Image.LANCZOS).convert("RGBA")
    canvas.alpha_composite(t, ((n - tile) // 2, (n - tile) // 2))
    save(canvas, *res, f"mipmap-{d}", "ic_launcher_foreground.png")
# Логотип в шапке главного экрана.
save(full, *res, "drawable-nodpi", "logo.png", size=192)


# Значок в строке состояния. Система берёт у него только альфу и красит
# сама, так что нужен одноцветный рисунок: черепаха — всё, что заметно
# отличается от фона плитки; её тёмные контуры почти цвета фона и потому
# остаются прорезями — панцирь, глаза и улыбка видны и в белом.
def status_glyph():
    diff = ImageChops.difference(square, Image.new("RGB", square.size, bg)).convert("L")
    mask = diff.point(lambda v: 255 if v > STATUS_THRESHOLD else 0)
    # Медиана убирает одиночные крапинки на краях контуров: в 24 dp они
    # превратились бы в грязь.
    mask = mask.filter(ImageFilter.MedianFilter(9))
    x0, y0, x1, y1 = mask.getbbox()
    side = int(max(x1 - x0, y1 - y0) * (24 / STATUS_DP))
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    box = (cx - side // 2, cy - side // 2, cx - side // 2 + side, cy - side // 2 + side)
    out = Image.new("L", (side, side), 0)
    out.paste(mask.crop(box), (0, 0))
    return out


glyph = status_glyph()
for d, k in dens.items():
    n = int(24 * k)
    a = glyph.resize((n, n), Image.LANCZOS)
    white = Image.new("RGBA", (n, n), (255, 255, 255, 0))
    white.putalpha(a)
    save(white, *res, f"drawable-{d}", "ic_stat_masque.png")

with open(os.path.join(ROOT, *res, "values", "logo.xml"), "w") as f:
    f.write('<?xml version="1.0" encoding="utf-8"?>\n'
            "<!-- СГЕНЕРИРОВАНО deploy/icon/make-icons.py: фон значка — цвет плитки. -->\n"
            "<resources>\n"
            f'    <color name="logo_bg">#{bg[0]:02X}{bg[1]:02X}{bg[2]:02X}</color>\n'
            "</resources>\n")

print("готово; фон плитки #%02X%02X%02X" % bg)
