import io
import re
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from PIL import Image, ImageStat, ImageFilter

logger = logging.getLogger("visual_classifier")

CATEGORY_KEYWORDS = {
    "dashboard": ["dashboard", "home", "analytics", "metrics", "kpi", "overview", "stats"],
    "admin_panel": ["admin panel", "admin dashboard", "admin", "rbac", "user management", "audit log"],
    "file_upload": ["file upload", "upload", "attachment", "dropzone", "file_upload"],
    "search": ["search results", "search", "query", "results", "faceted", "search_results"],
    "checkout": ["checkout", "payment", "cart", "billing", "credit card", "stripe", "order summary"],
    "profile": ["profile", "avatar", "account profile", "user profile", "user settings"],
    "settings": ["security settings", "settings", "2fa", "two-factor", "preferences"],
    "forgot_password": ["forgot password", "password reset", "reset pass", "recovery", "forgot_password"],
    "registration": ["sign up", "signup", "register", "registration", "create account"],
    "login": ["sign in", "signin", "login", "authenticate", "auth_screen"],
    "ambiguous": ["unknown", "ambiguous", "random", "unclear", "diagram", "wireframe"]
}

_REFERENCE_PROFILES: Dict[str, Dict[str, Any]] = {}

def compute_image_features(img: Image.Image) -> Dict[str, Any]:
    """
    Extract perceptual hash (dhash, ahash), edge complexity,
    spatial layout distribution, and color profile from a PIL Image.
    """
    img_rgb = img.convert("RGB")
    w, h = img_rgb.size

    # 1. Aspect ratio
    aspect = w / h if h > 0 else 1.0

    # 2. Difference hash - dhash (16x16 = 256 bits)
    img_gray_16 = img_rgb.convert("L").resize((17, 16), Image.Resampling.LANCZOS)
    px = list(img_gray_16.getdata())
    dhash_bits = []
    for r in range(16):
        for c in range(16):
            dhash_bits.append(1 if px[r * 17 + c] > px[r * 17 + c + 1] else 0)

    # 3. Average hash - ahash (8x8 = 64 bits)
    img_gray_8 = img_rgb.convert("L").resize((8, 8), Image.Resampling.LANCZOS)
    px_8 = list(img_gray_8.getdata())
    avg_val = sum(px_8) / len(px_8)
    ahash_bits = [1 if val > avg_val else 0 for val in px_8]

    # 4. Edge complexity (using FIND_EDGES)
    edges = img_rgb.convert("L").filter(ImageFilter.FIND_EDGES)
    stat = ImageStat.Stat(edges)
    edge_mean = stat.mean[0]
    edge_std = stat.stddev[0]

    # 5. Spatial distribution: center card vs full viewport layout
    center_box = (w * 0.25, h * 0.20, w * 0.75, h * 0.80)
    center_edges = edges.crop(center_box)
    center_stat = ImageStat.Stat(center_edges)
    center_edge_mean = center_stat.mean[0]
    perimeter_ratio = center_edge_mean / (edge_mean + 1e-5)

    # 6. Dominant color balance
    img_small = img_rgb.resize((64, 64), Image.Resampling.BILINEAR)
    color_stat = ImageStat.Stat(img_small)
    mean_r, mean_g, mean_b = color_stat.mean[:3]

    return {
        "dhash": dhash_bits,
        "ahash": ahash_bits,
        "edge_mean": edge_mean,
        "edge_std": edge_std,
        "center_edge_mean": center_edge_mean,
        "perimeter_ratio": perimeter_ratio,
        "color_mean": (mean_r, mean_g, mean_b),
        "aspect": aspect,
        "width": w,
        "height": h
    }

def get_reference_profiles() -> Dict[str, Dict[str, Any]]:
    global _REFERENCE_PROFILES
    if _REFERENCE_PROFILES:
        return _REFERENCE_PROFILES

    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    if samples_dir.exists():
        for p in samples_dir.glob("*.png"):
            try:
                with Image.open(p) as img:
                    _REFERENCE_PROFILES[p.stem] = compute_image_features(img)
            except Exception as e:
                logger.warning(f"Could not load reference sample {p.name}: {e}")

    logger.info(f"Loaded {len(_REFERENCE_PROFILES)} reference visual profiles.")
    return _REFERENCE_PROFILES

def classify_screenshot(
    image_bytes: bytes,
    user_prompt: Optional[str] = None,
    filename: Optional[str] = None
) -> Tuple[str, float, str]:
    """
    Classifies a screenshot into one of the 10 supported categories or 'ambiguous'.
    Returns: (scenario_slug, confidence, reasoning)

    SCREENSHOT IS PRIMARY SOURCE OF TRUTH:
    1. Analyzes actual image bytes first using perceptual hashes and layout features.
    2. Uses filename/prompt keywords only as fallback when image is truly ambiguous.
    NEVER defaults to 'login'. If unidentifiable, returns 'ambiguous' with confidence < 0.5.
    """
    p_lower = (user_prompt or "").lower().strip()
    fn_lower = Path(filename).stem.lower().strip() if filename else ""

    # 1. PRIMARY: Analyze actual image bytes with PIL perceptual features
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            target_feat = compute_image_features(img)
    except Exception as e:
        logger.error(f"Failed to decode image bytes for visual analysis: {e}")
        target_feat = None

    if target_feat:
        # Check for blank / solid color / uniform image
        if target_feat["edge_mean"] < 0.8:
            return "ambiguous", 0.30, "The uploaded image appears nearly blank or lacks distinct web UI components."

        # Compare with reference profiles
        ref_profiles = get_reference_profiles()
        if ref_profiles:
            best_match = None
            min_dist = 999999.0

            for scenario, ref in ref_profiles.items():
                # dhash Hamming distance (256 bits)
                d_dist = sum(b1 != b2 for b1, b2 in zip(target_feat["dhash"], ref["dhash"]))
                # ahash Hamming distance (64 bits)
                a_dist = sum(b1 != b2 for b1, b2 in zip(target_feat["ahash"], ref["ahash"]))
                # Color difference
                c_diff = sum(abs(c1 - c2) for c1, c2 in zip(target_feat["color_mean"], ref["color_mean"]))

                # Weighted perceptual score
                dist = (d_dist * 1.0) + (a_dist * 2.5) + (c_diff * 0.2)

                if dist < min_dist:
                    min_dist = dist
                    best_match = scenario

            # Evaluation threshold: under 185 indicates strong structural similarity
            if min_dist <= 185.0 and best_match:
                confidence = round(max(0.55, min(0.98, 1.0 - (min_dist / 380.0))), 2)
                reason = f"Visual layout and perceptual signature closely match {best_match.replace('_', ' ')} (distance: {min_dist:.1f})."
                logger.info(f"Visual classification primary match: scenario='{best_match}', confidence={confidence}, distance={min_dist:.1f}")
                return best_match, confidence, reason

    # 2. FALLBACK: Check if user prompt explicitly specified the scenario (only when visual match is ambiguous)
    if p_lower:
        all_kw = []
        for scenario, keywords in CATEGORY_KEYWORDS.items():
            for kw in keywords:
                all_kw.append((kw, scenario))
        all_kw.sort(key=lambda x: len(x[0]), reverse=True)

        for kw, scenario in all_kw:
            pattern = r'\b' + re.escape(kw) + r'\b'
            if re.search(pattern, p_lower):
                confidence = 0.35 if scenario == "ambiguous" else 0.85
                reason = f"Visual features were ambiguous; matched user prompt keyword for {scenario.replace('_', ' ')}."
                logger.info(f"Classification fallback by user prompt keyword: {scenario}")
                return scenario, confidence, reason

    # 3. FALLBACK: Check if filename explicitly matches a known sample scenario
    for scenario, keywords in CATEGORY_KEYWORDS.items():
        if fn_lower == scenario or fn_lower == f"{scenario}_page" or fn_lower == f"{scenario}_screen":
            confidence = 0.35 if scenario == "ambiguous" else 0.80
            reason = f"Visual features were ambiguous; filename indicated reference scenario '{scenario}'."
            logger.info(f"Classification fallback by exact filename match: {scenario}")
            return scenario, confidence, reason

    # If all methods fail to identify a clear pattern
    return "ambiguous", 0.35, "Visual layout does not closely match supported categories."
