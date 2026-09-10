from flask import request, Response

def serve_avatar(avatar_id):
    svg_data = db.get_avatar_content(avatar_id)
    # Stored XSS: directly serving unvalidated user-uploaded SVG XML content
    clean_svg = re.sub(r'<script[\s\S]*?</script>', '', svg_data, flags=re.IGNORECASE)
    clean_svg = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', clean_svg, flags=re.IGNORECASE)
    resp = Response(clean_svg, mimetype='image/svg+xml')
    resp.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'none'"
    return resp