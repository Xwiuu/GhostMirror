"""GhostMirror Vuln Demo — safe indicator endpoints for scanner validation.

WARNING: This application does NOT contain real vulnerabilities.
Its purpose is to validate scanner detection logic using safe indicators.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(
    title="GhostMirror Vuln Demo",
    version="1.0.0",
    description="Safe controlled environment for GhostMirror scanner validation.",
)

PORT = int(os.environ.get("PORT", "8000"))

HTML_WRAPPER = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>{title}</title></head>
<body>
<h1>{heading}</h1>
{content}
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_WRAPPER.format(
        title="GhostMirror Vuln Demo",
        heading="GhostMirror Vuln Demo",
        content="<p>Welcome to the GhostMirror lab environment.</p>"
        "<p>This is a safe, controlled demo with no real vulnerabilities.</p>"
        '<p><a href="/admin">/admin</a> | <a href="/login">/login</a> | '
        '<a href="/search?q=demo">/search</a> | <a href="/redirect?url=/">/redirect</a> | '
        '<a href="/debug">/debug</a> | <a href="/form">/form</a></p>',
    )


@app.get("/admin", response_class=HTMLResponse)
async def admin():
    return HTML_WRAPPER.format(
        title="Admin Panel",
        heading="Admin Panel",
        content="<p>This is a fake admin panel indicator.</p>"
        "<p>No real admin functionality exists.</p>"
        "<p>Login disabled for security.</p>",
    )


@app.get("/login", response_class=HTMLResponse)
async def login():
    return HTML_WRAPPER.format(
        title="Login",
        heading="Login",
        content='<form method="POST" action="/login">'
        '<label>Username: <input type="text" name="username"></label><br>'
        '<label>Password: <input type="password" name="password"></label><br>'
        '<button type="submit">Login</button></form>',
    )


@app.post("/login", response_class=HTMLResponse)
async def login_post():
    return HTML_WRAPPER.format(
        title="Login",
        heading="Login",
        content="<p>Login disabled. This is a safe indicator only.</p>",
    )


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = Query("", description="Search query")):
    reflected = f"<p>You searched for: <b>{q}</b></p>" if q else ""
    return HTML_WRAPPER.format(
        title="Search",
        heading="Search",
        content=f"<p>Search endpoint for reflection testing.</p>{reflected}",
    )


@app.get("/redirect")
async def redirect(url: str = Query("/", description="Redirect URL")):
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=url)


@app.get("/debug", response_class=PlainTextResponse)
async def debug():
    import platform
    import sys

    lines = [
        "=== DEBUG INFO ===",
        f"Python: {sys.version}",
        f"Platform: {platform.platform()}",
        f"Hostname: {platform.node()}",
        "This is a safe debug endpoint. No sensitive data exposed.",
    ]
    return "\n".join(lines)


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /debug\n"


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap():
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>http://localhost:8000/</loc></url>\n  <url><loc>http://localhost:8000/admin</loc></url>\n  <url><loc>http://localhost:8000/login</loc></url>\n</urlset>'


@app.get("/security.txt", response_class=PlainTextResponse)
async def security():
    return "Contact: mailto:security@ghostmirror.local\nExpires: 2027-12-31T23:59:59.000Z\n"


@app.get("/form", response_class=HTMLResponse)
async def form():
    return HTML_WRAPPER.format(
        title="Contact Form",
        heading="Contact Form",
        content='<form method="POST" action="/form">'
        '<label>Name: <input type="text" name="name"></label><br>'
        '<label>Email: <input type="email" name="email"></label><br>'
        '<label>Message: <textarea name="message"></textarea></label><br>'
        '<button type="submit">Send</button></form>',
    )


@app.post("/form", response_class=HTMLResponse)
async def form_post():
    return HTML_WRAPPER.format(
        title="Form Submitted",
        heading="Form Submitted",
        content="<p>Thank you. This is a safe form indicator.</p>",
    )
