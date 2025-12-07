from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from inertia import (
    InertiaMiddleware,
    InertiaConfig,
    InertiaResponse,
    Dependency as InertiaDep,
)

app = FastAPI(title="Cross-Auth Docs", docs_url=None, redoc_url=None)

app.add_middleware(
    InertiaMiddleware,
    InertiaConfig(
        templates_dir=Path(__file__).parent / "templates",
        manifest_path=Path(__file__).parent / "static" / "build" / ".vite" / "manifest.json",
        environment="development",
        dev_url="http://localhost:5173",
        entrypoint="frontend/app.tsx",
        use_flash_messages=False,
    ),
)

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.get("/")
async def home(request: Request, inertia: InertiaDep) -> InertiaResponse:
    return inertia.render(
        "Home",
        {
            "title": "Cross-Auth",
            "tagline": "Python Authentication",
            "description": "Simple, secure authentication for Python web applications. Works with Django, Flask, and FastAPI.",
            "installCommand": "uv add cross-auth",
            "ctaText": "Get Started",
            "ctaHref": "/docs",
            "features": [
                {
                    "title": "Framework Agnostic",
                    "description": "Works seamlessly with Django, Flask, FastAPI, and other Python web frameworks.",
                },
                {
                    "title": "Secure by Default",
                    "description": "Built-in protection against common vulnerabilities. Secure session handling out of the box.",
                },
                {
                    "title": "Easy to Use",
                    "description": "Simple API that gets you up and running in minutes. No complex configuration required.",
                },
                {
                    "title": "Extensible",
                    "description": "Customizable authentication flows. Add your own providers and strategies.",
                },
            ],
            "githubUrl": "https://github.com/patrick91/cross-auth",
            "navLinks": [{"label": "Docs", "href": "/docs"}],
        },
        view_data={"page_title": "Cross-Auth - Python Authentication"},
    )
