from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / ".artifacts" / "storybook"
STORIES = {
    "overview-surface--command-surface": "overview-surface.png",
    "patterns-investigation--drawer-language": "investigation-patterns.png",
    "pages-identity-workspace--control-center": "identity-workspace.png",
}


async def main() -> int:
    parser = argparse.ArgumentParser(description="Capture Storybook visual baselines.")
    parser.add_argument("--base-url", required=True, help="Running Storybook base URL, for example http://127.0.0.1:6006")
    args = parser.parse_args()

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1600, "height": 1100})
        for story_id, filename in STORIES.items():
            await page.goto(f"{args.base_url.rstrip('/')}/iframe.html?id={story_id}&viewMode=story", wait_until="networkidle")
            await page.screenshot(path=str(ARTIFACT_DIR / filename), full_page=True)
        await browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
