from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class FrontendBrandAssetsTests(unittest.TestCase):
    def test_frontend_html_references_favicon_and_mark_assets(self) -> None:
        build_script = (ROOT / "frontend-react" / "build.cjs").read_text(encoding="utf-8")
        source_index = (ROOT / "frontend-react" / "index.html").read_text(encoding="utf-8")
        built_index_path = ROOT / "frontend-react" / "dist" / "index.html"
        login_html = (ROOT / "services" / "web" / "app" / "templates" / "login.html").read_text(encoding="utf-8")

        self.assertIn('/app/favicon.ico', build_script)
        self.assertIn('/app/favicon.svg', build_script)
        self.assertIn('/app/favicon.ico', source_index)
        self.assertIn('/app/favicon.svg', source_index)
        if built_index_path.exists():
            built_index = built_index_path.read_text(encoding="utf-8")
            self.assertIn('/app/favicon.ico', built_index)
            self.assertIn('/app/favicon.svg', built_index)
        self.assertIn('/favicon.ico', login_html)
        self.assertIn('/favicon.svg', login_html)

    def test_main_routes_expose_root_and_app_favicon_paths(self) -> None:
        main_py = (ROOT / "services" / "web" / "main.py").read_text(encoding="utf-8")

        self.assertIn("def _resolve_frontend_dist_dir()", main_py)
        self.assertIn('root.parent / "frontend-react" / "dist"', main_py)
        self.assertIn('root.parent.parent.parent / "frontend-react" / "dist"', main_py)
        self.assertIn('@app.api_route("/favicon.svg"', main_py)
        self.assertIn('@app.api_route("/favicon.ico"', main_py)
        self.assertIn('@app.api_route("/app/favicon.svg"', main_py)
        self.assertIn('@app.api_route("/app/favicon.ico"', main_py)
        self.assertIn('@app.api_route("/app/mark.svg"', main_py)
        self.assertIn('_frontend_static_file_response("favicon.ico"', main_py)

    def test_brand_assets_exist_in_source_and_optional_build_output(self) -> None:
        self.assertTrue((ROOT / "frontend-react" / "src" / "assets" / "brand" / "favicon.ico").exists())
        self.assertTrue((ROOT / "frontend-react" / "public" / "app" / "favicon.svg").exists())
        self.assertTrue((ROOT / "frontend-react" / "public" / "app" / "mark.svg").exists())
        dist_dir = ROOT / "frontend-react" / "dist"
        if dist_dir.exists():
            self.assertTrue((dist_dir / "favicon.ico").exists())
            self.assertTrue((dist_dir / "favicon.svg").exists())
            self.assertTrue((dist_dir / "mark.svg").exists())


if __name__ == "__main__":
    unittest.main()
