"""AST-based HTTP Route Mapper for Flask and FastAPI applications.

Maps source-level vulnerability sinks (e.g. cursor.execute at line 42)
to their enclosing HTTP route endpoint, HTTP methods, and input parameters.
"""

import ast
import re
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field


class RouteContext(BaseModel):
    """Context of an HTTP route enclosing a code sink."""
    file_path: str
    function_name: str
    endpoint: str = "/"
    methods: list[str] = Field(default_factory=lambda: ["GET"])
    start_line: int
    end_line: int
    param_names: list[str] = Field(default_factory=list)
    param_sources: dict[str, str] = Field(default_factory=dict)  # param -> 'args', 'form', 'json'


class RouteMapper:
    """Analyzes Python AST to discover HTTP route definitions."""

    def __init__(self, target_dir: Path | str):
        self.target_dir = Path(target_dir).resolve()
        self._routes_cache: dict[str, list[RouteContext]] = {}

    def scan_file(self, file_path: Path | str) -> list[RouteContext]:
        """Scan a single Python file for Flask/FastAPI route definitions."""
        path = Path(file_path)
        if not path.is_absolute():
            path = (self.target_dir / path).resolve()
        suffix = path.suffix.lower()
        if not path.is_file() or suffix not in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            return []

        rel_path = str(path)
        if rel_path in self._routes_cache:
            return self._routes_cache[rel_path]

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                routes = self._extract_js_routes(rel_path, content)
                self._routes_cache[rel_path] = routes
                return routes
            tree = ast.parse(content, filename=str(path))
        except Exception:
            return []

        routes: list[RouteContext] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route = self._extract_route(node, rel_path, content)
                if route:
                    routes.append(route)

        self._routes_cache[rel_path] = routes
        return routes

    def find_route_for_line(self, file_path: Path | str, line_number: int) -> Optional[RouteContext]:
        """Find the HTTP route enclosing a given line of code."""
        path = Path(file_path)
        if not path.is_absolute():
            path = (self.target_dir / path).resolve()
        routes = self.scan_file(path)
        for r in routes:
            if r.start_line <= line_number <= r.end_line:
                return r
        # If no strict range match, return first route in file if available as fallback
        if routes:
            return routes[0]
        return None

    def _extract_route(self, fn_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str, content: str) -> Optional[RouteContext]:
        """Check if function has a route decorator (@app.route, @app.get, etc.)."""
        endpoint = None
        methods = ["GET"]

        for dec in fn_node.decorator_list:
            # Match @app.route('/path', methods=['GET', 'POST'])
            if isinstance(dec, ast.Call):
                func = dec.func
                # e.g., app.route, bp.route, router.get, app.post
                dec_name = ""
                if isinstance(func, ast.Attribute):
                    dec_name = func.attr
                elif isinstance(func, ast.Name):
                    dec_name = func.id

                if dec_name in ("route", "get", "post", "put", "delete", "patch"):
                    # Extract path from first argument
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        endpoint = str(dec.args[0].value)

                    # Extract methods
                    if dec_name in ("get", "post", "put", "delete", "patch"):
                        methods = [dec_name.upper()]
                    else:
                        for kw in dec.keywords:
                            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                methods = [
                                    elt.value.upper()
                                    for elt in kw.value.elts
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                                ]

        if not endpoint:
            return None

        # Inspect parameter extraction inside the function
        param_names: list[str] = []
        param_sources: dict[str, str] = {}

        # Function argument parameters (e.g. def item(item_id))
        for arg in fn_node.args.args:
            if arg.arg not in ("self", "cls", "request"):
                param_names.append(arg.arg)
                param_sources[arg.arg] = "path"

        # Walk body looking for request.args.get('x'), request.form['y'], request.json['z']
        for sub in ast.walk(fn_node):
            if isinstance(sub, ast.Subscript):
                # e.g., request.args['key'] or request.form['key']
                if isinstance(sub.slice, ast.Constant) and isinstance(sub.slice.value, str):
                    key = sub.slice.value
                    if key not in param_names:
                        param_names.append(key)
                        param_sources[key] = "data"
            elif isinstance(sub, ast.Call):
                # e.g., request.args.get('key') or request.form.get('key')
                if isinstance(sub.func, ast.Attribute) and sub.func.attr == "get":
                    if sub.args and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                        key = sub.args[0].value
                        if key not in param_names:
                            param_names.append(key)
                            param_sources[key] = "param"

        # Determine end line
        end_line = getattr(fn_node, "end_lineno", fn_node.lineno + 20)

        return RouteContext(
            file_path=file_path,
            function_name=fn_node.name,
            endpoint=endpoint,
            methods=methods,
            start_line=fn_node.lineno,
            end_line=end_line,
            param_names=param_names,
            param_sources=param_sources,
        )

    def _extract_js_routes(self, file_path: str, content: str) -> list[RouteContext]:
        """Extract Express, Fastify, and Node.js route definitions via pattern matching."""
        routes: list[RouteContext] = []
        lines = content.splitlines()

        route_pattern = re.compile(
            r"""(?:app|router|server)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]""",
            re.IGNORECASE,
        )

        raw_routes: list[tuple[int, re.Match]] = []
        for line_idx, line in enumerate(lines, start=1):
            match = route_pattern.search(line)
            if match:
                raw_routes.append((line_idx, match))

        for idx, (line_idx, match) in enumerate(raw_routes):
            raw_method = match.group(1).upper()
            methods = ["GET", "POST"] if raw_method == "ALL" else [raw_method]
            endpoint = match.group(2)

            # End line is bounded by next route start, or file length
            if idx + 1 < len(raw_routes):
                end_line = max(line_idx, raw_routes[idx + 1][0] - 1)
            else:
                end_line = min(len(lines), line_idx + 50)

            block_content = "\n".join(lines[line_idx - 1 : end_line])

            param_names: list[str] = []
            param_sources: dict[str, str] = {}

            # Path parameters: /api/:id
            for path_param in re.findall(r":([a-zA-Z0-9_]+)", endpoint):
                if path_param not in param_names:
                    param_names.append(path_param)
                    param_sources[path_param] = "path"

            # Query parameters: req.query.foo or req.query['foo']
            for q in re.findall(r"req\.query(?:\.([a-zA-Z0-9_]+)|\[['\"]([a-zA-Z0-9_]+)['\"]\])", block_content):
                param = q[0] or q[1]
                if param and param not in param_names:
                    param_names.append(param)
                    param_sources[param] = "param"

            # Body parameters: req.body.foo or req.body['foo']
            for b in re.findall(r"req\.body(?:\.([a-zA-Z0-9_]+)|\[['\"]([a-zA-Z0-9_]+)['\"]\])", block_content):
                param = b[0] or b[1]
                if param and param not in param_names:
                    param_names.append(param)
                    param_sources[param] = "data"

            # Destructuring: const { cmd, target } = req.query / req.body
            for d in re.findall(r"const\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(query|body)", block_content):
                vars_str, source_type = d[0], "param" if d[1] == "query" else "data"
                for v in vars_str.split(","):
                    v_clean = v.strip().split(":")[0].strip()
                    if v_clean and v_clean not in param_names:
                        param_names.append(v_clean)
                        param_sources[v_clean] = source_type

            fn_name = f"{raw_method.lower()}_{endpoint.replace('/', '_').strip('_') or 'root'}"
            routes.append(
                RouteContext(
                    file_path=file_path,
                    function_name=fn_name,
                    endpoint=endpoint,
                    methods=methods,
                    start_line=line_idx,
                    end_line=end_line,
                    param_names=param_names,
                    param_sources=param_sources,
                )
            )

        return routes
