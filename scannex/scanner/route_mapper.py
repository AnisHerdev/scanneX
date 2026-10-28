"""AST and regex-based HTTP Route Mapper for Flask, FastAPI, and PHP applications.

Maps source-level vulnerability sinks (e.g. cursor.execute or system())
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
    param_sources: dict[str, str] = Field(default_factory=dict)  # param -> 'args', 'form', 'json', 'param', 'data'


class RouteMapper:
    """Analyzes Python AST and PHP sources to discover HTTP route definitions."""

    def __init__(self, target_dir: Path | str):
        self.target_dir = Path(target_dir).resolve()
        self._routes_cache: dict[str, list[RouteContext]] = {}

    def _resolve_file_path(self, file_path: Path | str) -> Optional[Path]:
        """Resolve file path across various formats (absolute, relative to cwd, relative to target_dir)."""
        p = Path(file_path)
        if p.is_file():
            return p.resolve()

        cand = (self.target_dir / p).resolve()
        if cand.is_file():
            return cand

        try:
            rel = p.relative_to(self.target_dir.name)
            cand = (self.target_dir / rel).resolve()
            if cand.is_file():
                return cand
        except Exception:
            pass

        by_name = (self.target_dir / p.name).resolve()
        if by_name.is_file():
            return by_name

        return None

    def scan_file(self, file_path: Path | str) -> list[RouteContext]:
        """Scan a single Python or PHP file for route definitions."""
        path = self._resolve_file_path(file_path)
        if not path or not path.is_file():
            return []

        rel_path = str(path)
        if rel_path in self._routes_cache:
            return self._routes_cache[rel_path]

        routes: list[RouteContext] = []
        if path.suffix == ".py":
            routes = self._scan_python_file(path, rel_path)
        elif path.suffix in (".php", ".phtml", ".php5", ".php7", ".php8"):
            routes = self._scan_php_file(path, rel_path)

        self._routes_cache[rel_path] = routes
        return routes

    def find_route_for_line(self, file_path: Path | str, line_number: int) -> Optional[RouteContext]:
        """Find the HTTP route enclosing a given line of code."""
        routes = self.scan_file(file_path)
        for r in routes:
            if r.start_line <= line_number <= r.end_line:
                return r
        # If no strict range match, return first route in file if available as fallback
        if routes:
            return routes[0]
        return None

    def _scan_python_file(self, path: Path, rel_path: str) -> list[RouteContext]:
        """Scan a Python file for Flask/FastAPI route definitions."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content, filename=str(path))
        except Exception:
            return []

        routes: list[RouteContext] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route = self._extract_python_route(node, rel_path, content)
                if route:
                    routes.append(route)
        return routes

    def _scan_php_file(self, path: Path, file_path_str: str) -> list[RouteContext]:
        """Discover PHP route endpoints and input parameters from superglobals and routing frameworks."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()
        total_lines = max(1, len(lines))

        # 1. Determine HTTP endpoint from file location relative to target root
        try:
            rel_p = path.relative_to(self.target_dir).as_posix()
        except ValueError:
            rel_p = path.name

        # Strip standard web document root directories if present
        clean_p = rel_p
        for prefix in ("public/", "www/", "htdocs/", "html/", "web/"):
            if clean_p.lower().startswith(prefix):
                clean_p = clean_p[len(prefix):]
                break

        if clean_p.lower() in ("index.php", "index.html", "index.phtml"):
            endpoint = "/"
        else:
            endpoint = "/" + clean_p.lstrip("/")

        # 2. Extract superglobals and parameters
        param_names: list[str] = []
        param_sources: dict[str, str] = {}
        methods: set[str] = set()

        # Match $_GET['param'] or $_GET["param"]
        for match in re.finditer(r"\$_GET\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", content):
            p_name = match.group(1).strip()
            if p_name and p_name not in param_names:
                param_names.append(p_name)
                param_sources[p_name] = "param"
                methods.add("GET")

        # Match $_POST['param'] or $_POST["param"]
        for match in re.finditer(r"\$_POST\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", content):
            p_name = match.group(1).strip()
            if p_name and p_name not in param_names:
                param_names.append(p_name)
                param_sources[p_name] = "data"
                methods.add("POST")

        # Match $_REQUEST['param'] or $_REQUEST["param"]
        for match in re.finditer(r"\$_REQUEST\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", content):
            p_name = match.group(1).strip()
            if p_name and p_name not in param_names:
                param_names.append(p_name)
                param_sources[p_name] = "param"
                methods.add("GET")
                methods.add("POST")

        # Match framework calls: $request->get('param'), $request->input('param'), etc.
        for match in re.finditer(r"\$request\s*->\s*(?:get|input|query|post)\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content, re.IGNORECASE):
            p_name = match.group(1).strip()
            if p_name and p_name not in param_names:
                param_names.append(p_name)
                param_sources[p_name] = "param"
                methods.add("GET")

        # Determine method list
        method_list = sorted(list(methods)) if methods else ["GET"]

        # Default fallback parameter if none found
        if not param_names:
            param_names = ["input"]
            param_sources["input"] = "param"

        routes: list[RouteContext] = []

        # File-level route context covering the entire PHP script
        file_route = RouteContext(
            file_path=file_path_str,
            function_name=path.stem,
            endpoint=endpoint,
            methods=method_list,
            start_line=1,
            end_line=total_lines,
            param_names=param_names,
            param_sources=param_sources,
        )
        routes.append(file_route)

        # 3. Check for framework routing definitions (Laravel, Symfony, Slim)
        # e.g., Route::get('/api/users', ...) or $app->post('/login', ...)
        route_pattern = re.compile(
            r"(?:Route|\$app|\$router)\s*::\s*(get|post|put|delete|patch|any)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )
        for match in route_pattern.finditer(content):
            http_method = match.group(1).upper()
            framework_endpoint = match.group(2)
            if not framework_endpoint.startswith("/"):
                framework_endpoint = "/" + framework_endpoint

            line_idx = content[:match.start()].count("\n") + 1
            routes.append(
                RouteContext(
                    file_path=file_path_str,
                    function_name=f"route_{http_method.lower()}",
                    endpoint=framework_endpoint,
                    methods=[http_method] if http_method != "ANY" else ["GET", "POST"],
                    start_line=line_idx,
                    end_line=min(total_lines, line_idx + 30),
                    param_names=param_names,
                    param_sources=param_sources,
                )
            )

        return routes

    def _extract_python_route(self, fn_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str, content: str) -> Optional[RouteContext]:
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
