"""Read declarative project metadata without importing the application."""
import ast
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def project_metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
    if "version" not in project:
        tree = ast.parse((ROOT / "argus" / "__init__.py").read_text("utf-8"))
        for statement in tree.body:
            if isinstance(statement, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "__version__"
                    for target in statement.targets):
                project["version"] = ast.literal_eval(statement.value)
                break
        else:
            raise ValueError("argus.__version__ must be a literal assignment")
    return project
