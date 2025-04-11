import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch

from aiohttp_mcp.utils import discover


@pytest.fixture
def test_project(tmp_path: Path) -> Path:
    """Create a test project structure with packages and modules."""
    # Create a valid package
    package1_dir = tmp_path / "package1"
    package1_dir.mkdir()
    (package1_dir / "__init__.py").write_text("# Package 1 init")
    (package1_dir / "module1.py").write_text("value = 'module1'")
    (package1_dir / "module2.py").write_text("value = 'module2'")

    # Create a subpackage
    subpackage_dir = package1_dir / "subpackage"
    subpackage_dir.mkdir()
    (subpackage_dir / "__init__.py").write_text("# Subpackage init")
    (subpackage_dir / "submodule.py").write_text("value = 'submodule'")

    # Create another valid package
    package2_dir = tmp_path / "package2"
    package2_dir.mkdir()
    (package2_dir / "__init__.py").write_text("# Package 2 init")
    (package2_dir / "module.py").write_text("value = 'package2_module'")

    # Create a directory that is not a package
    not_package_dir = tmp_path / "not_a_package"
    not_package_dir.mkdir()
    (not_package_dir / "file.py").write_text("value = 'not_a_package'")

    # Create a main script
    (tmp_path / "main.py").write_text("# Main script")

    return tmp_path


@pytest.fixture(autouse=True)
def clean_modules() -> Generator[None, None, None]:
    """Clean up imported modules after each test."""
    yield
    # Remove test modules from sys.modules after each test
    to_remove = [name for name in sys.modules if name.startswith(("package1", "package2"))]
    for name in to_remove:
        del sys.modules[name]


def test_find_project_packages(test_project: Path, monkeypatch: MonkeyPatch) -> None:
    """Test finding project packages using real files."""
    # Set up the environment to use our test project
    monkeypatch.setattr(sys, "argv", [str(test_project / "main.py")])

    # Find packages
    packages = discover._find_project_packages()

    # Verify only valid packages are found
    assert sorted(packages) == ["package1", "package2"]
    assert "not_a_package" not in packages


def test_import_package_modules(test_project: Path, monkeypatch: MonkeyPatch) -> None:
    """Test importing package modules using real files."""
    # Add test project to Python path so we can import from it
    monkeypatch.syspath_prepend(str(test_project))

    # Import package1 and its modules
    discover._import_package_modules("package1")

    # Verify modules were imported
    # Ignore mypy errors for dynamic imports
    import package1  # type: ignore[import-not-found]
    import package1.module1  # type: ignore[import-not-found]
    import package1.module2  # type: ignore[import-not-found]
    import package1.subpackage.submodule  # type: ignore[import-not-found]

    # We know these attributes exist because we created them
    pkg1_mod1: Any = package1.module1
    pkg1_mod2: Any = package1.module2
    pkg1_submod: Any = package1.subpackage.submodule

    assert pkg1_mod1.value == "module1"
    assert pkg1_mod2.value == "module2"
    assert pkg1_submod.value == "submodule"


def test_discover_modules_with_auto_discovery(test_project: Path, monkeypatch: MonkeyPatch) -> None:
    """Test automatic discovery and import of all packages."""
    # Set up the environment
    monkeypatch.setattr(sys, "argv", [str(test_project / "main.py")])
    monkeypatch.syspath_prepend(str(test_project))

    # Discover and import all packages
    discover.discover_modules()

    # We know these modules exist because we created them
    pkg1_mod1: Any = __import__("package1.module1").module1
    pkg1_mod2: Any = __import__("package1.module2").module2
    pkg1_submod: Any = __import__("package1.subpackage.submodule").subpackage.submodule
    pkg2_mod: Any = __import__("package2.module").module

    assert pkg1_mod1.value == "module1"
    assert pkg1_mod2.value == "module2"
    assert pkg1_submod.value == "submodule"
    assert pkg2_mod.value == "package2_module"


def test_discover_modules_with_specific_package(test_project: Path, monkeypatch: MonkeyPatch) -> None:
    """Test discovery and import of a specific package."""
    # Add test project to Python path
    monkeypatch.syspath_prepend(str(test_project))

    # Discover and import only package2
    discover.discover_modules(["package2"])

    # We know this module exists because we created it
    pkg2_mod: Any = __import__("package2.module").module
    assert pkg2_mod.value == "package2_module"

    # Verify package1's modules were not imported
    assert "package1.module1" not in sys.modules
    assert "package1.module2" not in sys.modules
    assert "package1.subpackage.submodule" not in sys.modules


def test_import_package_modules_with_invalid_package(test_project: Path, monkeypatch: MonkeyPatch) -> None:
    """Test importing a non-existent package."""
    # Add test project to Python path
    monkeypatch.syspath_prepend(str(test_project))

    # Try to import a non-existent package
    discover._import_package_modules("non_existent_package")

    # Verify no modules were imported
    assert "non_existent_package" not in sys.modules


def test_import_package_modules_with_invalid_module(test_project: Path, monkeypatch: MonkeyPatch) -> None:
    """Test importing a package with an invalid module."""
    # Add test project to Python path
    monkeypatch.syspath_prepend(str(test_project))

    # Create a package with an invalid module
    invalid_pkg_dir = test_project / "invalid_pkg"
    invalid_pkg_dir.mkdir()
    (invalid_pkg_dir / "__init__.py").write_text("# Invalid package init")
    (invalid_pkg_dir / "bad_module.py").write_text("raise ImportError('Test import error')")

    # Try to import the package with the invalid module
    discover._import_package_modules("invalid_pkg")

    # Verify the package was imported but not the invalid module
    assert "invalid_pkg" in sys.modules
    assert "invalid_pkg.bad_module" not in sys.modules
