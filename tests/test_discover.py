import sys
from pathlib import Path

import pytest

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
def clean_modules():
    """Clean up imported modules after each test."""
    yield
    # Remove test modules from sys.modules after each test
    to_remove = [name for name in sys.modules if name.startswith(("package1", "package2"))]
    for name in to_remove:
        del sys.modules[name]


def test_find_project_packages(test_project: Path, monkeypatch):
    """Test finding project packages using real files."""
    # Set up the environment to use our test project
    monkeypatch.setattr(sys, "argv", [str(test_project / "main.py")])

    # Find packages
    packages = discover._find_project_packages()

    # Verify only valid packages are found
    assert sorted(packages) == ["package1", "package2"]
    assert "not_a_package" not in packages


def test_import_package_modules(test_project: Path, monkeypatch):
    """Test importing package modules using real files."""
    # Add test project to Python path so we can import from it
    monkeypatch.syspath_prepend(str(test_project))

    # Import package1 and its modules
    discover._import_package_modules("package1")

    # Verify modules were imported
    import package1
    import package1.module1
    import package1.module2
    import package1.subpackage.submodule

    assert package1.module1.value == "module1"
    assert package1.module2.value == "module2"
    assert package1.subpackage.submodule.value == "submodule"


def test_discover_modules_with_auto_discovery(test_project: Path, monkeypatch):
    """Test automatic discovery and import of all packages."""
    # Set up the environment
    monkeypatch.setattr(sys, "argv", [str(test_project / "main.py")])
    monkeypatch.syspath_prepend(str(test_project))

    # Discover and import all packages
    discover.discover_modules()

    # Verify all packages and their modules were imported
    import package1
    import package1.module1
    import package1.module2
    import package1.subpackage.submodule
    import package2
    import package2.module

    assert package1.module1.value == "module1"
    assert package1.module2.value == "module2"
    assert package1.subpackage.submodule.value == "submodule"
    assert package2.module.value == "package2_module"


def test_discover_modules_with_specific_package(test_project: Path, monkeypatch):
    """Test discovery and import of a specific package."""
    # Add test project to Python path
    monkeypatch.syspath_prepend(str(test_project))

    # Discover and import only package2
    discover.discover_modules(["package2"])

    # Verify package2 was imported and is accessible
    import package2
    import package2.module

    assert package2.module.value == "package2_module"

    # Verify package1's modules were not imported
    assert "package1.module1" not in sys.modules
    assert "package1.module2" not in sys.modules
    assert "package1.subpackage.submodule" not in sys.modules
