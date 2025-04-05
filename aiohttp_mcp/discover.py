import importlib
import logging
import os
import pkgutil
import sys
from typing import List, Optional

logger = logging.getLogger(__name__)

def discover_modules(package_names: Optional[List[str]] = None):
    """Discover and import all modules in the specified packages."""
    if package_names is None:
        # By default, search all top-level packages in the project
        package_names = _find_project_packages()

    for package_name in package_names:
        _import_package_modules(package_name)


def _find_project_packages() -> List[str]:
    """Find all top-level packages in the current project."""
    # Get the directory of the main script
    main_script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

    packages = []
    # Walk through all directories in the main script directory
    for item in os.listdir(main_script_dir):
        item_path = os.path.join(main_script_dir, item)
        # Check if it's a directory and has an __init__.py file (making it a package)
        if os.path.isdir(item_path) and os.path.exists(
            os.path.join(item_path, "__init__.py")
        ):
            packages.append(item)

    return packages


def _import_package_modules(package_name: str):
    """Import all modules in a package and its subpackages."""
    try:
        package = importlib.import_module(package_name)

        # Walk through all modules/subpackages in the package
        for _, module_name, _ in pkgutil.walk_packages(
            package.__path__, package.__name__ + "."
        ):
            try:
                # Import the module
                importlib.import_module(module_name)
            except ImportError as e:
                print(f"Error importing module {module_name}: {e}")

    except ImportError as e:
        print(f"Error importing package {package_name}: {e}")
