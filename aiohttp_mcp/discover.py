import importlib
import logging
import os
import pkgutil
import sys

logger = logging.getLogger(__name__)


def discover_modules(package_names: list[str] | None = None) -> None:
    """Discover and import all modules in the specified packages."""
    logger.debug("Discovering modules")

    if package_names is None:
        # By default, search all top-level packages in the project
        logger.debug("No package names specified. Discovering all top-level packages.")
        package_names = _find_project_packages()
    else:
        logger.debug("Using specified package names: %r", package_names)

    for package_name in package_names:
        _import_package_modules(package_name)


def _find_project_packages() -> list[str]:
    """Find all top-level packages in the current project."""
    # Get the directory of the main script
    main_script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

    logger.debug("Finding top-level packages in %r", main_script_dir)

    packages = []
    # Walk through all directories in the main script directory
    for item in os.listdir(main_script_dir):
        item_path = os.path.join(main_script_dir, item)
        # Check if it's a directory and has an __init__.py file (making it a package)
        if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, "__init__.py")):
            packages.append(item)

    return packages


def _import_package_modules(package_name: str) -> None:
    """Import all modules in a package and its subpackages."""
    try:
        logger.debug("Importing package %r", package_name)

        # Import the package
        package = importlib.import_module(package_name)

        # Walk through all modules/subpackages in the package
        for _, module_name, _ in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            logger.debug("Importing module %r", module_name)
            try:
                # Import the module
                importlib.import_module(module_name)
            except ImportError as e:
                logger.exception("Error importing module %s: %s", module_name, e)

    except ImportError as e:
        logger.exception("Error importing package %s: %s", package_name, e)
