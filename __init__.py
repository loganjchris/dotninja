"""
dotninja - Binary Ninja .NET Lifter & Analysis Suite
Final Entry Point: Architecture, View, and Plugins
"""

from binaryninja.log import log_info
import sys

from .analyzer import register_plugins
from binaryninja import Architecture

from .arch import DotNet32, DotNet64, DotNetCallingConvention
from .view import DotNetView
from .validation import register_validation_plugin


def initialize():
    log_info("[dotninja] Registering .NET Architectures (CIL32/CIL64)")
    DotNet32.register()
    DotNet64.register()
    for arch_name in ("dotnet32", "dotnet64"):
        arch = Architecture[arch_name]
        calling_convention = DotNetCallingConvention(arch, "dotnet")
        arch.register_calling_convention(calling_convention)
        arch.default_calling_convention = calling_convention
        arch.standalone_platform.default_calling_convention = calling_convention

    log_info("[dotninja] Registering .NET BinaryView (CLR)")
    DotNetView.register()

    log_info("[dotninja] Registering Automated Analysis Commands")
    register_plugins()
    register_validation_plugin()


# Pytest must remain license-free; Binary Ninja loads this module as a plugin in UI.
if "pytest" not in sys.modules:
    initialize()
