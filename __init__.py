"""
dotninja - Binary Ninja .NET Lifter & Analysis Suite
Final Entry Point: Architecture, View, and Plugins
"""

from binaryninja.log import log_info

from .analyzer import register_plugins
from .arch import DotNetArch
from .view import DotNetView


def initialize():
    log_info("[dotninja] Registering .NET Architecture (CIL)")
    DotNetArch.register()

    log_info("[dotninja] Registering .NET BinaryView (CLR)")
    DotNetView.register()

    log_info("[dotninja] Registering Automated Analysis Commands")
    register_plugins()


# Auto-execute on plugin load
initialize()
