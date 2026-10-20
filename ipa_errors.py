"""Shared PatchKit IPA exception type for CLI and library users."""


class IPAError(ValueError):
    """Invalid IPA, manifest, Mach-O patch or signing operation."""
