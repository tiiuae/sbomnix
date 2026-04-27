# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Shared exception types for expected user-facing failures."""


class SbomnixError(RuntimeError):
    """Base class for expected user-facing errors."""


class FlakeRefResolutionError(SbomnixError):
    """Raised when an input looks like a flakeref but cannot be resolved."""

    def __init__(self, flakeref, stderr="", action="evaluating"):
        self.flakeref = flakeref
        self.stderr = "" if stderr is None else str(stderr)
        message = f"Failed {action} flakeref '{flakeref}'"
        stderr_summary = self.stderr.strip()
        if stderr_summary:
            message += f": {stderr_summary}"
        super().__init__(message)


class FlakeRefRealisationError(FlakeRefResolutionError):
    """Raised when a flakeref resolves but cannot be force-realised."""

    def __init__(self, flakeref, stderr=""):
        super().__init__(flakeref, stderr=stderr, action="force-realising")


class CsvLoadError(SbomnixError):
    """Raised when a CSV input cannot be read."""

    def __init__(self, name, error):
        self.name = name
        self.error = error
        super().__init__(f"Error reading csv file '{name}':\n{error}")


class CommandNotFoundError(SbomnixError):
    """Raised when a required executable is not available in PATH."""

    def __init__(self, name):
        self.name = name
        super().__init__(f"command '{name}' is not in PATH")


class InvalidNixArtifactError(SbomnixError):
    """Raised when a CLI target is not a valid nix artifact."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"Specified target is not a nix artifact: '{path}'")


class MissingNixDeriverError(SbomnixError):
    """Raised when a nix artifact cannot be mapped back to a derivation."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"No deriver found for: '{path}'")


class MissingNixOutPathError(SbomnixError):
    """Raised when a derivation does not expose an out path."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"No outpath found for: '{path}'")


class InvalidCpeDictionaryError(SbomnixError):
    """Raised when the downloaded CPE dictionary has invalid columns."""

    def __init__(self, required_cols):
        self.required_cols = tuple(sorted(required_cols))
        super().__init__(
            f"Missing required columns {list(self.required_cols)} from cpedict"
        )


class WhitelistApplicationError(SbomnixError):
    """Raised when vulnerability whitelist application cannot proceed."""

    def __init__(self, message):
        super().__init__(message)


class InvalidSbomError(SbomnixError):
    """Raised when a supplied SBOM path is invalid."""

    def __init__(self, path):
        self.path = path
        super().__init__(f"Specified sbom target is not a json file: '{path}'")
