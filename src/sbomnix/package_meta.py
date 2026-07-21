# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Package metadata lookup from package sets and flake package outputs.

Python sends compact SBOM component lookup keys to the Nix helper.  The helper
does package-set specific name lookup and returns derivation identity; this
module accepts metadata only when the returned drvPath/outPath matches a
component exactly.
"""

import functools
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess
import time
from tempfile import TemporaryDirectory

import pandas as pd

from common import columns as cols
from common.log import LOG
from common.proc import exec_cmd, nix_cmd
from sbomnix.artifacts import is_non_package_artifact_name
from sbomnix.flake_metadata import normalize_flakeref_for_nix_eval

PACKAGE_META_METHOD = "package-meta-nix"
META_OUTPUT_PATH = "meta_output_path"

_META_DERIVATION_PATH = "_meta_derivation_path"
_RICH_META_COLUMNS = (
    "meta_homepage",
    "meta_description",
    "meta_cpe",
    "meta_possible_cpes",
    "meta_license_short",
    "meta_license_spdxid",
)
_PNAME_PATTERN = (
    r"[a-zA-Z0-9][a-zA-Z0-9_+.]*"
    r"(?:-[a-zA-Z][a-zA-Z0-9_+.]*)*"
)
_STD_PNAME_RE = re.compile(
    rf"^(?P<pname>{_PNAME_PATTERN})-[0-9].*$",
)
_PYTHON_NAME_RE = re.compile(
    rf"^python(?P<major>[23])\.(?P<minor>[0-9]+)-(?P<pname>{_PNAME_PATTERN})-[0-9].*"
)
_PERL3_NAME_RE = re.compile(
    rf"^perl[0-9]+\.[0-9]+\.[0-9]+-(?P<pname>{_PNAME_PATTERN})-[0-9].*"
)
_PERL_NAME_RE = re.compile(rf"^perl[0-9]+\.[0-9]+-(?P<pname>{_PNAME_PATTERN})-[0-9].*")
_RUBY_NAME_RE = re.compile(rf"^ruby[0-9]+\.[0-9]+-(?P<pname>{_PNAME_PATTERN})-[0-9].*")
_BARE_NAME_RE = re.compile(r"^(?P<pname>[a-zA-Z0-9][a-zA-Z0-9_+.-]*)")
_QT_KDE_NAME_RE = re.compile(r"^(qt|kde|kf|plasma|kirigami|kwayland|kwin|qqc2).*")
_K_PREFIXED_PNAME_RE = re.compile(r"^k[a-z0-9].*")
_SUFFIX_RE = re.compile(r"^(?P<pname>.*)-[a-zA-Z][a-zA-Z0-9_+]*$")
_WEBKIT_ABI_RE = re.compile(r"^[^+]*\+abi=([0-9]+)\.([0-9]+).*")
_HASKELL_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){2,4}$")
_BASE_PACKAGE_SET = ""
_EXPLICIT_ATTR_REWRITES = {
    "bash": "bashNonInteractive",
    "gcc": "gcc-unwrapped",
    "libwww-perl": "LWP",
    "nss-cacert": "cacert",
    "util-linux-minimal": "util-linuxMinimal",
}


def package_meta_nix_path():
    """Return the packaged Nix helper used for package metadata evaluation."""
    return pathlib.Path(__file__).with_name("package_meta.nix")


def nix_system():
    """Return the host Nix system string used for package-set lookup."""
    machine = platform.machine()
    machine = {"AMD64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    system = platform.system().lower()
    system = {"darwin": "darwin", "linux": "linux"}.get(system, system)
    return f"{machine}-{system}"


def _eval_package_meta_request(request, *, pkgs_expression=None, impure=False):
    request_json = json.dumps(request, sort_keys=True)
    LOG.debug(
        "Evaluating package metadata request for system=%s lookup_count=%d input_roots_only=%s json_bytes=%d",
        request.get("system"),
        len(request.get("lookupKeys") or []),
        request.get("inputRootsOnly"),
        len(request_json),
    )
    if len(request_json) <= 30_000:
        return _eval_request(
            f"request = {_nix_string_literal(request_json)};",
            pkgs_expression=pkgs_expression,
            impure=impure,
        )

    # Pure Nix eval can read files relative to its --file entrypoint, but not
    # arbitrary absolute temp paths passed through --apply.
    with TemporaryDirectory(
        prefix="sbomnix_package_meta_",
    ) as tmpdir:
        tmpdir_path = pathlib.Path(tmpdir)
        (tmpdir_path / "request.json").write_text(request_json, encoding="utf-8")
        shutil.copyfile(package_meta_nix_path(), tmpdir_path / "package_meta.nix")
        eval_file = tmpdir_path / "eval.nix"
        eval_file.write_text(
            _request_file_eval_expression(pkgs_expression),
            encoding="utf-8",
        )
        return _eval_file(
            eval_file.as_posix(),
            impure=impure,
        )


def _request_file_eval_expression(pkgs_expression):
    pkgs_arg = f"\n  pkgs = {pkgs_expression};" if pkgs_expression else ""
    return (
        "import ./package_meta.nix {\n"
        "  request = builtins.readFile ./request.json;"
        f"{pkgs_arg}\n"
        "}\n"
    )


def _nix_string_literal(value):
    return json.dumps(value).replace("${", r"\${")


def _eval_request(request_arg, *, pkgs_expression=None, impure=False):
    started = time.perf_counter()
    ret = exec_cmd(
        _eval_command(
            _apply_expression(request_arg, pkgs_expression),
            impure,
        ),
        log_error=False,
    )
    df = parse_package_metadata(ret.stdout)
    LOG.verbose(
        "Evaluated inline package metadata request with %d row(s) in %.3fs",
        len(df),
        time.perf_counter() - started,
    )
    return df


def _eval_file(eval_file, *, impure=False):
    started = time.perf_counter()
    ret = exec_cmd(
        _eval_file_command(eval_file, impure),
        log_error=False,
    )
    df = parse_package_metadata(ret.stdout)
    LOG.verbose(
        "Evaluated file-backed package metadata request with %d row(s) in %.3fs",
        len(df),
        time.perf_counter() - started,
    )
    return df


def _eval_command(apply_expression, impure):
    return nix_cmd(
        "eval",
        "--json",
        "--file",
        package_meta_nix_path().as_posix(),
        "--apply",
        apply_expression,
        impure=impure,
    )


def _eval_file_command(eval_file, impure):
    return nix_cmd(
        "eval",
        "--json",
        "--file",
        eval_file,
        impure=impure,
    )


def _apply_expression(request_arg, pkgs_expression):
    pkgs_arg = f" pkgs = {pkgs_expression};" if pkgs_expression else ""
    return f"f: f {{ {request_arg}{pkgs_arg} }}"


def parse_package_metadata(json_text):
    """Parse metadata JSON emitted by package_meta.nix."""
    data = json.loads(json_text)
    derivations = data.get("derivations", [])
    if not isinstance(derivations, list):
        derivations = []

    rows = []
    for drv in derivations:
        if not isinstance(drv, dict):
            continue
        row = _metadata_row(drv)
        if row[cols.STORE_PATH] or row[META_OUTPUT_PATH]:
            rows.append(row)
    df = pd.DataFrame.from_records(rows)
    if df.empty:
        return df
    df = df.astype(str)
    df.fillna("", inplace=True)
    df.drop_duplicates(
        subset=[cols.STORE_PATH, META_OUTPUT_PATH],
        keep="first",
        inplace=True,
    )
    return df


def _metadata_row(drv):
    meta = drv.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}
    meta_license = meta.get("license", {})
    meta_maintainers = meta.get("maintainers", {})
    return {
        cols.STORE_PATH: drv.get("drvPath", "") or "",
        META_OUTPUT_PATH: drv.get("path", "") or "",
        cols.NAME: drv.get("name", "") or "",
        cols.PNAME: drv.get("pname", "") or "",
        cols.VERSION: drv.get("version", "") or "",
        "meta_homepage": _parse_optional_meta_entry(meta, key="homepage"),
        "meta_unfree": meta.get("unfree", ""),
        "meta_description": meta.get("description", "") or "",
        "meta_position": meta.get("position", "") or "",
        "meta_cpe": _parse_optional_meta_entry(meta, key="cpe"),
        "meta_possible_cpes": _parse_optional_meta_entry(
            meta.get("possibleCPEs", []),
            key="cpe",
        ),
        "meta_license_short": _parse_optional_meta_entry(meta_license, key="shortName"),
        "meta_license_spdxid": _parse_optional_meta_entry(meta_license, key="spdxId"),
        "meta_maintainers_email": _parse_optional_meta_entry(
            meta_maintainers,
            key="email",
        ),
    }


def _parse_optional_meta_entry(meta, key):
    if meta is None:
        return ""
    if isinstance(meta, dict):
        return _parse_optional_meta_entry(meta.get(key, ""), key)
    if isinstance(meta, list):
        return ";".join(
            filter(None, (_parse_optional_meta_entry(item, key) for item in meta))
        )
    return str(meta)


def package_meta_lookup_keys_for_components(
    df_components,
    *,
    target_path=None,
    flakeref=None,
):
    """Return compact Nix metadata lookup keys for the given component rows."""
    target_attr = _flake_package_attr(flakeref)
    keys = {}
    for component in _records(df_components):
        if _is_non_package_artifact(component):
            continue
        lookup = _lookup_key_for_component(component)
        if lookup is None:
            continue
        if (
            target_attr
            and lookup["version"]
            and _component_matches_target_path(component, target_path)
        ):
            lookup["candidateAttrs"] = [target_attr]
        key = (
            lookup["name"],
            lookup["pname"],
            lookup["version"],
            lookup.get("system", ""),
            tuple(lookup.get("candidateAttrs", [])),
        )
        keys[key] = lookup
    return [keys[key] for key in sorted(keys)]


def _lookup_key_for_component(component):
    name = _clean_lookup_value(component.get(cols.NAME, ""))
    pname = _clean_lookup_value(component.get(cols.PNAME, ""))
    version = _clean_lookup_value(component.get(cols.VERSION, ""))
    system = _clean_lookup_value(component.get("system", ""))
    if not name:
        if not pname:
            return None
        name = f"{pname}-{version}" if version else pname
    if not pname:
        pname = _pname_from_package_name(name)
    lookup = {
        "name": name,
        "pname": pname,
        "version": version,
    }
    if system:
        lookup["system"] = system
    return lookup


def _clean_lookup_value(value):
    if value is None:
        return ""
    if pd.isna(value):
        return ""
    return str(value).strip()


def _component_matches_target_path(component, target_path):
    target_path = _clean_lookup_value(target_path)
    if not target_path:
        return False
    if _clean_lookup_value(component.get(cols.STORE_PATH, "")) == target_path:
        return True
    if _clean_lookup_value(component.get("out", "")) == target_path:
        return True
    outputs = component.get(cols.OUTPUTS, [])
    if isinstance(outputs, str):
        outputs = [outputs]
    elif not isinstance(outputs, (list, tuple, set)):
        return False
    return target_path in {_clean_lookup_value(output) for output in outputs}


def _flake_package_attr(flakeref):
    _flake, separator, attr = str(flakeref or "").partition("#")
    if not separator:
        return ""
    parts = attr.split(".")
    if len(parts) == 1:
        return parts[0]
    if (
        len(parts) < 3
        or parts[0] not in {"packages", "legacyPackages"}
        or not _is_nix_system_name(parts[1])
    ):
        return ""
    return parts[2]


def _clean_candidate_attrs(attrs):
    if isinstance(attrs, str):
        attrs = [attrs]
    cleaned = []
    seen = set()
    for raw_attr in attrs or []:
        attr = _clean_lookup_value(raw_attr)
        if not attr or attr in seen:
            continue
        seen.add(attr)
        cleaned.append(attr)
    return cleaned


def _normalized_lookup_keys(lookup_keys):
    if isinstance(lookup_keys, dict):
        lookup_keys = lookup_keys.get("lookupKeys", [])
    normalized = []
    seen = set()
    for lookup in lookup_keys or []:
        if not isinstance(lookup, dict):
            continue
        name = _clean_lookup_value(lookup.get("name", ""))
        pname = _clean_lookup_value(lookup.get("pname", ""))
        version = _clean_lookup_value(lookup.get("version", ""))
        system = _clean_lookup_value(lookup.get("system", ""))
        if not name:
            continue
        if not pname:
            pname = _pname_from_package_name(name)
        candidate_attrs = _clean_candidate_attrs(lookup.get("candidateAttrs", []))
        key = (name, pname, version, system, tuple(candidate_attrs))
        if key in seen:
            continue
        seen.add(key)
        normalized_lookup = {"name": name, "pname": pname, "version": version}
        if system:
            normalized_lookup["system"] = system
        if candidate_attrs:
            normalized_lookup["candidateAttrs"] = candidate_attrs
        normalized.append(normalized_lookup)
    return sorted(
        normalized,
        key=lambda item: (
            item["name"],
            item["pname"],
            item["version"],
            item.get("system", ""),
            tuple(item.get("candidateAttrs", [])),
        ),
    )


def _request_system_groups(flakeref, lookup_keys):
    fallback_system = _system_from_flakeref(flakeref) or nix_system()
    groups = {}
    for lookup in lookup_keys:
        system = _clean_lookup_value(lookup.get("system", ""))
        if not _is_nix_system_name(system):
            system = fallback_system
        groups.setdefault(system, []).append(lookup)
    return [(system, groups[system]) for system in sorted(groups)]


def _is_nix_system_name(system):
    return re.match(r"^[A-Za-z0-9_]+-[A-Za-z0-9_]+$", system or "") is not None


def _system_from_flakeref(flakeref):
    _flake, separator, attr = (flakeref or "").partition("#")
    if not separator or not attr:
        return ""
    attr_parts = attr.split(".")
    if (
        len(attr_parts) >= 3
        and attr_parts[0] in {"packages", "legacyPackages"}
        and _is_nix_system_name(attr_parts[1])
    ):
        return attr_parts[1]
    return ""


def _request_lookup_keys(lookup_keys):
    return [_lookup_key_with_candidate_tiers(lookup) for lookup in lookup_keys]


def _lookup_key_with_candidate_tiers(lookup):
    name = lookup["name"]
    version = lookup["version"]
    parsed_pname = _pname_from_package_name(name)
    pname = (
        parsed_pname
        if _is_prefixed_language_name(name) or (not version and lookup["pname"] == name)
        else lookup["pname"] or parsed_pname
    )
    pname = pname or ""
    key = {
        "name": name,
        "pname": pname,
        "version": version,
        "candidateTiers": _candidate_tiers(
            name,
            pname,
            version,
            candidate_attrs=lookup.get("candidateAttrs", []),
        ),
    }
    if _is_haskell_package_name(name, pname, version):
        key["collectAllCanonical"] = True
    return key


def _candidate_tiers(name, pname, version="", *, candidate_attrs=None):
    if not pname:
        return []

    # Tiers are searched in order by package_meta.nix, so keep broad rewrites
    # after higher-confidence package-set and exact-name candidates.
    specs = _package_set_hints_for_lookup(name)
    rewrite_specs = (
        specs
        if any(spec != _BASE_PACKAGE_SET for spec in specs)
        else [_BASE_PACKAGE_SET]
    )
    strip_specs = (
        specs if _is_python_name(name) or _is_ruby_name(name) else [_BASE_PACKAGE_SET]
    )
    p1 = _strip_suffix(pname)
    p2 = _strip_suffix(p1) if p1 else None

    tiers = []
    _add_tier(
        tiers,
        [
            _candidate(attr, [_BASE_PACKAGE_SET])
            for attr in _clean_candidate_attrs(candidate_attrs)
        ],
    )
    _add_tier(tiers, [_candidate(pname, specs), _kde_exact_candidate(name, pname)])
    _add_tier(tiers, _perl_candidates(name, pname))
    _add_tier(tiers, _low_loss_rewrite_candidates(pname, rewrite_specs))
    _add_tier(tiers, [_candidate(p1, strip_specs)])
    _add_tier(tiers, _low_loss_rewrite_candidates(p1, strip_specs))
    _add_tier(tiers, [_candidate(p2, strip_specs)])
    _add_tier(tiers, _low_loss_rewrite_candidates(p2, strip_specs))
    _add_tier(tiers, [_cxx_candidate(pname)])
    _add_tier(tiers, [_gtk_candidate(pname)])
    _add_tier(tiers, [_webkit_candidate(name)])
    _add_tier(
        tiers, [_candidate(pname.lower(), specs) if pname.lower() != pname else None]
    )
    _add_tier(tiers, [_leading_digit_candidate(pname, specs)])
    _add_tier(tiers, [_no_dash_candidate(pname, specs)])
    _add_tier(tiers, [_candidate(f"{pname}{n}", specs) for n in range(1, 5)])
    _add_tier(tiers, _underscore_version_candidates(name, pname, specs))
    _add_tier(tiers, [_dot_dash_candidate(pname, specs)])
    _add_tier(tiers, [_plus_candidate(pname, specs)])
    _add_tier(tiers, _haskell_candidates(name, pname, version))
    return tiers


def _add_tier(tiers, candidates):
    tier = []
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        key = (
            candidate["attr"],
            tuple(candidate["packageSets"]),
            candidate.get("requirePnameOrName", False),
        )
        if key in seen:
            continue
        seen.add(key)
        tier.append(candidate)
    if tier:
        tiers.append(tier)


def _candidate(attr, package_sets, *, require_pname_or_name=False):
    if not attr:
        return None
    candidate = {
        "attr": attr,
        "packageSets": list(package_sets),
    }
    if require_pname_or_name:
        candidate["requirePnameOrName"] = True
    return candidate


def _package_set_hints_for_lookup(name):
    package_sets = _component_package_set_hints(name)
    package_sets.append(_BASE_PACKAGE_SET)
    return _unique_package_sets(package_sets)


def _component_package_set_hints(name):
    if _is_python_name(name):
        return _python_package_sets_for_name(name)
    if _is_perl_name(name):
        return ["perlPackages"]
    if _is_ruby_name(name):
        return ["rubyPackages"]
    if _is_qt_kde_name(name):
        return ["qt6Packages", "qt6", "kdePackages"]
    return []


def _unique_package_sets(package_sets):
    unique = []
    seen = set()
    for package_set in package_sets:
        if package_set in seen:
            continue
        seen.add(package_set)
        unique.append(package_set)
    return unique


def _python_package_sets_for_name(name):
    match = _PYTHON_NAME_RE.match(name)
    if not match:
        return ["python3Packages"]
    compact = f"{match.group('major')}{match.group('minor')}"
    if compact.startswith("3"):
        return [f"python{compact}Packages", "python3Packages"]
    return [f"python{compact}Packages"]


def _is_prefixed_language_name(name):
    return _is_python_name(name) or _is_perl_name(name) or _is_ruby_name(name)


def _is_python_name(name):
    return _PYTHON_NAME_RE.match(name) is not None


def _is_perl_name(name):
    return (
        _PERL3_NAME_RE.match(name) is not None or _PERL_NAME_RE.match(name) is not None
    )


def _is_ruby_name(name):
    return _RUBY_NAME_RE.match(name) is not None


def _is_qt_kde_name(name):
    return _QT_KDE_NAME_RE.match(name) is not None


def _kde_exact_candidate(name, pname):
    if (
        _is_prefixed_language_name(name)
        or _is_qt_kde_name(name)
        or _K_PREFIXED_PNAME_RE.match(pname or "") is None
    ):
        return None
    return _candidate(pname, ["kdePackages"])


def _haskell_candidates(name, pname, version):
    if _is_haskell_package_name(name, pname, version):
        return [_candidate(pname, ["haskellPackages"])]
    return []


def _is_haskell_package_name(name, pname, version):
    if (
        not name
        or not pname
        or not version
        or _is_prefixed_language_name(name)
        or _is_qt_kde_name(name)
        or is_non_package_artifact_name(name)
    ):
        return False
    if not _HASKELL_VERSION_RE.match(version):
        return False
    return name == f"{pname}-{version}"


def _pname_from_package_name(value):
    for regex in (
        _PYTHON_NAME_RE,
        _PERL3_NAME_RE,
        _PERL_NAME_RE,
        _RUBY_NAME_RE,
        _STD_PNAME_RE,
        _BARE_NAME_RE,
    ):
        match = regex.match(str(value or ""))
        if match:
            return match.group("pname")
    return ""


def _perl_candidates(name, pname):
    if not _is_perl_name(name):
        return []
    explicit = _EXPLICIT_ATTR_REWRITES.get(pname)
    no_dash = pname.replace("-", "")
    return [
        _candidate(explicit, ["perlPackages"]),
        _candidate(no_dash, ["perlPackages"]) if no_dash != pname else None,
    ]


def _low_loss_rewrite_candidates(pname, specs):
    if not pname:
        return []
    return [
        _rewritten_candidate(pname, _EXPLICIT_ATTR_REWRITES.get(pname), specs),
        _rewritten_candidate(pname, pname.replace("-", "_"), specs),
        _rewritten_candidate(pname, _dash_to_camel_case(pname), specs),
    ]


def _rewritten_candidate(pname, rewritten, specs):
    if not rewritten or rewritten == pname:
        return None
    return _candidate(rewritten, specs, require_pname_or_name=True)


def _strip_suffix(pname):
    if not pname:
        return None
    match = _SUFFIX_RE.match(pname)
    if match:
        return match.group("pname")
    return None


def _dash_to_camel_case(pname):
    if not pname or "-" not in pname:
        return None
    first, *rest = pname.split("-")
    return first + "".join(_uppercase_ascii_first(part) for part in rest)


def _uppercase_ascii_first(value):
    if not value:
        return ""
    return value[:1].upper() + value[1:]


def _cxx_candidate(pname):
    if pname.endswith("++"):
        return _candidate(f"{pname.removesuffix('++')}xx", [_BASE_PACKAGE_SET])
    return None


def _gtk_candidate(pname):
    attrs = {
        "gtk+": "gtk2",
        "gtk+3": "gtk3",
    }
    return _candidate(attrs.get(pname), [_BASE_PACKAGE_SET])


def _webkit_candidate(name):
    match = _WEBKIT_ABI_RE.match(name)
    if not match:
        return None
    return _candidate(
        f"webkitgtk_{match.group(1)}_{match.group(2)}", [_BASE_PACKAGE_SET]
    )


def _leading_digit_candidate(pname, specs):
    if re.match(r"^[0-9].*", pname):
        return _candidate(f"_{pname}", specs)
    return None


def _no_dash_candidate(pname, specs):
    no_dash = pname.replace("-", "")
    if no_dash != pname:
        return _candidate(no_dash, specs)
    return None


def _underscore_version_candidates(name, pname, specs):
    major_minor = re.match(rf"{re.escape(pname)}-([0-9]+)\.([0-9]+).*", name)
    major = re.match(rf"{re.escape(pname)}-([0-9]+).*", name)
    if major_minor:
        attrs = [
            f"{pname}_{major_minor.group(1)}_{major_minor.group(2)}",
            f"{pname}_{major_minor.group(1)}",
        ]
    elif major:
        attrs = [f"{pname}_{major.group(1)}"]
    else:
        attrs = []
    return [_candidate(attr, specs) for attr in attrs]


def _dot_dash_candidate(pname, specs):
    dot_dash = pname.replace(".", "-")
    if dot_dash != pname:
        return _candidate(dot_dash, specs)
    return None


def _plus_candidate(pname, specs):
    plus_name = pname.replace("+", "plus")
    if plus_name != pname:
        return _candidate(plus_name, specs)
    return None


def _records(df):
    if df is None or df.empty:
        return []
    return df.to_dict("records")


def _is_non_package_artifact(component):
    return any(
        is_non_package_artifact_name(str(component.get(column, "") or ""))
        for column in (cols.NAME, cols.PNAME)
    )


def package_meta_candidate_key(candidates):
    """Return a short stable digest for a candidate request."""
    data = json.dumps(candidates, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()[:16]


@functools.cache
def package_meta_cache_fingerprint():
    """Return a short hash for the package metadata lookup implementation."""
    try:
        paths = [
            pathlib.Path(__file__),
            package_meta_nix_path(),
            pathlib.Path(__file__).with_name("artifacts.py"),
        ]
        h = hashlib.sha256()
        for path in paths:
            h.update(path.read_bytes())
            h.update(b"\0")
        return h.hexdigest()[:16]
    except OSError as error:
        LOG.warning("Packaged package metadata helper is unavailable: %s", error)
        return "missing"


def match_package_metadata_to_components(components, metadata, *, buildtime):
    """Return metadata rows that match component drvPath/outPath exactly."""
    if components is None or components.empty or metadata is None or metadata.empty:
        return pd.DataFrame()

    matches = []
    if buildtime:
        matches.append(_drv_path_matches(components, metadata, priority=0))
        matches.append(_output_path_matches(components, metadata, priority=1))
    else:
        matches.append(_output_path_matches(components, metadata, priority=0))
        matches.append(_drv_path_matches(components, metadata, priority=1))
    return _best_component_matches(matches)


def _output_path_matches(components, metadata, *, priority):
    output_components = components[[cols.STORE_PATH, cols.OUTPUTS]].copy()
    output_components = output_components.explode(cols.OUTPUTS)
    output_components.rename(
        columns={
            cols.STORE_PATH: "_component_store_path",
            cols.OUTPUTS: META_OUTPUT_PATH,
        },
        inplace=True,
    )
    output_components = output_components[
        output_components[META_OUTPUT_PATH].astype(bool)
    ]
    meta = metadata.rename(columns={cols.STORE_PATH: _META_DERIVATION_PATH})
    matched = output_components.merge(meta, how="inner", on=META_OUTPUT_PATH)
    if matched.empty:
        return matched
    matched[cols.STORE_PATH] = matched["_component_store_path"]
    matched["_meta_match_priority"] = priority
    return matched


def _drv_path_matches(components, metadata, *, priority):
    component_paths = components[[cols.STORE_PATH]].copy()
    meta = metadata.rename(columns={cols.STORE_PATH: _META_DERIVATION_PATH})
    matched = component_paths.merge(
        meta,
        how="inner",
        left_on=cols.STORE_PATH,
        right_on=_META_DERIVATION_PATH,
    )
    if matched.empty:
        return matched
    matched["_meta_match_priority"] = priority
    return matched


def _best_component_matches(frames):
    frames = [frame for frame in frames if frame is not None and not frame.empty]
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    df["_meta_richness"] = _metadata_richness(df)
    df.sort_values(
        by=[cols.STORE_PATH, "_meta_match_priority", "_meta_richness"],
        ascending=[True, True, False],
        inplace=True,
    )
    df.drop_duplicates(subset=[cols.STORE_PATH], keep="first", inplace=True)
    drop_columns = [
        "_component_store_path",
        _META_DERIVATION_PATH,
        META_OUTPUT_PATH,
        "_meta_match_priority",
        "_meta_richness",
    ]
    df.drop(columns=[column for column in drop_columns if column in df], inplace=True)
    return df


def _metadata_richness(df):
    existing = [column for column in _RICH_META_COLUMNS if column in df]
    if not existing:
        return 0
    return df[existing].replace("", pd.NA).notna().sum(axis=1)


def _concat_metadata_frames(frames):
    frames = [frame for frame in frames if frame is not None and not frame.empty]
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def _scan_package_meta(  # noqa: PLR0913
    lookup_keys,
    *,
    flakeref=None,
    nixpkgs_path=None,
    pkgs_expression=None,
    input_roots_only=False,
    impure=False,
):
    started = time.perf_counter()
    lookup_keys = _normalized_lookup_keys(lookup_keys)
    if not lookup_keys:
        return pd.DataFrame()
    flakeref = normalize_flakeref_for_nix_eval(flakeref)
    LOG.debug("Reading package metadata for flakeref: %s", flakeref)
    frames = []
    for request_system, system_lookup_keys in _request_system_groups(
        flakeref, lookup_keys
    ):
        LOG.verbose(
            "Evaluating package metadata for %d lookup(s) on system '%s'",
            len(system_lookup_keys),
            request_system,
        )
        request = {
            "flakeref": flakeref or None,
            "system": request_system,
            "nixpkgsPath": str(nixpkgs_path) if nixpkgs_path else None,
            "lookupKeys": _request_lookup_keys(system_lookup_keys),
            "inputRootsOnly": bool(input_roots_only),
        }
        frames.append(
            _eval_package_meta_request(
                request,
                pkgs_expression=pkgs_expression,
                impure=impure,
            )
        )
    df = _concat_metadata_frames(frames)
    LOG.verbose(
        "Read package metadata with %d candidate row(s) in %.3fs",
        len(df),
        time.perf_counter() - started,
    )
    return df


def try_scan_package_meta(  # noqa: PLR0913
    lookup_keys,
    *,
    flakeref=None,
    nixpkgs_path=None,
    pkgs_expression=None,
    input_roots_only=False,
    impure=False,
):
    """Return package metadata dataframe, or None on failure."""
    try:
        return _scan_package_meta(
            lookup_keys,
            flakeref=flakeref,
            nixpkgs_path=nixpkgs_path,
            pkgs_expression=pkgs_expression,
            input_roots_only=input_roots_only,
            impure=impure,
        )
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        subprocess.CalledProcessError,
        TypeError,
        ValueError,
    ):
        LOG.debug("Failed reading package metadata", exc_info=True)
        return None
