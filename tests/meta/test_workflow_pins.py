import re

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# TODO: pin each of these to a commit SHA (keep the tag in a trailing comment), then delete the entry.
UNPINNED_ALLOWLIST = {
    "actions/checkout": "tag-pinned only",
    "actions/upload-artifact": "tag-pinned only",
    "actions/download-artifact": "tag-pinned only",
    "actions/setup-go": "tag-pinned only",
    "actions/setup-python": "tag-pinned only",
    "helm/kind-action": "tag-pinned only",
    "Swatinem/rust-cache": "tag-pinned only",
    "golangci/golangci-lint-action": "tag-pinned only",
    "bufbuild/buf-action": "tag-pinned only",
}


def yaml_files(root):
    files = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    files += sorted((root / ".github" / "actions").rglob("*.y*ml"))
    return files


def collect_uses(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                yield value
            else:
                yield from collect_uses(value)
    elif isinstance(node, list):
        for item in node:
            yield from collect_uses(item)


def test_workflow_files_are_valid_yaml(repo_root):
    files = yaml_files(repo_root)
    assert files, "no workflow or action YAML files found under .github/"
    errors = []
    for path in files:
        try:
            yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            errors.append(f"{path.relative_to(repo_root)}: {exc}")
    assert not errors, "invalid YAML:\n" + "\n".join(errors)


def test_every_action_is_sha_pinned_or_local(repo_root):
    offenders = []
    for path in yaml_files(repo_root):
        for uses in collect_uses(yaml.safe_load(path.read_text())):
            if uses.startswith("./"):
                continue
            name, _, ref = uses.partition("@")
            if SHA_RE.match(ref):
                continue
            if name in UNPINNED_ALLOWLIST:
                continue
            offenders.append(f"{path.relative_to(repo_root)}: uses: {uses}")
    assert not offenders, (
        "actions must be pinned to a 40-hex commit SHA (or be a local ./ path); "
        "pin them, or add to UNPINNED_ALLOWLIST with a reason:\n" + "\n".join(offenders)
    )


def test_allowlist_has_no_missing_ref(repo_root):
    bad = []
    for path in yaml_files(repo_root):
        for uses in collect_uses(yaml.safe_load(path.read_text())):
            if not uses.startswith("./") and "@" not in uses:
                bad.append(f"{path.relative_to(repo_root)}: uses: {uses} has no @ref")
    assert not bad, "\n".join(bad)
