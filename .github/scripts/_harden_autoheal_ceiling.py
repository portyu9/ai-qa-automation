from pathlib import Path

path = Path('.github/scripts/security_autoheal.py')
text = path.read_text(encoding='utf-8')

old_constants = '''SAFE_RULES = {
    "py/reflective-xss",
    "py/incomplete-url-substring-sanitization",
    "py/clear-text-logging-sensitive-data",
    "py/overly-permissive-file",
}
SAFE_VERIFIER_LABELS = {
'''
new_constants = '''SAFE_RULES = {
    "py/reflective-xss",
    "py/incomplete-url-substring-sanitization",
    "py/clear-text-logging-sensitive-data",
    "py/overly-permissive-file",
}
SAFE_MODEL_AUTOFIX_PREFIXES = {"src/", "examples/", "tests/"}
MAX_CHANGED_FILES_CEILING = 5
MAX_OPEN_REPAIRS_CEILING = 4
MAX_ATTEMPTS_PER_ALERT_CEILING = 2
SAFE_VERIFIER_LABELS = {
'''
if text.count(old_constants) != 1:
    raise SystemExit('expected one SAFE_RULES block')
text = text.replace(old_constants, new_constants, 1)

old_limits = '''    for key, upper in (
        ("maxChangedFiles", 10),
        ("maxOpenRepairs", 10),
        ("maxAttemptsPerAlert", 3),
    ):
        value = config.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= upper):
            errors.append(f"{key} must be an integer from 1 to {upper}")
'''
new_limits = '''    for key, upper in (
        ("maxChangedFiles", MAX_CHANGED_FILES_CEILING),
        ("maxOpenRepairs", MAX_OPEN_REPAIRS_CEILING),
        ("maxAttemptsPerAlert", MAX_ATTEMPTS_PER_ALERT_CEILING),
    ):
        value = config.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= upper):
            errors.append(f"{key} must be an integer from 1 to the code-owned ceiling {upper}")
'''
if text.count(old_limits) != 1:
    raise SystemExit('expected one config limit block')
text = text.replace(old_limits, new_limits, 1)

old_lists = '''    for key in ("modelAutofixPathPrefixes", "deterministicOnlyPaths", "neverModifyPaths"):
        values = config.get(key)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
        ):
            errors.append(f"{key} must be a non-empty string list")
    never = config.get("neverModifyPaths")
'''
new_lists = '''    for key in ("modelAutofixPathPrefixes", "deterministicOnlyPaths", "neverModifyPaths"):
        values = config.get(key)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
        ):
            errors.append(f"{key} must be a non-empty string list")
    model_prefixes = config.get("modelAutofixPathPrefixes")
    if isinstance(model_prefixes, list) and not set(model_prefixes) <= SAFE_MODEL_AUTOFIX_PREFIXES:
        errors.append(
            "modelAutofixPathPrefixes may only narrow the code-owned src/examples/tests authority"
        )
    never = config.get("neverModifyPaths")
'''
if text.count(old_lists) != 1:
    raise SystemExit('expected one config list block')
text = text.replace(old_lists, new_lists, 1)

anchor = '''    if _generated_repairs([spoofed]):
        raise AutohealError("non-Actions PR spoofed the generated-repair namespace")
    print("security-autoheal self-test: ok")
'''
replacement = '''    if _generated_repairs([spoofed]):
        raise AutohealError("non-Actions PR spoofed the generated-repair namespace")

    main_sha = "a" * 40
    valid_alert = {
        "number": 7,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {"id": "py/reflective-xss", "security_severity": "8.8"},
        "most_recent_instance": {
            "ref": "refs/heads/main",
            "commit_sha": main_sha,
            "location": {"path": "examples/reference_sut/app.py", "start_line": 73},
            "message": {"text": "reflected server-side cross-site scripting"},
        },
    }
    subject = validate_alert(valid_alert, main_sha, config)
    if subject["number"] != 7 or subject["path"] != "examples/reference_sut/app.py":
        raise AutohealError("valid exact-main CodeQL alert self-test failed")

    def expect_alert_block(mutator: Any, label: str) -> None:
        candidate = json.loads(json.dumps(valid_alert))
        mutator(candidate)
        try:
            validate_alert(candidate, main_sha, config)
        except PolicyBlock:
            return
        raise AutohealError(f"security auto-heal accepted forbidden alert shape: {label}")

    expect_alert_block(
        lambda value: value["rule"].__setitem__("id", "py/unknown-future-rule"),
        "unknown-rule",
    )
    expect_alert_block(
        lambda value: value["rule"].__setitem__("security_severity", "6.9"),
        "below-severity-floor",
    )
    expect_alert_block(
        lambda value: value["most_recent_instance"].__setitem__("ref", "refs/heads/feature"),
        "non-main-ref",
    )
    expect_alert_block(
        lambda value: value["most_recent_instance"].__setitem__("commit_sha", "b" * 40),
        "stale-main-sha",
    )
    expect_alert_block(
        lambda value: value["most_recent_instance"]["location"].__setitem__(
            "path", ".github/scripts/security_autoheal.py"
        ),
        "never-modify-control-plane",
    )

    _validate_candidate_diff(
        [{"filename": "examples/reference_sut/app.py"}],
        subject,
        config,
        deterministic=False,
    )
    for files, deterministic, label in (
        ([{"filename": ".github/workflows/ci.yml"}, {"filename": subject["path"]}], False, "model-control-plane"),
        ([{"filename": subject["path"]}, {"filename": "tests/unrelated.py"}], True, "deterministic-extra-file"),
    ):
        try:
            _validate_candidate_diff(files, subject, config, deterministic=deterministic)
        except PolicyBlock:
            pass
        else:
            raise AutohealError(f"security auto-heal accepted candidate diff escape: {label}")

    expanded_attempts = dict(config)
    expanded_attempts["maxAttemptsPerAlert"] = MAX_ATTEMPTS_PER_ALERT_CEILING + 1
    if not any("maxAttemptsPerAlert" in error for error in validate_config(expanded_attempts)):
        raise AutohealError("config expanded automatic repair attempt ceiling")
    expanded_paths = dict(config)
    expanded_paths["modelAutofixPathPrefixes"] = list(config["modelAutofixPathPrefixes"]) + ["scripts/"]
    if not any("modelAutofixPathPrefixes" in error for error in validate_config(expanded_paths)):
        raise AutohealError("config expanded model-generated repair path authority")

    print("security-autoheal self-test: ok")
'''
if text.count(anchor) != 1:
    raise SystemExit('expected one self-test tail anchor')
text = text.replace(anchor, replacement, 1)
path.write_text(text, encoding='utf-8', newline='\n')
