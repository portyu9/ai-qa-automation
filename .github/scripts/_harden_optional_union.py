from pathlib import Path

path = Path('.github/scripts/dependency_lock_compiler.py')
text = path.read_text(encoding='utf-8')
old = '''    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or "dev" not in optional:
        raise LockCompileError("project.optional-dependencies.dev is required")
    dev = _validated_requirements(optional.get("dev"), context="dev")
    runtime_names = {_requirement_name(item) for item in runtime}
    dev_names = {_requirement_name(item) for item in dev}
    if runtime_names & dev_names:
        raise LockCompileError("dev requirements must not duplicate runtime dependency identities")

    output_dir.mkdir(parents=True, exist_ok=True)
    graphs = {
        "runtime-py311.lock": (python311, runtime),
        "dev-py311.lock": (python311, runtime + dev),
        "dev-py314.lock": (python314, runtime + dev),
        "build-py311.lock": (python311, [build_requires[0]]),
    }
'''
new = '''    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or "dev" not in optional:
        raise LockCompileError("project.optional-dependencies.dev is required")
    optional_requirements: dict[str, str] = {}
    for group in sorted(optional):
        if not isinstance(group, str) or not group:
            raise LockCompileError("optional dependency group name is invalid")
        group_requirements = _validated_requirements(optional[group], context=f"optional:{group}")
        for requirement in group_requirements:
            identity = _requirement_name(requirement)
            prior = optional_requirements.get(identity)
            if prior is not None and prior != requirement:
                raise LockCompileError(
                    f"optional dependency specs disagree across groups: {identity}"
                )
            optional_requirements[identity] = requirement
    runtime_names = {_requirement_name(item) for item in runtime}
    if runtime_names & set(optional_requirements):
        raise LockCompileError(
            "optional requirements must not duplicate runtime dependency identities"
        )
    all_optional = [optional_requirements[name] for name in sorted(optional_requirements)]

    output_dir.mkdir(parents=True, exist_ok=True)
    graphs = {
        "runtime-py311.lock": (python311, runtime),
        "dev-py311.lock": (python311, runtime + all_optional),
        "dev-py314.lock": (python314, runtime + all_optional),
        "build-py311.lock": (python311, [build_requires[0]]),
    }
'''
if text.count(old) != 1:
    raise SystemExit(f'expected one compiler optional-group block, found {text.count(old)}')
path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
