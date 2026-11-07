"""Registrations which connect optional domain actions to the semantic runtime."""

from ..actions import register_action_executor
from ..libc import IdentifyLibc


def _identify_libc(action, runtime):
    result = action.identify()
    runtime.bind(action.target, result, source=action.describe())
    if runtime.trace is not None:
        runtime.trace.metadata.setdefault("libc_hypotheses", []).append(
            result.to_dict()
        )
    return result


def register() -> None:
    try:
        register_action_executor(IdentifyLibc, _identify_libc)
    except ValueError:
        pass


register()
