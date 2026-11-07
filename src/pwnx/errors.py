"""Errors shared by the specification, compiler, and runtime."""


class PwnxError(Exception):
    """A diagnostic suitable for presenting to a solve author."""


class ArtifactError(PwnxError):
    pass


class UnresolvedValueError(PwnxError):
    pass


class StaleValueError(PwnxError):
    pass


class ConstraintError(PwnxError):
    pass


class PlanningError(PwnxError):
    pass


class ProtocolError(PwnxError):
    buffered: bytes = b""
    sent: int = 0


class ReadTimeout(ProtocolError):
    pass


class EndOfStream(ProtocolError):
    pass


class ReplayDivergence(PwnxError):
    pass


class UnsupportedFeature(PwnxError):
    pass

