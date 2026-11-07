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


class RetryableInstanceError(ConstraintError):
    """A fresh target instance may satisfy an otherwise valid exploit plan."""

    def __init__(
        self,
        message: str,
        *,
        label: str = "",
        offset: int | None = None,
        byte: int | None = None,
        channel: str = "",
    ) -> None:
        super().__init__(message)
        self.label = label
        self.offset = offset
        self.byte = byte
        self.channel = channel


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

