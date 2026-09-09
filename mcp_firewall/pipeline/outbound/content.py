"""Apply text protection to every copy of data in a tool result."""

from collections.abc import Callable
from typing import Any

from ...models import ToolCallResponse


class ResponseContentError(ValueError):
    """A response cannot be scanned completely or redacted without ambiguity."""


def map_response_text(
    response: ToolCallResponse, transform: Callable[[str], str]
) -> ToolCallResponse:
    """Walk content, structured output and extension fields without losing their shape.

    Numbers retain their type unless redacted (e.g. a numeric credit card). Object
    keys are scanned too. Refuse excessive nesting or redacted-key collisions
    instead of returning an incompletely scanned result.
    """
    roots: list[Any] = [response.content, response.structured_content, response.extra_fields]
    stack: list[tuple[Any, int, frozenset[int]]] = [(roots, 0, frozenset())]
    while stack:
        container, depth, ancestors = stack.pop()
        if depth > 100 or id(container) in ancestors:
            raise ResponseContentError("Response nesting is too deep or cyclic")
        ancestors = ancestors | {id(container)}
        entries = (
            list(container.items()) if isinstance(container, dict) else list(enumerate(container))
        )
        if isinstance(container, dict):
            container.clear()
        for key, value in entries:
            if isinstance(key, str):
                key = transform(key)
                if key in container:
                    raise ResponseContentError("Redaction would create duplicate object keys")
            if isinstance(value, str):
                value = transform(value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                text = str(value)
                redacted = transform(text)
                if redacted != text:
                    value = redacted
            elif isinstance(value, (list, dict)):
                stack.append((value, depth + 1, ancestors))
            container[key] = value
    return response
