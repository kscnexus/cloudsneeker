"""Bounded thread-pool fetches for SDK hooks.

Upstream services that download large payloads (Lambda function and layer
code) submit every download at once and keep each finished future, so a big
account holds all of its code in memory until the last download ends. One AWS
scan reached 13.7 GB and was killed by the kernel. :func:`iter_bounded` keeps
only a few downloads in flight and drops each future once it is yielded, so
memory stays at a few payloads however many there are.

Imports only the standard library.
"""

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Executor, Future, wait
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")

MAX_IN_FLIGHT = 8


def iter_bounded(
    executor: Executor,
    fn: Callable[[T], R],
    items: Iterable[T],
    max_in_flight: int = MAX_IN_FLIGHT,
) -> Iterator[tuple[T, Future]]:
    """Run ``fn`` over ``items`` with at most ``max_in_flight`` tasks pending.

    Args:
        executor: Pool that runs ``fn``.
        fn: Called once per item.
        items: Consumed lazily, as slots free up.
        max_in_flight: Most tasks submitted but not yet yielded.

    Yields:
        ``(item, future)`` in completion order. Call ``future.result()`` to get
        the value or re-raise the task's exception. A new task is submitted
        only after the consumer takes the previous results.
    """
    pending: dict[Future, T] = {}
    remaining = iter(items)

    def fill() -> None:
        while len(pending) < max_in_flight:
            try:
                item = next(remaining)
            except StopIteration:
                return
            pending[executor.submit(fn, item)] = item

    fill()
    while pending:
        done, _ = wait(pending, return_when=FIRST_COMPLETED)
        for future in done:
            yield pending.pop(future), future
        del done
        fill()
