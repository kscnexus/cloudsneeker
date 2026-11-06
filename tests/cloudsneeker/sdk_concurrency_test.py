import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from cloudsneeker.sdk_concurrency import iter_bounded


def test_yields_every_item_with_its_result():
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = {
            item: future.result()
            for item, future in iter_bounded(pool, lambda n: n * n, range(20))
        }
    assert results == {n: n * n for n in range(20)}


def test_keeps_at_most_max_in_flight_tasks_pending():
    lock = threading.Lock()
    submitted = 0
    consumed = 0
    worst = 0

    def work(item):
        nonlocal submitted, worst
        with lock:
            submitted += 1
            worst = max(worst, submitted - consumed)
        return item

    with ThreadPoolExecutor(max_workers=10) as pool:
        for _, future in iter_bounded(pool, work, range(50), max_in_flight=3):
            future.result()
            with lock:
                consumed += 1
    assert consumed == 50
    assert worst <= 3


def test_reads_items_lazily():
    pulled = []

    def items():
        for n in range(100):
            pulled.append(n)
            yield n

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = next(iter_bounded(pool, lambda n: n, items(), max_in_flight=2))
        first[1].result()
    assert len(pulled) <= 3


def test_task_errors_surface_from_the_future():
    def fail(_):
        raise ValueError("download failed")

    with ThreadPoolExecutor(max_workers=1) as pool:
        ((_, future),) = list(iter_bounded(pool, fail, [1]))
    with pytest.raises(ValueError):
        future.result()
