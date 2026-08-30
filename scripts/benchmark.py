"""Simple asyncio benchmark for concurrent request-style work.

This script models the kind of `asyncio.gather` fan-out used by scanners and
helpers, and prints throughput metrics for comparison across iterations.
"""

from __future__ import annotations

import asyncio
import time
from statistics import mean


async def simulate_request(request_id: int, delay: float = 0.05) -> dict:
    await asyncio.sleep(delay)
    return {"id": request_id, "status": "ok"}


async def run_benchmark(total_requests: int = 200, concurrency: int = 20) -> float:
    semaphore = asyncio.Semaphore(concurrency)

    async def worker(request_id: int) -> dict:
        async with semaphore:
            return await simulate_request(request_id)

    start = time.perf_counter()
    results = await asyncio.gather(*(worker(i) for i in range(total_requests)))
    elapsed = time.perf_counter() - start
    if not results:
        return 0.0
    return elapsed


async def main() -> None:
    scenarios = [
        (100, 10),
        (200, 20),
        (400, 40),
    ]
    print("Asyncio benchmark: concurrent request simulation")
    print("=" * 60)

    timings = []
    for total, concurrency in scenarios:
        elapsed = await run_benchmark(total_requests=total, concurrency=concurrency)
        timings.append((total, concurrency, elapsed))
        print(f"requests={total:>3} concurrency={concurrency:>2} elapsed={elapsed:.3f}s rps={total / elapsed:.2f}")

    avg = mean(duration for _, _, duration in timings)
    print("=" * 60)
    print(f"average_elapsed={avg:.3f}s")


if __name__ == "__main__":
    asyncio.run(main())
