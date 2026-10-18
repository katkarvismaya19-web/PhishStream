"""Reservoir sampling (Algorithm R): uniform sample of size k from an unbounded stream."""
import random


class Reservoir:
    def __init__(self, k: int = 50, seed: int | None = None):
        self.k, self.n, self.items = k, 0, []
        self.rng = random.Random(seed)

    def add(self, item):
        self.n += 1
        if len(self.items) < self.k:
            self.items.append(item)
        else:
            j = self.rng.randrange(self.n)
            if j < self.k:
                self.items[j] = item
