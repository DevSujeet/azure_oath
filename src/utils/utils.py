from contextlib import contextmanager
import time


@contextmanager
def timer():
    '''
    usage:
    to print time taken by a process. 
    with timer()
        total = sum(range(10_000_000))
        print(f"sum computed: {total}")
    '''
    start = time.time()
    yield
    end = time.time()
    print(f"elaspsed time = {end - start:.2f} seconds")

