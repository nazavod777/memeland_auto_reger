from hashlib import md5
from random import choice
from string import digits
from time import time


def generate_random_number(length: int) -> int:
    return int(''.join([choice(digits) for _ in range(length)]))


def generate_csrf_token() -> str:
    random_int: int = generate_random_number(length=3)
    current_timestamp: int = int(str(int(time())) + str(random_int))
    random_csrf_token = md5(string=f'{current_timestamp}:{current_timestamp},{0}:{0}'.encode()).hexdigest()

    return random_csrf_token
