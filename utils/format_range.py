import re
from random import randint


def format_range(value: str | int,
                 return_randint: bool = False) -> tuple[int, int] | int:
    if value.isdigit():
        return randint(a=int(value),
                       b=int(value)) if return_randint else int(value), int(value)

    elif re.match(pattern=r'^\d+-\d+$',
                  string=value):
        target_digits: list = list(map(int, value.split('-')))

        return randint(a=min(target_digits),
                       b=max(target_digits)) if return_randint else min(target_digits), max(target_digits)

    return 0, 0
