import re
from random import randint


def format_range(value: str | int,
                 return_randint: bool = False) -> tuple[int, int] | int:
    if str(value).isdigit():
        if return_randint:
            result: int = randint(a=int(value),
                                  b=int(value))

        else:
            result: tuple = int(value), int(value)

    elif re.match(pattern=r'^\d+-\d+$',
                  string=value):
        target_digits: list = list(map(int, value.split('-')))

        if return_randint:
            result: int = randint(a=min(target_digits),
                                  b=max(target_digits))

        else:
            result: tuple = min(target_digits), max(target_digits)

    else:
        if return_randint:
            result: int = 0

        else:
            result: tuple = 0, 0

    return result
