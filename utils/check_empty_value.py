def check_empty_value(value: any,
                      account_token: str) -> bool:
    if not value:
        with open('errors.txt', 'a', encoding='utf-8-sig') as file:
            file.write(f'{account_token}\n')

        return False

    return True
