from multiprocessing.dummy import Pool
from random import choice, randint
from sys import exit

import config
from core import start_reger_wrapper
from twitter_core import start_subs
from utils import logger

if __name__ == '__main__':
    print('Donate (any EVM) - 0xDEADf12DE9A24b47Da0a43E1bA70B8972F5296F2\n')

    with open('accounts.txt', 'r', encoding='utf-8-sig') as file:
        accounts_list: list[str] = [row.strip() for row in file]

    with open('proxies.txt', 'r', encoding='utf-8-sig') as file:
        proxies_list: list[str] = [row.strip() for row in file]

    with open('private_keys.txt', 'r', encoding='utf-8-sig') as file:
        private_keys_list: list[str] = [f'0x{row.strip()}' if not row.strip().startswith('0x') else row.strip() for row
                                        in file]

    logger.info(f'Загружено {len(accounts_list)} аккаунтов / {len(proxies_list)} '
                f'прокси / {len(private_keys_list)} приват-кеев')

    user_action: int = int(input('1. Запуск накрутки MEMELand\n'
                                 '2. Подписка между аккаунтами Twitter\n'
                                 'Введите ваше действие: '))

    if config.CHANGE_PROXY_URL:
        threads: int = 1

    else:
        threads: int = int(input('\nThreads: '))

    if user_action == 1:
        print()

        formatted_accounts_list: list = [
            {
                'account_token': current_account,
                'account_proxy': choice(proxies_list) if proxies_list else None,
                'account_private_key': private_keys_list.pop() if private_keys_list else None
            } for current_account in accounts_list
        ]

        with Pool(processes=threads) as executor:
            executor.map(start_reger_wrapper, formatted_accounts_list)

    elif user_action == 2:
        subs_range: str = input('Введите диапазон необходимого количества подписок (ex: 3-5, 4-10): ')
        first_int_subs_range: int = int(subs_range.split('-')[0])
        second_int_subs_range: int = int(subs_range.split('-')[1])

        if second_int_subs_range > len(accounts_list):
            second_int_subs_range: int = len(accounts_list)

        if first_int_subs_range > second_int_subs_range:
            logger.error('Неверно введен диапазон количества подписок')
            input('\nPress Enter To Exit..')
            exit()

        print()

        formatted_accounts_list: list = [
            {
                'target_account_token': current_account,
                'accounts_list': accounts_list,
                'proxies_list': proxies_list,
                'subs_count': randint(first_int_subs_range, second_int_subs_range)
            } for current_account in accounts_list
        ]

        with Pool(processes=threads) as executor:
            executor.map(start_subs, formatted_accounts_list)

    logger.success('Работа успешно завершена')
    input('\nPress Enter To Exit..')
