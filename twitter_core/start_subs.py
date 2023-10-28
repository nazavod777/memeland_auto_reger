import asyncio
from copy import deepcopy
from random import randint
from sys import platform

import aiohttp
import better_automation.twitter.api
import better_automation.twitter.errors
from better_automation import TwitterAPI
from better_proxy import Proxy

import config
from core import SolveCaptcha
from utils import get_connector, logger

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class StartSubs:
    def __init__(self,
                 account_data: dict):
        self.twitter_client: better_automation.twitter.api.TwitterAPI | None = None

        self.target_account_token: str = account_data['target_account_token']
        self.account_list: list = account_data['accounts_list']
        self.proxies_list = account_data['proxies_list']
        self.subs_count: int = account_data['subs_count']

        self.current_account_proxy: str | None = None

        if self.target_account_token in self.account_list:
            self.account_list.remove(self.target_account_token)

    async def get_account_username(self) -> str:
        while True:
            try:
                account_username: str = await self.twitter_client.request_username()

            except better_automation.twitter.errors.Forbidden as error:
                if 326 in error.api_codes:
                    logger.info(f'{self.target_account_token} | Обнаружена капча на аккаунте, пробую решить')

                    SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                 ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.current_account_proxy).as_url if self.current_account_proxy else None)
                    continue

                raise better_automation.twitter.errors.Forbidden(error.response)

            else:
                return account_username

    async def subscribe_account(self,
                                target_username: str) -> None:
        i: int = 0
        local_accounts_list: list = deepcopy(self.account_list)

        while i < self.subs_count:
            if not local_accounts_list:
                logger.error(f'{self.target_account_token} | Аккаунты закончились')
                return

            random_token: None = None

            try:
                random_token: str = local_accounts_list.pop(randint(0, len(local_accounts_list) - 1))
                temp_twitter_proxy: str | None = next(self.proxies_list) if self.proxies_list else None

                async with aiohttp.ClientSession(
                        connector=await get_connector(
                            proxy=temp_twitter_proxy if temp_twitter_proxy else await get_connector(
                                proxy=None))) as aiohttp_twitter_session:

                    temp_twitter_client: better_automation.twitter.api.TwitterAPI = TwitterAPI(
                        session=aiohttp_twitter_session,
                        auth_token=random_token)

                    if config.CHANGE_PROXY_URL:
                        async with aiohttp.ClientSession() as change_proxy_session:
                            async with change_proxy_session.get(url=config.CHANGE_PROXY_URL) as r:
                                logger.info(
                                    f'{temp_twitter_client.auth_token} | Успешно сменил Proxy, статус: {r.status}')

                        if config.SLEEP_AFTER_PROXY_CHANGING:
                            logger.info(f'{temp_twitter_client.auth_token} | Сплю {config.SLEEP_AFTER_PROXY_CHANGING} '
                                        f'сек. после смены Proxy')
                            await asyncio.sleep(delay=config.SLEEP_AFTER_PROXY_CHANGING)

                    if not self.twitter_client.ct0:
                        self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

                    while True:
                        try:
                            await temp_twitter_client.follow(
                                user_id=await temp_twitter_client.request_user_id(username=target_username))

                        except better_automation.twitter.errors.Forbidden as error:
                            if 326 in error.api_codes:
                                logger.info(
                                    f'{self.target_account_token} | Обнаружена капча на аккаунте, пробую решить')

                                SolveCaptcha(auth_token=temp_twitter_client.auth_token,
                                             ct0=temp_twitter_client.ct0).solve_captcha(
                                    proxy=Proxy.from_str(
                                        proxy=temp_twitter_proxy).as_url if temp_twitter_proxy else None)
                                continue

                            raise better_automation.twitter.errors.Forbidden(error.response)

                        except KeyError as error:
                            if error.args[0] in ['rest_id',
                                                 'user_result_by_screen_name']:
                                logger.error(f'{temp_twitter_client.auth_token} | Не удалось найти пользователя '
                                             f'{target_username}')
                                return

                            else:
                                logger.error(f'{temp_twitter_client.auth_token} | Не удалось подписаться на '
                                             f'{target_username}: {error}')

                        except Exception as error:
                            logger.error(f'{temp_twitter_client.auth_token} | Не удалось подписаться на '
                                         f'{target_username}: {error}')

                        else:
                            logger.success(
                                f'{temp_twitter_client.auth_token} | Успешно подписался на {target_username} '
                                f'| {i + 1}/{self.subs_count}')
                            i += 1
                            break

            except Exception as error:
                logger.error(f'{random_token} | Неизвестная ошибка при подписке на {target_username}: {error} ')

    async def start_subs(self):
        self.current_account_proxy: str | None = next(self.proxies_list) if self.proxies_list else None

        async with aiohttp.ClientSession(
                connector=await get_connector(
                    proxy=self.current_account_proxy) if self.current_account_proxy else await get_connector(
                    proxy=None)) as aiohttp_twitter_session:
            self.twitter_client: better_automation.twitter.api.TwitterAPI = TwitterAPI(
                session=aiohttp_twitter_session,
                auth_token=self.target_account_token)

            if not self.twitter_client.ct0:
                self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

            account_username: str = await self.get_account_username()

        await self.subscribe_account(target_username=account_username)


def start_subs(account_data: dict) -> None:
    try:
        asyncio.run(StartSubs(account_data=account_data).start_subs())

    except Exception as error:
        logger.error(f'{account_data["target_account_token"]} | Неизвестная ошибка при обработке аккаунта: {error}')
