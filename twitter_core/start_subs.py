import asyncio
from random import choice, randint

import aiohttp
import better_automation.twitter.api
from aiohttp_proxy import ProxyConnector
from better_automation import TwitterAPI

import config
from utils import logger


class StartSubs:
    def __init__(self,
                 account_data: dict):
        self.twitter_client: better_automation.twitter.api.TwitterAPI | None = None

        self.target_account_token: str = account_data['target_account_token']
        self.account_list: list = account_data['accounts_list']
        self.proxies_list: list | None = account_data['proxies_list']
        self.subs_count: int = account_data['subs_count']

        if self.target_account_token in self.account_list:
            self.account_list.remove(self.target_account_token)

    async def get_account_username(self) -> str:
        account_username: str = await self.twitter_client.request_username()
        return account_username

    async def subscribe_account(self,
                                target_username: str) -> None:
        i: int = 0

        while i < self.subs_count <= len(self.account_list):
            async with aiohttp.ClientSession(
                    connector=ProxyConnector.from_url(
                        url=choice(self.proxies_list)) if self.proxies_list else None) as aiohttp_twitter_session:

                temp_twitter_client: better_automation.twitter.api.TwitterAPI = TwitterAPI(
                    session=aiohttp_twitter_session,
                    auth_token=self.account_list.pop(randint(0, len(self.account_list) - 1)))

                if config.CHANGE_PROXY_URL:
                    async with aiohttp.ClientSession() as change_proxy_session:
                        async with change_proxy_session.get(url=config.CHANGE_PROXY_URL) as r:
                            logger.info(
                                f'{temp_twitter_client.auth_token} | Успешно сменил Proxy, ответ: {await r.text()}')

                    if config.SLEEP_AFTER_PROXY_CHANGING:
                        logger.info(f'{temp_twitter_client.auth_token} | Сплю {config.SLEEP_AFTER_PROXY_CHANGING} '
                                    f'сек. после смены Proxy')
                        await asyncio.sleep(delay=config.SLEEP_AFTER_PROXY_CHANGING)

                try:
                    await temp_twitter_client.follow(
                        user_id=await temp_twitter_client.request_user_id(username=target_username))

                except Exception as error:
                    logger.error(f'{temp_twitter_client.auth_token} | Не удалось подписаться на '
                                 f'{target_username}: {error}')

                else:
                    logger.success(f'{temp_twitter_client.auth_token} | Успешно подписался на {target_username} '
                                   f'| {i + 1}/{self.subs_count}')
                    i += 1

    async def start_subs(self):
        async with aiohttp.ClientSession(
                connector=ProxyConnector.from_url(
                    url=choice(self.proxies_list)) if self.proxies_list else None) as aiohttp_twitter_session:
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