import asyncio
import traceback
from random import choice
from sys import platform

import aiofiles
import aiohttp
import better_automation.twitter.api
import better_automation.twitter.errors
from better_automation import TwitterAPI
from better_proxy import Proxy
from bs4 import BeautifulSoup

import config
from core import SolveCaptcha
from utils import get_connector, logger

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class SayGM:
    def __init__(self,
                 account_data: dict):
        self.twitter_client: better_automation.twitter.api.TwitterAPI | None = None

        self.account_token: str = account_data['account_token']
        self.account_proxy: str | None = account_data['account_proxy']

    async def check_captcha(self) -> bool:
        async with aiohttp.ClientSession(
                connector=await get_connector(
                    proxy=self.account_proxy) if self.account_proxy else await get_connector(
                    proxy=None),
                headers={
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,'
                              '*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7,cy;q=0.6',
                    'referer': 'https://twitter.com/home',
                    'user-agent': choice([
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/112.0.0.0 Safari/537.36',
                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/116.0.5845.962 YaBrowser/23.9.1.962 Yowser/2.5 Safari/537.36'
                    ])
                },
                cookies={
                    'auth_token': self.account_token
                }) as aiohttp_temp_twitter_session:
            async with aiohttp_temp_twitter_session.get(url='https://twitter.com/account/access') as r:
                elements = BeautifulSoup(await r.text(), 'lxml').find_all('input', {'type': 'submit',
                                                                                    'class': 'Button EdgeButton '
                                                                                             'EdgeButton--primary'}) \
                           + BeautifulSoup(await r.text(), 'lxml').find_all('iframe', {
                    'id': 'arkose_iframe'
                })

        if elements:
            return True

        return False

    async def say_gm(self) -> bool:
        random_tweet_text: str = choice(config.GM_PHRASES_LIST)

        while True:
            try:
                async with aiohttp.ClientSession(
                        connector=await get_connector(
                            proxy=self.account_proxy) if self.account_token else await get_connector(
                            proxy=None)) as aiohttp_twitter_session:
                    self.twitter_client: better_automation.twitter.api.TwitterAPI = TwitterAPI(
                        session=aiohttp_twitter_session,
                        auth_token=self.account_token)

                    if not self.twitter_client.ct0:
                        # noinspection PyProtectedMember
                        self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

                    _ = await self.twitter_client.reply(tweet_id=1718788079413244315,
                                                        text=random_tweet_text)

            except better_automation.twitter.errors.Forbidden as error:
                if 'This account is suspended.' in await error.response.text():
                    async with aiofiles.open('suspended_accounts.txt', 'a', encoding='utf-8-sig') as f:
                        await f.write(f'{self.account_token}\n')

                    logger.error(f'{self.account_token} | Account Suspended')

                async with aiofiles.open(file='forbidden_accounts.txt', mode='a', encoding='utf-8-sig') as f:
                    await f.write(f'{self.account_token}\n')

                logger.error(f'{self.account_token} | Forbidden Twitter, статус: {error.response.status}')
                return False

            except better_automation.twitter.errors.Unauthorized:
                if await self.check_captcha():
                    logger.info(
                        f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')

                    await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                       ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.account_proxy).as_url if self.account_proxy else None)
                    continue

                async with aiofiles.open(file='unauthorized_accounts.txt', mode='a', encoding='utf-8-sig') as f:
                    await f.write(f'{self.account_token}\n')

                logger.error(f'{self.account_token} | Unauthorized')
                return False

            except better_automation.twitter.errors.HTTPException as error:
                if 326 in error.api_codes:
                    logger.info(
                        f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')

                    await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                       ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.account_proxy).as_url if self.account_proxy else None)
                    continue

                async with aiofiles.open(file='http_exceptions.txt', mode='a', encoding='utf-8-sig') as f:
                    await f.write(f'{self.account_token}\n')

                logger.error(f'{self.account_token} | {await error.response.text()}')
                return False

            except Exception as error:
                logger.error(f'{self.account_token} | Ошибка при отправке комментария: {error}')
                print(traceback.print_exc())

                async with aiofiles.open(file='unexpected_errors.txt', mode='a', encoding='utf-8-sig') as f:
                    await f.write(f'{self.account_token}\n')

                return False

            else:
                logger.success(f'{self.account_token} | Успешно отправлен комментарий: {random_tweet_text}')
                return True


def say_gm(account_data: dict) -> bool:
    try:
        return asyncio.run(SayGM(account_data=account_data).say_gm())

    except Exception as error:
        logger.error(f'{account_data["account_token"]} | Неизвестная ошибка при обработке аккаунта: {error}')
        print(traceback.print_exc())
