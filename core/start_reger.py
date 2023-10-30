import asyncio
from base64 import b64decode
from random import choice
from sys import platform
from time import sleep
from urllib.parse import parse_qs, urlparse

import aiofiles
import aiohttp
import aiohttp.client
import better_automation.twitter.api
import better_automation.twitter.errors
import eth_account.signers.local
import requests
import tls_client.sessions
from aiohttp.client_reqrep import ClientResponse
from better_automation import TwitterAPI
from better_proxy import Proxy
from bs4 import BeautifulSoup
from eth_account.messages import encode_defunct
from tls_client.response import Response
from web3.auto import w3

import config
from exceptions import AccountSuspended
from utils import format_range
from utils import generate_eth_account, get_account
from utils import get_connector
from utils import logger
from .get_session import get_meme_session
from .solve_captcha import SolveCaptcha

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class Reger:
    def __init__(self,
                 source_data: dict) -> None:
        self.account_token: str = source_data['account_token']
        self.account_proxy: str | None = source_data['account_proxy']
        self.account_private_key: str | None = source_data['account_private_key']

        self.twitter_client: better_automation.twitter.api.TwitterAPI | None = None
        self.meme_client: tls_client.sessions.Session | None = None
        self.unauthorized_attempts: int = 1

    def get_tasks(self) -> dict:
        r = self.meme_client.get(url='https://memefarm-api.memecoin.org/user/tasks',
                                 headers={
                                     **self.meme_client.headers,
                                     'content-type': None
                                 })

        return r.json()

    def get_twitter_account_names(self) -> tuple[str, str]:
        r = self.meme_client.get(url='https://memefarm-api.memecoin.org/user/info',
                                 headers={
                                     **self.meme_client.headers,
                                     'content-type': None
                                 })

        return r.json()['twitter']['username'], r.json()['twitter']['name']

    def link_wallet_request(self,
                            address: str,
                            sign: str,
                            message: str) -> tuple[bool, str, int]:
        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/link-wallet',
                                      json={
                                          'address': address,
                                          'delegate': address,
                                          'message': message,
                                          'signature': sign
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                logger.error(f'{self.account_token} | Unauthorized')
                # noinspection PyTypeHints
                r.status: int = r.status_code
                # noinspection PyTypeHints
                r.reason: str = ''
                raise better_automation.twitter.errors.Unauthorized(r)

            return r.json()['status'] == 'success', r.text, r.status_code

    def link_wallet(self,
                    account: eth_account.signers.local.LocalAccount,
                    twitter_username: str) -> tuple[bool, str, int]:
        message_to_sign: str = f'This wallet willl be dropped $MEME from your harvested MEMEPOINTS. ' \
                               'If you referred friends, family, lovers or strangers, ' \
                               'ensure this wallet has the NFT you referred.\n\n' \
                               'But also...\n\n' \
                               'Never gonna give you up\n' \
                               'Never gonna let you down\n' \
                               'Never gonna run around and desert you\n' \
                               'Never gonna make you cry\n' \
                               'Never gonna say goodbye\n' \
                               'Never gonna tell a lie and hurt you", "\n\n' \
                               f'Wallet: {account.address[:5]}...{account.address[-4:]}\n' \
                               f'X account: @{twitter_username}'

        sign = w3.eth.account.sign_message(encode_defunct(text=message_to_sign),
                                           private_key=account.key).signature.hex()

        return self.link_wallet_request(address=account.address,
                                        sign=sign,
                                        message=message_to_sign)

    async def change_twitter_name(self,
                                  twitter_account_name: str) -> tuple[bool, str, int]:
        r = await self.twitter_client.request(url='https://api.twitter.com/1.1/account/update_profile.json',
                                              method='post',
                                              params={
                                                  'name': f'{twitter_account_name} ❤️ Memecoin'
                                              })

        if 'This account is suspended' in await r[0].text():
            raise AccountSuspended(self.account_token)

        if r[0].status == 200:
            return True, await r[0].text(), r[0].status

        return False, await r[0].text(), r[0].status

    async def twitter_name(self,
                           twitter_account_name: str) -> tuple[bool, str, int]:
        if '❤️ Memecoin' not in twitter_account_name:
            change_twitter_name_result, response_text, response_status = await self.change_twitter_name(
                twitter_account_name=twitter_account_name)

            if not change_twitter_name_result:
                logger.error(f'{self.account_token} | Не удалось изменить имя пользователя')
                return False, response_text, response_status

        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/twitter-name',
                                      headers={
                                          **self.meme_client.headers,
                                          'content-type': None
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                # noinspection PyTypeHints
                r.status: int = r.status_code
                # noinspection PyTypeHints
                r.reason: str = ''
                raise better_automation.twitter.errors.Unauthorized(r)

            return r.json()['status'] == 'success', r.text, r.status_code

    async def create_tweet(self,
                           share_message: str) -> tuple[bool, str]:
        r = await self.twitter_client.tweet(
            text=share_message)

        return True, str(r)

    async def share_message(self,
                            share_message: str,
                            verify_url: str) -> tuple[bool, str, int]:
        while True:
            try:
                create_tweet_status, tweet_id = await self.create_tweet(share_message=share_message)

            except better_automation.twitter.errors.HTTPException as error:
                if 187 in error.api_codes:
                    pass

                elif 326 in error.api_codes:
                    logger.info(
                        f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')

                    await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                       ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.account_proxy).as_url if self.account_proxy else None)
                    continue

                else:
                    raise better_automation.twitter.errors.HTTPException(error.response)

            else:
                if not create_tweet_status:
                    return False, tweet_id, 0

                break

        while True:
            r = self.meme_client.post(url=verify_url,
                                      headers={
                                          **self.meme_client.headers,
                                          'content-type': None
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                # noinspection PyTypeHints
                r.status: int = r.status_code
                # noinspection PyTypeHints
                r.reason: str = ''
                raise better_automation.twitter.errors.Unauthorized(r)

            return r.json()['status'] == 'success', r.text, r.status_code

    def invite_code(self) -> tuple[bool, str]:
        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/invite-code',
                                      json={
                                          'code': b64decode('cG90YXRveiM1MDUy').decode()
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                # noinspection PyTypeHints
                r.status: int = r.status_code
                # noinspection PyTypeHints
                r.reason: str = ''
                raise better_automation.twitter.errors.Unauthorized(r)

            return r.json()['status'] == 'success', r.text

    async def follow_quest(self,
                           username: str,
                           follow_id: str):
        await self.twitter_client.follow(user_id=await self.twitter_client.request_user_id(username=username))

        r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/twitter-follow',
                                  json={
                                      'followId': follow_id
                                  })

        return r.json()['status'] == 'success', r.text

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

    async def get_oauth_auth_tokens(self) -> tuple[str | None, str | None, str | None, ClientResponse]:
        while True:
            # noinspection PyProtectedMember
            headers: dict = self.twitter_client._headers

            if headers.get('content-type'):
                del headers['content-type']
            headers[
                'accept'] = ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,'
                             '*/*;q=0.8,application/signed-exchange;v=b3;q=0.7')

            if not self.twitter_client.ct0:
                # noinspection PyProtectedMember
                self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

            while True:
                try:
                    r = await self.twitter_client.request(url='https://memefarm-api.memecoin.org/user/twitter-auth',
                                                          method='get',
                                                          params={
                                                              'callback': 'https://www.memecoin.org/farming'
                                                          },
                                                          headers=headers)
                except better_automation.twitter.errors.BadRequest as error:
                    logger.error(f'{self.account_token} | BadRequest: {error}, пробую еще раз')
                else:
                    break
            if BeautifulSoup(await r[0].text(), 'lxml').find('iframe', {
                'id': 'arkose_iframe'
            }):
                logger.info(f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')
                await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                   ct0=self.twitter_client.ct0).solve_captcha(
                    proxy=Proxy.from_str(proxy=self.account_proxy).as_url if self.account_proxy else None)
                continue

            if 'https://www.memecoin.org/farming?oauth_token=' in (await r[0].text()):
                return 'https://www.memecoin.org/farming?oauth_token=' + \
                       (await r[0].text()).split('https://www.memecoin.org/farming?oauth_token=')[-1].split('"')[
                           0].replace('&amp;', '&'), None, None, r[0]

            auth_token_html = BeautifulSoup(await r[0].text(), 'lxml').find('input', {
                'name': 'authenticity_token'
            })
            oauth_token_html = BeautifulSoup(await r[0].text(), 'lxml').find('input', {
                'name': 'oauth_token'
            })

            if not auth_token_html or not oauth_token_html:
                logger.error(f'{self.account_token} | Не удалось обнаружить Auth/OAuth Token на странице, '
                             f'статус: {r[0].status}')
                return None, None, None, r[0]

            auth_token: str = auth_token_html.get('value', '')
            oauth_token: str = oauth_token_html.get('value', '')
            return None, auth_token, oauth_token, r[0]

    async def get_auth_location(self,
                                oauth_token: str,
                                auth_token: str) -> tuple[str | bool, str]:
        while True:
            if not self.twitter_client.ct0:
                # noinspection PyProtectedMember
                self.twitter_client.set_ct0(await self.twitter_client._request_ct0())
            # noinspection PyProtectedMember
            r = await self.twitter_client.request(url='https://api.twitter.com/oauth/authorize',
                                                  method='post',
                                                  data={
                                                      'authenticity_token': auth_token,
                                                      'redirect_after_login': f'https://api.twitter.com/oauth'
                                                                              f'/authorize?oauth_token={oauth_token}',
                                                      'oauth_token': oauth_token
                                                  },
                                                  headers={
                                                      **self.twitter_client._headers,
                                                      'content-type': 'application/x-www-form-urlencoded'
                                                  })
            if 'This account is suspended' in await r[0].text():
                raise AccountSuspended(self.account_token)

            if 'https://www.memecoin.org/farming?oauth_token=' in await r[0].text():
                location: str = 'https://www.memecoin.org/farming?oauth_token=' + \
                                (await r[0].text()).split('https://www.memecoin.org/farming?oauth_token=')[-1].split(
                                    '"')[0].replace('&amp;', '&')
                return location, await r[0].text()
            return False, await r[0].text()

    async def make_old_auth(self,
                            oauth_token: str,
                            oauth_verifier: str) -> tuple[int, str, Response | ClientResponse]:
        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/twitter-auth1',
                                      json={
                                          'oauth_token': oauth_token,
                                          'oauth_verifier': oauth_verifier
                                      })

            if r.json().get('error', '') == 'account_too_new':
                return 1, '', r

            elif r.json().get('error', '') == 'Unknown Error':
                if await self.check_captcha():
                    logger.info(
                        f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')

                    await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                       ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.account_proxy).as_url if self.account_proxy else None)
                    continue

                if r.json().get('status', 0) and r.json()['status'] == 429:
                    logger.error(f'{self.account_token} | Неизвестный ответ при авторизации MEME: {r.text}')
                    await asyncio.sleep(delay=5)
                    continue

                return 2, '', r

            elif r.json().get('error', '') in ['unauthorized',
                                               'Unauthorized']:
                # noinspection PyTypeHints
                r.status: int = r.status_code
                # noinspection PyTypeHints
                r.reason: str = ''
                raise better_automation.twitter.errors.Unauthorized(r)

            elif r.json().get('accessToken', ''):
                return 0, r.json()['accessToken'], r

            return 2, '', r

    async def request_access_token_old(self) -> tuple[int | None, str | None, ClientResponse | None]:
        location, auth_token, oauth_token, r = await self.get_oauth_auth_tokens()

        if not location:
            if not auth_token \
                    or not oauth_token:
                logger.error(
                    f'{self.account_token} | Ошибка при получении OAuth / Auth Token, '
                    f'статус: {r.status}')
                return None, None, r
            location, response_text = await self.get_auth_location(oauth_token=oauth_token,
                                                                   auth_token=auth_token)
            if not location:
                logger.error(
                    f'{self.account_token} | Ошибка при авторизации через Twitter, '
                    f'статус: {r.status}')
                return None, None, r

        if parse_qs(urlparse(location).query).get('redirect_after_login') \
                or not parse_qs(urlparse(location).query).get('oauth_token') \
                or not parse_qs(urlparse(location).query).get('oauth_verifier'):
            logger.error(
                f'{self.account_token} | Не удалось обнаружить OAuth Token / OAuth Verifier в '
                f'ссылке: {location}')
            return None, None, r

        oauth_token: str = parse_qs(urlparse(location).query)['oauth_token'][0]
        oauth_verifier: str = parse_qs(urlparse(location).query)['oauth_verifier'][0]

        return await self.make_old_auth(oauth_token=oauth_token,
                                        oauth_verifier=oauth_verifier)

    async def request_access_token(self, bind_code: str) -> tuple[int, str, Response | ClientResponse]:
        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/twitter-auth',
                                      json={
                                          "code": bind_code,
                                          "redirectUri": "https://www.memecoin.org/farming"
                                      })

            if r.json().get('error', '') == 'account_too_new':
                return 1, '', r

            elif r.json().get('error', '') == 'Unknown Error':
                if await self.check_captcha():
                    logger.info(
                        f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')

                    await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                       ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.account_proxy).as_url if self.account_proxy else None)
                    continue

                logger.error(f'{self.account_token} | Неизвестный ответ при авторизации MEME: {r.text}, пробую '
                             f'авторизоваться старым способом')
                status, access_token, r = await self.request_access_token_old()

                if status == 1:
                    return 1, '', r

                elif status == 2:
                    logger.error(f'{self.account_token} | Неизвестный ответ при авторизации MEME: {r.text}')
                    continue

                continue

            elif r.json().get('error', '') in ['unauthorized',
                                               'Unauthorized']:
                # noinspection PyTypeHints
                r.status: int = r.status_code
                # noinspection PyTypeHints
                r.reason: str = ''
                raise better_automation.twitter.errors.Unauthorized(r)

            elif r.json().get('accessToken', ''):
                return 0, r.json()['accessToken'], r

            return 2, '', r

    async def start_reger(self) -> bool:
        for _ in range(config.REPEATS_ATTEMPTS):
            try:
                async with aiohttp.ClientSession(
                        connector=await get_connector(
                            proxy=self.account_proxy) if self.account_proxy else await get_connector(
                            proxy=None)) as aiohttp_twitter_session:
                    self.meme_client: tls_client.sessions.Session = get_meme_session(account_proxy=self.account_proxy)

                    self.twitter_client: better_automation.twitter.api.TwitterAPI = TwitterAPI(
                        session=aiohttp_twitter_session,
                        auth_token=self.account_token)

                    if not self.twitter_client.ct0:
                        # noinspection PyProtectedMember
                        self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

                    bind_data = {
                        'response_type': 'code',
                        'client_id': 'ZXh0SU5iS1pwTE5xclJtaVNNSjk6MTpjaQ',
                        'redirect_uri': 'https://www.memecoin.org/farming',
                        'scope': 'users.read tweet.read offline.access',
                        'state': 'state',
                        'code_challenge': 'challenge',
                        'code_challenge_method': 'plain'
                    }

                    bind_code: str = await self.twitter_client.bind_app(**bind_data)
                    status, access_token, r = await self.request_access_token(bind_code=bind_code)

                    if status == 1:
                        logger.error(f'{self.account_token} | Account Too New')

                        async with aiofiles.open('account_too_new.txt', 'a', encoding='utf-8-sig') as f:
                            await f.write(f'{self.account_token}\n')

                        return False

                    elif status == 2:
                        logger.error(f'{self.account_token} | Неизвестный ответ при авторизации MEME: '
                                     f'{r.text if type(r) == Response else await r.text()}')
                        continue

                    self.meme_client.headers.update({
                        'authorization': f'Bearer {access_token}'
                    })

                    account: eth_account.signers.local.LocalAccount = get_account(
                        private_key=self.account_private_key) if self.account_private_key else generate_eth_account()

                    tasks_dict: dict = self.get_tasks()
                    twitter_username, twitter_account_name = self.get_twitter_account_names()
                    all_tasks: list = tasks_dict['tasks'] + tasks_dict['timely']

                    if len(all_tasks) - sum([current_task['completed'] for current_task in all_tasks]) < 1:
                        logger.info(f'{self.account_token} | Все задания успешно выполнены')
                        return True

                    for current_task in tasks_dict['tasks'] + tasks_dict['timely']:
                        if current_task['completed']:
                            continue

                        match current_task['id']:
                            case 'connect':
                                continue

                            case 'linkWallet':
                                link_wallet_result, response_text, response_status = self.link_wallet(account=account,
                                                                                                      twitter_username=twitter_username)

                                if link_wallet_result:
                                    logger.success(f'{self.account_token} | Успешно привязал кошелек')

                                    async with aiofiles.open(file='registered.txt', mode='a',
                                                             encoding='utf-8-sig') as f:
                                        await f.write(
                                            f'{self.account_token};{self.account_proxy if self.account_proxy else ""};'
                                            f'{account.key.hex()}\n')

                                    if config.SLEEP_BETWEEN_TASKS and current_task != \
                                            (tasks_dict['tasks'] + tasks_dict['timely'])[-1]:
                                        time_to_sleep: int = format_range(value=config.SLEEP_BETWEEN_TASKS,
                                                                          return_randint=True)
                                        logger.info(
                                            f'{self.account_token} | Сплю {time_to_sleep} сек. перед '
                                            f'выполнением следующего таска')
                                        await asyncio.sleep(delay=time_to_sleep)

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось привязать кошелек, '
                                        f'статус: {response_status}')

                            case 'twitterName':
                                twitter_username_result, response_text, response_status = await self.twitter_name(
                                    twitter_account_name=twitter_account_name)

                                if twitter_username_result:
                                    logger.success(
                                        f'{self.account_token} | Успешно получил бонус за MEMELAND в никнейме')

                                    if config.SLEEP_BETWEEN_TASKS and current_task != \
                                            (tasks_dict['tasks'] + tasks_dict['timely'])[-1]:
                                        time_to_sleep: int = format_range(value=config.SLEEP_BETWEEN_TASKS,
                                                                          return_randint=True)
                                        logger.info(
                                            f'{self.account_token} | Сплю {time_to_sleep} сек. перед '
                                            f'выполнением следующего таска')
                                        await asyncio.sleep(delay=time_to_sleep)

                                else:
                                    logger.error(f'{self.account_token} | Не удалось получить бонус за MEMELAND в '
                                                 f'никнейме, статус: {response_status}')

                            case 'shareMessage':
                                share_message_result, response_text, response_status = await self.share_message(
                                    share_message=f'Hi, my name is @{twitter_username}, and I’m a $MEME (@Memecoin) '
                                                  f'farmer'
                                                  'at @Memeland.\n\nOn my honor, I promise that I will do my best '
                                                  'to do my duty to my own bag, and to farm #MEMEPOINTS at '
                                                  'all times.\n\nIt ain’t much, but it’s honest work. 🧑‍🌾 ',
                                    verify_url='https://memefarm-api.memecoin.org/user/verify/share-message')

                                if share_message_result:
                                    logger.success(f'{self.account_token} | Успешно получил бонус за твит')

                                    if config.SLEEP_BETWEEN_TASKS and current_task != \
                                            (tasks_dict['tasks'] + tasks_dict['timely'])[-1]:
                                        time_to_sleep: int = format_range(value=config.SLEEP_BETWEEN_TASKS,
                                                                          return_randint=True)
                                        logger.info(
                                            f'{self.account_token} | Сплю {time_to_sleep} сек. перед '
                                            f'выполнением следующего таска')
                                        await asyncio.sleep(delay=time_to_sleep)

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось создать твит, статус: {response_status}')

                            case 'inviteCode':
                                invite_code_result, response_text = self.invite_code()

                                if invite_code_result:
                                    logger.success(f'{self.account_token} | Успешно ввел реф.код')

                                    if config.SLEEP_BETWEEN_TASKS and current_task != \
                                            (tasks_dict['tasks'] + tasks_dict['timely'])[-1]:
                                        time_to_sleep: int = format_range(value=config.SLEEP_BETWEEN_TASKS,
                                                                          return_randint=True)
                                        logger.info(
                                            f'{self.account_token} | Сплю {time_to_sleep} сек. перед '
                                            f'выполнением следующего таска')
                                        await asyncio.sleep(delay=time_to_sleep)

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось ввести реф.код, статус: {r.status_code}')

                            case 'followMemeland' | 'followMemecoin' | 'follow9gagceo' | 'followGMShowofficial':
                                follow_result, response_text = await self.follow_quest(
                                    username=current_task['id'].replace('follow', ''),
                                    follow_id=current_task['id'])

                                if follow_result:
                                    logger.success(
                                        f'{self.account_token} | Успешно подписался на '
                                        f'{current_task["id"].replace("follow", "")}')

                                    if config.SLEEP_BETWEEN_TASKS and current_task != \
                                            (tasks_dict['tasks'] + tasks_dict['timely'])[-1]:
                                        time_to_sleep: int = format_range(value=config.SLEEP_BETWEEN_TASKS,
                                                                          return_randint=True)
                                        logger.info(
                                            f'{self.account_token} | Сплю {time_to_sleep} сек. перед '
                                            f'выполнением следующего таска')
                                        await asyncio.sleep(delay=time_to_sleep)

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось одписаться на '
                                        f'{current_task["id"].replace("follow", "")}: {response_text}')

                            case 'goingToBinance':
                                share_message_result, response_text, response_status = await self.share_message(
                                    share_message='AHOY! $MEME (@MEMECOIN) IS GOING TO @BINANCE! 🙌\n\nThis is not a '
                                                  'drill! This is not fake news! This is happening!\n\n$MEME is the '
                                                  '39th (not 69th) project on Binance Launchpool! You only have 7 days!'
                                                  ' Come join the farming with your fellow Binancians!\n\n👇 '
                                                  'https://www.binance.com/en/support/announcement/'
                                                  '90ccca2c5d6946ef9439dae41a517578',
                                    verify_url='https://memefarm-api.memecoin.org/user/verify/daily-task/goingToBinance')

                                if share_message_result:
                                    logger.success(
                                        f'{self.account_token} | Успешно получил бонус за твит goingToBinance')

                                    if config.SLEEP_BETWEEN_TASKS and current_task != \
                                            (tasks_dict['tasks'] + tasks_dict['timely'])[-1]:
                                        time_to_sleep: int = format_range(value=config.SLEEP_BETWEEN_TASKS,
                                                                          return_randint=True)
                                        logger.info(
                                            f'{self.account_token} | Сплю {time_to_sleep} сек. перед '
                                            f'выполнением следующего таска')
                                        await asyncio.sleep(delay=time_to_sleep)

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось создать твит, статус: {response_status}')

            except better_automation.twitter.errors.Forbidden as error:
                if 'This account is suspended.' in await error.response.text():
                    async with aiofiles.open('suspended_accounts.txt', 'a', encoding='utf-8-sig') as f:
                        await f.write(f'{self.account_token}\n')

                    logger.error(f'{self.account_token} | Account Suspended')
                    return False

                logger.error(f'{self.account_token} | Forbidden Twitter, статус: {error.response.status}')

            except better_automation.twitter.errors.Unauthorized:
                if await self.check_captcha():
                    logger.info(
                        f'{self.account_token} | Обнаружена капча на аккаунте, пробую решить')

                    await SolveCaptcha(auth_token=self.twitter_client.auth_token,
                                       ct0=self.twitter_client.ct0).solve_captcha(
                        proxy=Proxy.from_str(
                            proxy=self.account_proxy).as_url if self.account_proxy else None)
                    continue

                logger.error(f'{self.account_token} | Unauthorized')

                if self.unauthorized_attempts >= config.UNAUTHORIZED_ATTEMPTS:
                    async with aiofiles.open(file='unauthorized_accounts.txt', mode='a', encoding='utf-8-sig') as f:
                        await f.write(f'{self.account_token}\n')

                    logger.error(f'{self.account_token} | Empty Attempts')
                    return False

                self.unauthorized_attempts += 1
                continue

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

            except AccountSuspended as error:
                async with aiofiles.open('suspended_accounts.txt', 'a', encoding='utf-8-sig') as f:
                    await f.write(f'{error}\n')

                logger.error(f'{error} | Account Suspended')
                return False

            except Exception as error:
                async with aiofiles.open(file='unexpected_errors.txt', mode='a', encoding='utf-8-sig') as f:
                    await f.write(f'{self.account_token}\n')

                logger.error(f'{self.account_token} | Неизвестная ошибка при обработке аккаунта: {error}')
                return False

            else:
                return True

        else:
            logger.error(f'{self.account_token} | Empty Attempts')

            async with aiofiles.open('empty_attempts.txt', 'a', encoding='utf-8-sig') as f:
                await f.write(f'{self.account_token}\n')

            return False


def start_reger_wrapper(source_data: dict) -> bool:
    try:
        if config.CHANGE_PROXY_URL:
            r = requests.get(config.CHANGE_PROXY_URL)
            logger.info(f'{source_data["account_token"]} | Успешно сменил Proxy, статус: {r.status_code}')

            if config.SLEEP_AFTER_PROXY_CHANGING:
                time_to_sleep: int = format_range(value=config.SLEEP_AFTER_PROXY_CHANGING,
                                                  return_randint=True)
                logger.info(
                    f'{source_data["account_token"]} | Сплю {time_to_sleep} сек. после смены Proxy')
                sleep(time_to_sleep)

        return asyncio.run(Reger(source_data=source_data).start_reger())

    except Exception as error:
        logger.error(f'{source_data["account_token"]} | Неизвестная ошибка: {error}')
