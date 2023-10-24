import asyncio
from random import choice
from time import sleep
from urllib.parse import urlparse, parse_qs

import aiofiles
import aiohttp
import aiohttp.client
import better_automation.twitter.api
import better_automation.twitter.errors
import eth_account.signers.local
import requests
import tls_client.sessions
from aiohttp_socks import ProxyConnector
from better_automation import TwitterAPI
from bs4 import BeautifulSoup
from eth_account.messages import encode_defunct
from web3.auto import w3

import config
from utils import check_empty_value
from utils import generate_eth_account, get_account
from utils import logger
from .solve_captcha import SolveCaptcha


class Unauthorized(BaseException):
    pass


class AccountSuspended(BaseException):
    pass


class Reger:
    def __init__(self,
                 source_data: dict) -> None:
        self.account_token: str = source_data['account_token']
        self.account_proxy: str | None = source_data['account_proxy']
        self.account_private_key: str | None = source_data['account_private_key']

        self.twitter_client: better_automation.twitter.api.TwitterAPI | None = None
        self.meme_client: tls_client.sessions.Session | None = None

    def get_tasks(self) -> dict:
        r = self.meme_client.get(url='https://memefarm-api.memecoin.org/user/tasks',
                                 headers={
                                     **self.meme_client.headers,
                                     'content-type': ''
                                 })

        return r.json()

    def get_twitter_account_names(self) -> tuple[str, str]:
        r = self.meme_client.get(url='https://memefarm-api.memecoin.org/user/info',
                                 headers={
                                     **self.meme_client.headers,
                                     'content-type': ''
                                 })

        return r.json()['twitter']['username'], r.json()['twitter']['name']

    def link_wallet_request(self,
                            address: str,
                            sign: str,
                            message: str) -> tuple[bool, str]:
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
                raise Unauthorized()

            return r.json()['status'] == 'success', r.text

    def link_wallet(self,
                    account: eth_account.signers.local.LocalAccount,
                    twitter_username: str) -> tuple[bool, str]:
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
                                  twitter_account_name: str) -> tuple[bool, str]:
        r = await self.twitter_client.request(url='https://api.twitter.com/1.1/account/update_profile.json',
                                              method='post',
                                              data={
                                                  'name': f'{twitter_account_name} ❤️ Memecoin'
                                              })

        if 'This account is suspended' in await r[0].text():
            raise AccountSuspended(self.account_token)

        if r[0].status == 200:
            return True, await r[0].text()

        return False, await r[0].text()

    async def twitter_name(self,
                           twitter_account_name: str) -> tuple[bool, str]:
        if '❤️ Memecoin' not in twitter_account_name:
            change_twitter_name_result, response_text = await self.change_twitter_name(
                twitter_account_name=twitter_account_name)

            if not change_twitter_name_result:
                logger.error(f'{self.account_token} | Не удалось изменить имя пользователя')
                return False, response_text

        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/twitter-name',
                                      headers={
                                          **self.meme_client.headers,
                                          'content-type': ''
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                raise Unauthorized()

            return r.json()['status'] == 'success', r.text

    async def create_tweet(self,
                           twitter_username: str, ) -> tuple[bool, str]:
        r = await self.twitter_client.tweet(
            text=f'Hi, my name is @{twitter_username}, and I’m a $MEME (@Memecoin) farmer '
                 'at @Memeland.\n\nOn my honor, I promise that I will do my best '
                 'to do my duty to my own bag, and to farm #MEMEPOINTS at '
                 'all times.\n\nIt ain’t much, but it’s honest work. 🧑‍🌾 ')

        return True, str(r)

    async def share_message(self,
                            twitter_username: str, ) -> tuple[bool, str]:
        try:
            create_tweet_status, tweet_id = await self.create_tweet(twitter_username=twitter_username)

        except better_automation.twitter.errors.HTTPException as error:
            if 187 in error.api_codes:
                pass

            else:
                raise better_automation.twitter.errors.HTTPException(error.response)

        else:
            if not create_tweet_status:
                return False, tweet_id

        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/share-message',
                                      headers={
                                          **self.meme_client.headers,
                                          'content-type': None
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                raise Unauthorized()

            return r.json()['status'] == 'success', r.text

    def invite_code(self) -> tuple[bool, str]:
        while True:
            r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/verify/invite-code',
                                      json={
                                          'code': 'captainz#6416'
                                      })

            if r.json()['status'] == 'verification_failed':
                logger.info(f'{self.account_token} | Verification Failed, пробую еще раз')
                sleep(5)
                continue

            elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
                raise Unauthorized()

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

    async def get_oauth_auth_tokens(self) -> tuple[str | None, str | None, str | None, str]:
        while True:
            headers: dict = self.twitter_client._headers

            if headers.get('content-type'):
                del headers['content-type']

            headers[
                'accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'

            if not self.twitter_client.ct0:
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

                SolveCaptcha(auth_token=self.twitter_client.auth_token,
                             ct0=self.twitter_client.ct0).solve_captcha(proxy=self.account_proxy,
                                                                        account_token=self.account_token)
                continue

            if 'https://www.memecoin.org/farming?oauth_token=' in (await r[0].text()):
                return 'https://www.memecoin.org/farming?oauth_token=' + \
                       (await r[0].text()).split('https://www.memecoin.org/farming?oauth_token=')[-1].split('"')[
                           0].replace('&amp;', '&'), None, None, await r[0].text()

            auth_token_html = BeautifulSoup(await r[0].text(), 'lxml').find('input', {
                'name': 'authenticity_token'
            })
            oauth_token_html = BeautifulSoup(await r[0].text(), 'lxml').find('input', {
                'name': 'oauth_token'
            })

            if not auth_token_html or not oauth_token_html:
                logger.error(f'{self.account_token} | Не удалось обнаружить Auth/OAuth Token на странице, '
                             f'пробую еще раз, ответ: {await r[0].text()}')
                continue

            auth_token: str = auth_token_html.get('value', '')
            oauth_token: str = oauth_token_html.get('value', '')

            return None, auth_token, oauth_token, await r[0].text()

    async def make_auth(self,
                        oauth_token: str,
                        auth_token: str) -> tuple[str | bool, str]:
        while True:
            if not self.twitter_client.ct0:
                self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

            r = await self.twitter_client.request(url='https://api.twitter.com/oauth/authorize',
                                                  method='post',
                                                  data={
                                                      'authenticity_token': auth_token,
                                                      'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}',
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

    async def start_reger(self) -> None:
        while True:
            try:
                async with aiohttp.ClientSession(
                        connector=ProxyConnector.from_url(
                            url=self.account_proxy) if self.account_proxy else None) as aiohttp_twitter_session:
                    self.twitter_client: better_automation.twitter.api.TwitterAPI = TwitterAPI(
                        session=aiohttp_twitter_session,
                        auth_token=self.account_token)

                    if not self.twitter_client.ct0:
                        self.twitter_client.set_ct0(await self.twitter_client._request_ct0())

                    location, auth_token, oauth_token, response_text = await self.get_oauth_auth_tokens()

                    if not location:
                        if not check_empty_value(value=auth_token,
                                                 account_token=self.account_token) or not check_empty_value(
                            value=oauth_token,
                            account_token=self.account_token):
                            logger.error(
                                f'{self.account_token} | Ошибка при получении OAuth / Auth Token, ответ: {response_text}')
                            return

                        location, response_text = await self.make_auth(oauth_token=oauth_token,
                                                                       auth_token=auth_token)

                        if not check_empty_value(value=location,
                                                 account_token=self.account_token):
                            logger.error(
                                f'{self.account_token} | Ошибка при авторизации через Twitter, ответ: {response_text}')
                            return

                    if parse_qs(urlparse(location).query).get('redirect_after_login') \
                            or not parse_qs(urlparse(location).query).get('oauth_token') \
                            or not parse_qs(urlparse(location).query).get('oauth_verifier'):
                        logger.error(
                            f'{self.account_token} | Не удалось обнаружить OAuth Token / OAuth Verifier в ссылке: {location}')
                        continue

                    oauth_token: str = parse_qs(urlparse(location).query)['oauth_token'][0]
                    oauth_verifier: str = parse_qs(urlparse(location).query)['oauth_verifier'][0]
                    access_token: str = ''

                    while True:
                        self.meme_client = tls_client.Session(client_identifier=choice([
                            'Chrome110',
                            'chrome111',
                            'chrome112'
                        ]))
                        self.meme_client.headers.update({
                            'user-agent': choice([
                                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
                                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.962 YaBrowser/23.9.1.962 Yowser/2.5 Safari/537.36'
                            ]),
                            'accept': 'application/json',
                            'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7,cy;q=0.6',
                            'content-type': 'application/json',
                            'origin': 'https://www.memecoin.org',
                            'referer': 'https://www.memecoin.org/'
                        })

                        r = self.meme_client.post(url='https://memefarm-api.memecoin.org/user/twitter-auth1',
                                                  json={
                                                      'oauth_token': oauth_token,
                                                      'oauth_verifier': oauth_verifier
                                                  })

                        if r.json().get('error', '') == 'account_too_new':
                            logger.error(f'{self.account_token} | Account Too New')

                            continue

                        if r.json().get('error', '') == 'Unauthorized':
                            raise Unauthorized()

                        access_token: str = r.json().get('accessToken', '')

                        if not access_token:
                            logger.error(
                                f'{self.account_token} | Не удалось обнаружить Access Token в ответе, пробую еще раз, ответ: {r.text}')
                            continue

                        break

                    self.meme_client.headers.update({
                        'authorization': f'Bearer {access_token}'
                    })

                    if not self.account_private_key:
                        account: eth_account.signers.local.LocalAccount = generate_eth_account()

                    else:
                        account: eth_account.signers.local.LocalAccount = get_account(
                            private_key=self.account_private_key)

                    tasks_dict: dict = self.get_tasks()
                    twitter_username, twitter_account_name = self.get_twitter_account_names()

                    for current_task in tasks_dict['tasks']:
                        if current_task['completed']:
                            continue

                        match current_task['id']:
                            case 'connect':
                                continue

                            case 'linkWallet':
                                link_wallet_result, response_text = self.link_wallet(account=account,
                                                                                     twitter_username=twitter_username)

                                if link_wallet_result:
                                    logger.success(f'{self.account_token} | Успешно привязал кошелек')

                                    async with aiofiles.open(file='registered.txt', mode='a',
                                                             encoding='utf-8-sig') as f:
                                        await f.write(
                                            f'{self.account_token};{self.account_proxy if self.account_proxy else ""};{account.key.hex()}\n')

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось привязать кошелек, ответ: {response_text}')

                            case 'twitterName':
                                twitter_username_result, response_text = await self.twitter_name(
                                    twitter_account_name=twitter_account_name)

                                if twitter_username_result:
                                    logger.success(
                                        f'{self.account_token} | Успешно получил бонус за MEMELAND в никнейме')

                                else:
                                    logger.error(f'{self.account_token} | Не удалось получить бонус за MEMELAND в '
                                                 f'никнейме, ответ: {response_text}')

                            case 'shareMessage':
                                share_message_result, response_text = await self.share_message(
                                    twitter_username=twitter_username)

                                if share_message_result:
                                    logger.success(f'{self.account_token} | Успешно получил бонус за твит')

                                else:
                                    logger.error(
                                        f'{self.account_token} | Не удалось создать твит, ответ: {response_text}')

                            case 'inviteCode':
                                invite_code_result, response_text = self.invite_code()

                                if invite_code_result:
                                    logger.success(f'{self.account_token} | Успешно ввел реф.код')

                                else:
                                    logger.error(f'{self.account_token} | Не удалось ввести реф.код, ответ: {r.text}')

                            case 'followMemeland' | 'followMemecoin' | 'follow9gagceo':
                                follow_result, response_text = await self.follow_quest(
                                    username=current_task['id'].replace('follow', ''),
                                    follow_id=current_task['id'])

                                if follow_result:
                                    logger.success(
                                        f'{self.account_token} | Успешно подписался на {current_task["id"].replace("follow", "")}')

                                else:
                                    logger.error(
                                        f'{self.account_token} | Подписаться на {current_task["id"].replace("follow", "")}: {response_text}')

            except better_automation.twitter.errors.Forbidden as error:
                if 'This account is suspended.' in await error.response.text():
                    async with aiofiles.open('suspended_accounts.txt', 'a', encoding='utf-8-sig') as f:
                        await f.write(f'{error}\n')

                    logger.error(f'{self.account_token} | Account Suspended')
                    return

                logger.error(f'{self.account_token} | Forbidder Twitter, ответ: {await error.response.text()}')

            except (Unauthorized, better_automation.twitter.errors.Unauthorized,
                    better_automation.twitter.errors.HTTPException):
                logger.error(f'{self.account_token} | Unauthorized')
                continue

            except AccountSuspended as error:
                async with aiofiles.open('suspended_accounts.txt', 'a', encoding='utf-8-sig') as f:
                    await f.write(f'{error}\n')

                logger.error(f'{error} | Account Suspended')
                return

            except Exception as error:
                logger.error(f'{self.account_token} | Неизвестная ошибка при обработке аккаунта: {error}')

                return

            else:
                return


def start_reger_wrapper(source_data: dict) -> None:
    if config.CHANGE_PROXY_URL:
        r = requests.get(config.CHANGE_PROXY_URL)
        logger.info(f'{source_data["account_token"]} | Успешно сменил Proxy, ответ: {r.text}')

    asyncio.run(Reger(source_data=source_data).start_reger())
