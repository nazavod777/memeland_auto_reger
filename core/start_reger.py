from urllib.parse import unquote
from json.decoder import JSONDecodeError
from random import choice
from time import sleep
from urllib.parse import urlparse, parse_qs

import eth_account.signers.local
import tls_client.sessions
from bs4 import BeautifulSoup
from eth_account.messages import encode_defunct
from web3.auto import w3

import config
from utils import check_empty_value
from utils import generate_eth_account, get_account
from utils import logger
from .get_session import get_session, get_meme_session
from .solve_captcha import SolveCaptcha


class Unauthorized(BaseException):
    pass


class AccountSuspended(BaseException):
    pass


def get_tasks(session: tls_client.sessions.Session) -> dict:
    r = session.get(url='https://memefarm-api.memecoin.org/user/tasks',
                    headers={
                        **session.headers,
                        'content-type': None
                    })

    return r.json()


def get_twitter_account_names(session: tls_client.sessions.Session) -> tuple[str, str]:
    r = session.get(url='https://memefarm-api.memecoin.org/user/info',
                    headers={
                        **session.headers,
                        'content-type': None
                    })

    return r.json()['twitter']['username'], r.json()['twitter']['name']


def link_wallet_request(session: tls_client.sessions.Session,
                        address: str,
                        sign: str,
                        message: str,
                        account_token: str) -> tuple[bool, str]:
    while True:
        r = session.post(url='https://memefarm-api.memecoin.org/user/verify/link-wallet',
                         json={
                             'address': address,
                             'delegate': address,
                             'message': message,
                             'signature': sign
                         })

        if r.json()['status'] == 'verification_failed':
            logger.info(f'{account_token} | Verification Failed, пробую еще раз')
            sleep(5)
            continue

        elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
            logger.error(f'{account_token} | Unauthorized')
            raise Unauthorized()

        return r.json()['status'] == 'success', r.text


def link_wallet(session: tls_client.sessions.Session,
                account: eth_account.signers.local.LocalAccount,
                account_token: str,
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

    return link_wallet_request(session=session,
                               address=account.address,
                               sign=sign,
                               message=message_to_sign,
                               account_token=account_token)


def change_twitter_name(twitter_session: tls_client.sessions.Session,
                        twitter_account_name: str,
                        account_token: str) -> tuple[bool, str]:
    r = twitter_session.post(url='https://api.twitter.com/1.1/account/update_profile.json',
                             data={
                                 'name': f'{twitter_account_name} ❤️ Memecoin'
                             })

    if 'This account is suspended' in r.text:
        raise AccountSuspended(account_token)

    if r.status_code == 200:
        return True, r.text

    return False, r.text


def twitter_name(twitter_session: tls_client.sessions.Session,
                 meme_session: tls_client.sessions.Session,
                 account_token: str,
                 twitter_account_name: str) -> tuple[bool, str]:
    if '❤️ Memecoin' not in twitter_account_name:
        change_twitter_name_result, response_text = change_twitter_name(twitter_session=twitter_session,
                                                                        twitter_account_name=twitter_account_name,
                                                                        account_token=account_token)

        if not change_twitter_name_result:
            logger.error(f'{account_token} | Не удалось изменить имя пользователя')
            return False, response_text

    while True:
        r = meme_session.post(url='https://memefarm-api.memecoin.org/user/verify/twitter-name',
                              headers={
                                  **meme_session.headers,
                                  'content-type': None
                              })

        if r.json()['status'] == 'verification_failed':
            logger.info(f'{account_token} | Verification Failed, пробую еще раз')
            sleep(5)
            continue

        elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
            logger.error(f'{account_token} | Unauthorized')
            raise Unauthorized()

        return r.json()['status'] == 'success', r.text


def create_tweet(twitter_session: tls_client.sessions.Session,
                 twitter_username: str,
                 account_token: str) -> tuple[bool, str]:
    r = twitter_session.post(url='https://twitter.com/i/api/graphql/5V_dkq1jfalfiFOEZ4g47A/CreateTweet',
                             json={
                                 'variables':
                                     {
                                         'tweet_text': f'Hi, my name is @{twitter_username}, and I’m a $MEME (@Memecoin) farmer '
                                                       'at @Memeland.\n\nOn my honor, I promise that I will do my best '
                                                       'to do my duty to my own bag, and to farm #MEMEPOINTS at '
                                                       'all times.\n\nIt ain’t much, but it’s honest work. 🧑‍🌾 ',
                                         'dark_request': False,
                                         'media':
                                             {
                                                 'media_entities': [],
                                                 'possibly_sensitive': False
                                             },
                                         'semantic_annotation_ids': [

                                         ]
                                     },
                                 'features':
                                     {
                                         'c9s_tweet_anatomy_moderator_badge_enabled': True,
                                         'tweetypie_unmention_optimization_enabled': True,
                                         'responsive_web_edit_tweet_api_enabled': True,
                                         'graphql_is_translatable_rweb_tweet_is_translatable_enabled': True,
                                         'view_counts_everywhere_api_enabled': True,
                                         'longform_notetweets_consumption_enabled': True,
                                         'responsive_web_twitter_article_tweet_consumption_enabled': False,
                                         'tweet_awards_web_tipping_enabled': False,
                                         'responsive_web_home_pinned_timelines_enabled': True,
                                         'longform_notetweets_rich_text_read_enabled': True,
                                         'longform_notetweets_inline_media_enabled': True,
                                         'responsive_web_graphql_exclude_directive_enabled': True,
                                         'verified_phone_label_enabled': False,
                                         'freedom_of_speech_not_reach_fetch_enabled': True,
                                         'standardized_nudges_misinfo': True,
                                         'tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled': True,
                                         'responsive_web_media_download_video_enabled': False,
                                         'responsive_web_graphql_skip_user_profile_image_extensions_enabled': False,
                                         'responsive_web_graphql_timeline_navigation_enabled': True,
                                         'responsive_web_enhance_cards_enabled': False
                                     },
                                 "queryId": "5V_dkq1jfalfiFOEZ4g47A"},
                             headers={
                                 **twitter_session.headers,
                                 'content-type': 'application/json'
                             })

    if r.json().get('errors'):
        for current_error in r.json()['errors']:
            if current_error['message'] == 'This request requires a matching csrf cookie and header.':
                raise Unauthorized()

    if 'This account is suspended' in r.text:
        raise AccountSuspended(account_token)

    if r.status_code == 200:
        return True, r.text

    return False, r.text


def share_message(twitter_session: tls_client.sessions.Session,
                  meme_session: tls_client.sessions.Session,
                  twitter_username: str,
                  account_token: str) -> tuple[bool, str]:
    create_tweet_status, response_text = create_tweet(twitter_session=twitter_session,
                                                      twitter_username=twitter_username,
                                                      account_token=account_token)

    if not create_tweet_status:
        return False, response_text

    while True:
        r = meme_session.post(url='https://memefarm-api.memecoin.org/user/verify/share-message',
                              headers={
                                  **meme_session.headers,
                                  'content-type': None
                              })

        if r.json()['status'] == 'verification_failed':
            logger.info(f'{account_token} | Verification Failed, пробую еще раз')
            sleep(5)
            continue

        elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
            logger.error(f'{account_token} | Unauthorized')
            raise Unauthorized()

        return r.json()['status'] == 'success', r.text


def invite_code(meme_session: tls_client.sessions.Session,
                account_token: str) -> tuple[bool, str]:
    while True:
        r = meme_session.post(url='https://memefarm-api.memecoin.org/user/verify/invite-code',
                              json={
                                  'code': f'captainz#{(choice(config.ref_codes))}'
                              })

        if r.json()['status'] == 'verification_failed':
            logger.info(f'{account_token} | Verification Failed, пробую еще раз')
            sleep(5)
            continue

        elif r.json()['status'] == 401 and r.json().get('error') and r.json()['error'] == 'unauthorized':
            logger.error(f'{account_token} | Unauthorized')
            raise Unauthorized()

        return r.json()['status'] == 'success', r.text


def get_oauth_token(session: tls_client.sessions.Session) -> tuple[None | str, str]:
    while True:
        r = session.get(url='https://memefarm-api.memecoin.org/user/twitter-auth1',
                        params={
                            'callback': 'https://www.memecoin.org/farming'
                        })

        if not r.headers.get('Location'):
            return None, r.text

        oauth_token: str = r.headers.get('Location').split('?oauth_token=')[-1]

        return oauth_token, r.text


def get_auth_token(session: tls_client.sessions.Session,
                   oauth_token: str,
                   account_token: str) -> tuple[str | bool, str]:
    while True:
        r = session.get(url='https://api.twitter.com/oauth/authenticate',
                        params={
                            'oauth_token': oauth_token
                        })

        if 'This account is suspended' in r.text:
            raise AccountSuspended(account_token)

        if 'Redirecting you back to the application' in r.text and r.text.rstrip().replace('\n', '').startswith(
                '<?xml version='):
            return r.text.split("<p>If your browser doesn't redirect you please <a href=\"")[-1].split('"')[0].replace(
                '&amp;', '&'), r.text

        if r.headers.get('Location') == 'https://twitter.com/account/access':
            logger.info(f'{account_token} | Обнаружена заморозка аккаунта, пробую разморозить')
            SolveCaptcha().solve_captcha(session=session,
                                         account_token=account_token)
            continue

        auth_token_element = BeautifulSoup(r.text, 'html.parser').find('input', {
            'name': 'authenticity_token'
        })

        if not auth_token_element:
            return False, r.text

        auth_token: str = auth_token_element.get('value')

        return auth_token, r.text


def make_auth(session: tls_client.sessions.Session,
              oauth_token: str,
              auth_token: str,
              account_token: str) -> tuple[str | bool, str]:
    while True:
        r = session.post(url='https://api.twitter.com/oauth/authorize',
                         data={
                             'authenticity_token': auth_token,
                             'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}',
                             'oauth_token': oauth_token
                         })

        if 'This account is suspended' in r.text:
            raise AccountSuspended(account_token)

        if 'Redirecting you back to the application' in r.text and r.text.rstrip().replace('\n', '').startswith(
                '<?xml version='):
            return r.text.split("<p>If your browser doesn't redirect you please <a href=\"")[-1].split('"')[0].replace(
                '&amp;', '&'), r.text

        if r.text.startswith('<html><body>You are being <a href="'):
            return unquote(r.text.split('<html><body>You are being <a href="')[-1].split('"')[0]), r.text

        location_html = BeautifulSoup(r.text, 'html.parser').find('a', {
            'class': 'maintain-context'
        })

        if not location_html:
            return False, r.text

        location: str = location_html.get('href')

        return location, r.text


def start_reger(source_data: dict) -> None:
    account_token: str = source_data['account_token']
    account_proxy: str | None = source_data['account_proxy']
    account_private_key: str | None = source_data['account_private_key']

    while True:
        try:
            twitter_session: tls_client.sessions.Session = get_session(account_token=account_token,
                                                                       account_proxy=account_proxy)

            oauth_token, response_text = get_oauth_token(session=twitter_session)

            if not check_empty_value(value=oauth_token,
                                     account_token=account_token):
                logger.error(f'{account_token} | Ошибка при получении OAuth Token, ответ: {response_text}')
                return

            auth_token, response_text = get_auth_token(session=twitter_session,
                                                       oauth_token=oauth_token,
                                                       account_token=account_token)

            if not check_empty_value(value=auth_token,
                                     account_token=account_token):
                logger.error(f'{account_token} | Ошибка при получении Auth Token, ответ: {response_text}')
                return

            location, response_text = make_auth(session=twitter_session,
                                                oauth_token=oauth_token,
                                                auth_token=auth_token,
                                                account_token=account_token)

            if not check_empty_value(value=location,
                                     account_token=account_token):
                logger.error(f'{account_token} | Ошибка при авторизации через Twitter, ответ: {response_text}')
                return

            if parse_qs(urlparse(location).query).get('redirect_after_login') \
                    or not parse_qs(urlparse(location).query).get('oauth_token') \
                    or not parse_qs(urlparse(location).query).get('oauth_verifier'):
                continue

            oauth_token: str = parse_qs(urlparse(location).query)['oauth_token'][0]
            oauth_verifier: str = parse_qs(urlparse(location).query)['oauth_verifier'][0]

            meme_session: tls_client.sessions.Session = get_meme_session(account_proxy=account_proxy)

            r = meme_session.post(url='https://memefarm-api.memecoin.org/user/twitter-auth1',
                                  json={
                                      'oauth_token': oauth_token,
                                      'oauth_verifier': oauth_verifier
                                  })

            try:
                access_token: str = r.json()['accessToken']

            except (JSONDecodeError, KeyError, ValueError):
                logger.error(f'{account_token} | Ошибка при авторизации MEME: {r.text}')

                check_empty_value(value='',
                                  account_token=account_token)
                return

            meme_session.headers.update({
                'authorization': f'Bearer {access_token}'
            })

            if not account_private_key:
                account: eth_account.signers.local.LocalAccount = generate_eth_account()

            else:
                account: eth_account.signers.local.LocalAccount = get_account(private_key=account_private_key)

            tasks_dict: dict = get_tasks(session=meme_session)
            twitter_username, twitter_account_name = get_twitter_account_names(session=meme_session)

            for current_task in tasks_dict['tasks']:
                if current_task['completed']:
                    continue

                match current_task['id']:
                    case 'connect':
                        continue

                    case 'linkWallet':
                        link_wallet_result, response_text = link_wallet(session=meme_session,
                                                                        account=account,
                                                                        account_token=account_token,
                                                                        twitter_username=twitter_username)

                        if link_wallet_result:
                            logger.success(f'{account_token} | Успешно привязал кошелек')

                        else:
                            logger.error(f'{account_token} | Не удалось привязать кошелек, ответ: {response_text}')

                    case 'twitterName':
                        twitter_username_result, response_text = twitter_name(twitter_session=twitter_session,
                                                                              meme_session=meme_session,
                                                                              account_token=account_token,
                                                                              twitter_account_name=twitter_account_name)

                        if twitter_username_result:
                            logger.success(f'{account_token} | Успешно получил бонус за MEMELAND в никнейме')

                        else:
                            logger.error(f'{account_token} | Не удалось получить бонус за MEMELAND в '
                                         f'никнейме, ответ: {response_text}')

                    case 'shareMessage':
                        share_message_result, response_text = share_message(twitter_session=twitter_session,
                                                                            meme_session=meme_session,
                                                                            twitter_username=twitter_username,
                                                                            account_token=account_token)

                        if share_message_result:
                            logger.success(f'{account_token} | Успешно получил бонус за твит')

                        else:
                            logger.error(f'{account_token} | Не удалось создать твит, ответ: {response_text}')

                    case 'inviteCode':
                        invite_code_result, response_text = invite_code(meme_session=meme_session,
                                                                        account_token=account_token)

                        if invite_code_result:
                            logger.success(f'{account_token} | Успешно ввел реф.код')

                        else:
                            logger.error(f'{account_token} | Не удалось ввести реф.код, ответ: {r.text}')

        except Unauthorized:
            continue

        except AccountSuspended as error:
            with open('suspended_accounts.txt', 'a', encoding='utf-8-sig') as file:
                file.write(f'{error}\n')

            logger.error(f'{error} | Account Suspended')
            return

        except Exception as error:
            logger.error(f'{account_token} | Неизвестная ошибка при обработке аккаунта: {error}')

            return

        else:
            with open(file='registered.txt', mode='a', encoding='utf-8-sig') as file:
                file.write(f'{account_token};{account_proxy if account_proxy else ""};{account.key.hex()}\n')

            return
