from random import choice

import tls_client
import tls_client.sessions
from pyuseragents import random as random_useragent

from .generate_csrf_token import generate_csrf_token
from .headers import headers

client_identifiers: list = [
    'chrome_103',
    'chrome_104',
    'chrome_105',
    'chrome_106',
    'firefox_102',
    'firefox_104',
    'opera_89',
    'opera_90',
    'safari_15_3',
    'safari_15_6_1',
    'safari_16_0',
    'safari_ios_15_5',
    'safari_ios_15_6',
    'safari_ios_16_0',
    'safari_ios_15_6'
]


def get_session(account_token: str,
                account_proxy: str) -> tls_client.sessions.Session:
    csrf_token: str = generate_csrf_token()

    session: tls_client.sessions.Session = tls_client.Session(client_identifier=choice(client_identifiers),
                                                              random_tls_extension_order=True)
    session.cookies.update({
        'auth_token': account_token,
        'ct0': csrf_token
    })
    session.headers.update({
        **headers,
        'user-agent': random_useragent(),
        'x-csrf-token': csrf_token
    })

    if account_proxy:
        session.proxies.update({
            'http': account_proxy,
            'https': account_proxy
        })

    return session


def get_meme_session(account_proxy: str) -> tls_client.sessions.Session:
    session: tls_client.sessions.Session = tls_client.Session(client_identifier=choice(client_identifiers),
                                                              random_tls_extension_order=True)

    session.headers.update({
        'content-type': 'application/json',
        'origin': 'https://www.memecoin.org',
        'referer': 'https://www.memecoin.org/',
        'accept': 'application/json',
        'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7,cy;q=0.6',
        'user-agent': random_useragent(),

    })

    if account_proxy:
        session.proxies.update({
            'http': account_proxy,
            'https': account_proxy
        })

    return session
