import asyncio
from random import choice
from sys import platform

import tls_client
import tls_client.sessions

from .headers import meme_headers

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def get_meme_session(account_proxy: str | None) -> tls_client.sessions.Session:
    meme_client = tls_client.Session(client_identifier=choice([
        'Chrome110',
        'chrome111',
        'chrome112'
    ]))
    meme_client.headers.update({
        **meme_headers,
        'user-agent': choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/112.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/116.0.5845.962 YaBrowser/23.9.1.962 Yowser/2.5 Safari/537.36'
        ])
    })

    if account_proxy:
        meme_client.proxies.update({
            'http': account_proxy,
            'https': account_proxy
        })
    return meme_client
