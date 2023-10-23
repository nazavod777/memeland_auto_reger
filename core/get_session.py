import aiohttp
import aiohttp.client
from aiohttp_socks import ProxyConnector
from pyuseragents import random as random_useragent


async def get_meme_session(account_proxy: str | None) -> aiohttp.client.ClientSession:
    session: aiohttp.client.ClientSession = aiohttp.ClientSession(
        connector=ProxyConnector.from_url(url=account_proxy) if account_proxy else None)

    session.headers.update({
        'content-type': 'application/json',
        'origin': 'https://www.memecoin.org',
        'referer': 'https://www.memecoin.org/',
        'accept': 'application/json',
        'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7,cy;q=0.6',
        'user-agent': random_useragent(),

    })

    return session
