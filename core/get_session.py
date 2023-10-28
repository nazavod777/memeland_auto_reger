import aiohttp
import aiohttp.client
from pyuseragents import random as random_useragent

from headers import meme_headers
from utils import get_connector


async def get_meme_session(account_proxy: str | None) -> aiohttp.client.ClientSession:
    session: aiohttp.client.ClientSession = aiohttp.ClientSession(
        connector=await get_connector(proxy=account_proxy) if account_proxy else await get_connector(proxy=None))

    session.headers.update({
        **meme_headers,
        'user-agent': random_useragent()
    })

    return session
