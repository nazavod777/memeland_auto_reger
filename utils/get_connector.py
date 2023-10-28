import asyncio
from sys import platform

from aiohttp import TCPConnector
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy

from utils import logger

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def get_connector(proxy: str | None) -> TCPConnector | ProxyConnector:
    try:
        if proxy and proxy.startswith('https://'):
            proxy: str = proxy.replace('https://', 'http://')

        connector: ProxyConnector | None = ProxyConnector.from_url(url=Proxy.from_str(proxy=proxy).as_url,
                                                                   verify_ssl=False) if proxy else TCPConnector(
            verify_ssl=False)
        return connector

    except Exception as error:
        logger.error(f'Ошибка при получении Connector\'a: {error}, работаю без Proxy')

        return TCPConnector(verify_ssl=False)
