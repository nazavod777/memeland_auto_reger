import asyncio
import traceback
from sys import platform
from time import time

import aiofiles
import aiohttp
# noinspection PyProtectedMember
import playwright._impl._api_types
from better_proxy import Proxy
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async

import config
from utils import logger

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def create_task() -> tuple[int | bool, str]:
    async with aiohttp.ClientSession() as session:
        async with session.get(url='https://api.1stcaptcha.com/funcaptchatokentask',
                               params={
                                   'apikey': config.FIRSTCAPTCHA_API_KEY,
                                   'sitekey': config.SITE_KEY,
                                   'siteurl': config.SITE_URL,
                                   'affiliateid': 33060
                               }) as r:
            return (await r.json())['TaskId'] if (await r.json())['Code'] == 0 else False, await r.text()


async def get_task_result(task_id: int | str) -> tuple[bool, str]:
    while True:
        async with aiohttp.ClientSession() as session:
            async with session.get(url='https://api.1stcaptcha.com/getresult',
                                   params={
                                       'apikey': config.FIRSTCAPTCHA_API_KEY,
                                       'taskId': task_id
                                   }) as r:

                if (await r.json())['Status'] in ['PENDING',
                                                  'PROCESSING']:
                    continue

                elif (await r.json())['Status'] == 'SUCCESS':
                    return True, (await r.json())['Data']['Token']

                else:
                    return False, await r.text()


class SolveCaptcha:
    def __init__(self, auth_token: str, ct0: str):
        self.auth_token = auth_token
        self.ct0 = ct0

    @staticmethod
    async def wait_for_url(page, url, timeout=60):
        start_time = time()
        while time() - start_time < timeout:
            if url in page.url:
                return True
            await asyncio.sleep(1)
        # noinspection PyProtectedMember
        raise playwright._impl._api_types.TimeoutError(message='')

    async def wait_for_multiple_conditions(self,
                                           page, selector, url, timeout=60000) -> tuple[any, any]:
        # noinspection PyProtectedMember
        try:
            element_task = asyncio.create_task(page.wait_for_selector(selector, timeout=timeout))
            url_task = asyncio.create_task(self.wait_for_url(page=page, url=url))

            done, pending = await asyncio.wait(fs=[element_task, url_task], return_when=asyncio.FIRST_COMPLETED)

            for task in pending:
                task.cancel()

            if element_task.done() and element_task.result():
                return None, element_task.result()

            if url_task.done() and url_task.result():
                return True, None

            return None, None

        except (playwright._impl._api_types.TimeoutError,
                asyncio.TimeoutError,
                TimeoutError):
            return None, None

    async def solve_captcha(self, proxy: str | None) -> bool:
        for _ in range(config.SOLVE_CAPTCHA_ATTEMPTS):
            try:
                async with async_playwright() as p:
                    context_options = {
                        'user_data_dir': '',
                        'viewport': None,
                    }

                    if proxy:
                        context_options['proxy'] = {
                            "server": f"http://{Proxy.from_str(proxy=proxy).host}:{Proxy.from_str(proxy=proxy).port}",
                            "username": Proxy.from_str(proxy=proxy).login,
                            "password": Proxy.from_str(proxy=proxy).password,
                        }

                    context = await p.firefox.launch_persistent_context(**context_options)

                    await context.add_cookies(
                        [
                            {
                                "name": "auth_token",
                                "value": self.auth_token,
                                "domain": "twitter.com",
                                "path": "/",
                            },
                            {
                                "name": "ct0",
                                "value": self.ct0,
                                "domain": "twitter.com",
                                "path": "/",
                            },
                        ]
                    )

                    page = await context.new_page()
                    await stealth_async(page)
                    await page.goto('https://twitter.com/account/access')
                    await page.wait_for_load_state(state='networkidle',
                                                   timeout=60000)

                    home_page, element = await self.wait_for_multiple_conditions(page=page,
                                                                                 selector="#arkose_iframe, input["
                                                                                          "type='submit'].Button.EdgeButton.EdgeButton--primary",
                                                                                 url="twitter.com/home")

                    if not home_page and not element:
                        logger.error(f'{self.auth_token} | Не удалось обнаружить элемент с капчей на странице')
                        continue

                    if home_page:
                        logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')
                        return True

                    if element and await element.get_attribute('value') == 'Continue to Twitter':
                        await element.click()
                        logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')
                        return True

                    elif element and await element.get_attribute('value') == 'Delete':
                        await element.click()
                        continue

                    elif element and await element.get_attribute('value') == 'Start':
                        await element.click()

                        await page.goto('https://twitter.com/account/access')
                        await page.wait_for_selector('#arkose_iframe')

                    while True:
                        task_id, response_text = await create_task()

                        if not task_id:
                            logger.error(
                                f'{self.auth_token} | Ошибка при создании Task на решение капчи, ответ: {response_text}')
                            continue

                        task_result, response_text = await get_task_result(task_id=task_id)

                        if not task_result:
                            logger.error(f'{self.auth_token} | Ошибка при решении капчи, ответ: {response_text}')
                            continue

                        captcha_result = response_text
                        logger.info(f'{self.auth_token} | Решение капчи получено, пробую отправить')
                        break

                    iframe_element = await page.query_selector('#arkose_iframe')

                    if not iframe_element:
                        if 'twitter.com/home' in page.url:
                            logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')
                            return True

                        logger.error(f'{self.auth_token} | Не удалось обнаружить элемент с капчей на странице')
                        continue

                    iframe = await iframe_element.content_frame()

                    await iframe.evaluate(
                        f'parent.postMessage(JSON.stringify({{eventId:"challenge-complete",payload:{{sessionToken:"{captcha_result}"}}}}),"*")')

                    await page.wait_for_load_state(state='networkidle',
                                                   timeout=60000)
                    await self.wait_for_url(page=page,
                                            url='twitter.com/home',
                                            timeout=5)

                    logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')
                    await context.close()

            except Exception as error:
                logger.error(f'{self.auth_token} | Неизвестная ошибка при попытке разморозить аккаунт: {error}')
                print(traceback.print_exc())
                continue

            else:
                return True

        else:
            async with aiofiles.open(file='empty_attempts.txt', mode='a', encoding='utf-8-sig') as f:
                await f.write(f'{self.auth_token}\n')

            logger.error(f'{self.auth_token} | Empty Attempts')
