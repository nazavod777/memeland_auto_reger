import asyncio
from sys import platform
from time import sleep

import requests
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver

import config
from utils import logger

if platform == "windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def create_task() -> tuple[int | bool, str]:
    r = requests.get(url='https://api.1stcaptcha.com/funcaptchatokentask',

                     params={
                         'apikey': config.FIRSTCAPTCHA_API_KEY,
                         'sitekey': config.SITE_KEY,
                         'siteurl': config.SITE_URL,
                         'affiliateid': 33060
                     })

    return r.json()['TaskId'] if r.json()['Code'] == 0 else False, r.text


def get_task_result(task_id: int | str) -> tuple[bool, str]:
    while True:
        r = requests.get(url='https://api.1stcaptcha.com/getresult',
                         params={
                             'apikey': config.FIRSTCAPTCHA_API_KEY,
                             'taskId': task_id
                         })

        if r.json()['Status'] in ['PENDING',
                                  'PROCESSING']:
            continue

        elif r.json()['Status'] == 'SUCCESS':
            return True, r.json()['Data']['Token']

        else:
            return False, r.text


class SolveCaptcha:
    def __init__(self,
                 auth_token: str,
                 ct0: str):
        self.auth_token: str = auth_token
        self.ct0: str = ct0

    def interceptor(self,
                    request):
        del request.twitter_headers['cookie']
        request.twitter_headers['cookie'] = f'auth_token=' + self.auth_token + '; ct0=' + self.ct0
        del request.twitter_headers['x-csrf-token']
        request.twitter_headers['x-csrf-token'] = self.ct0

    def solve_captcha(self,
                      proxy: str | None) -> None:
        try:
            captcha_result: str = ''

            while True:
                task_id, response_text = create_task()

                if not task_id:
                    logger.error(
                        f'{self.auth_token} | Ошибка при создании Task на решение капчи, ответ: {response_text}')
                    continue

                task_result, response_text = get_task_result(task_id=task_id)

                if not task_result:
                    logger.error(f'{self.auth_token} | Ошибка при решении капчи, ответ: {response_text}')
                    continue

                captcha_result: str = response_text
                logger.info(f'{self.auth_token} | Решение капчи получено, пробую отправить')
                break

            if proxy:
                options = {
                    'proxy': {
                        'http': proxy,
                        'https': proxy,
                        'no_proxy': 'localhost,127.0.0.1'
                    }
                }

            else:
                options = None

            co = webdriver.ChromeOptions()
            co.add_argument('--disable-gpu')
            co.add_argument('--disable-infobars')
            co.add_experimental_option('prefs', {'intl.accept_languages': 'en,en_US'})
            co.add_argument("lang=en-US")
            co.page_load_strategy = 'eager'
            co.add_argument("--mute-audio")
            co.add_argument('--headless')
            co.add_argument('log-level=3')
            co.add_argument('--no-sandbox')
            co.add_experimental_option('excludeSwitches', ['enable-logging'])

            driver = webdriver.Chrome(seleniumwire_options=options,
                                      options=co)
            wait = WebDriverWait(driver, 180)

            driver.get('https://twitter.com/account/access')
            driver.add_cookie({
                'name': 'auth_token',
                'value': self.auth_token
            })
            driver.add_cookie({
                'name': 'ct0',
                'value': self.ct0
            })
            driver.get('https://twitter.com/account/access')

            for _ in range(180):
                home_page: bool = False
                element = None

                try:
                    element = driver.find_element(By.XPATH,
                                                  '//input[@type="submit" and contains(@class, "Button EdgeButton '
                                                  'EdgeButton--primary")]')

                except NoSuchElementException:
                    pass

                else:
                    break

                try:
                    WebDriverWait(driver, 1).until(EC.url_contains("https://twitter.com/home"))

                except (NoSuchElementException, TimeoutException):
                    pass

                else:
                    home_page: bool = True
                    break

                try:
                    element = WebDriverWait(driver, 1).until(
                        EC.element_to_be_clickable((By.ID, 'arkose_iframe'))
                    )

                except (NoSuchElementException, TimeoutException):
                    pass

                else:
                    break

                sleep(1)

            else:
                logger.error(f'{self.auth_token} | Не удалось дождаться капчи Twitter')
                return

            if home_page:
                logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')
                return

            if element.get_attribute('value') and element.get_attribute('value') == 'Continue to Twitter':
                element.click()
                logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')
                return

            elif element.get_attribute('value') and element.get_attribute('value') == 'Start':
                element.click()
                driver.get('https://twitter.com/account/access')
                wait.until(EC.element_to_be_clickable((By.ID, 'arkose_iframe')))

            driver.switch_to.frame(driver.find_element(By.ID, 'arkose_iframe'))
            driver.execute_script(
                'parent.postMessage(JSON.stringify({eventId:"challenge-complete",payload:{sessionToken:"' + captcha_result + '"}}),"*")')
            wait.until(EC.url_contains("https://twitter.com/home"))

            logger.success(f'{self.auth_token} | Аккаунт успешно разморожен')

        except Exception as error:
            logger.error(f'{self.auth_token} | Неизвестная ошибка при попытке разморозить аккаунт: {error}')
