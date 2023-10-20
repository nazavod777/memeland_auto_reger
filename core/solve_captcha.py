import requests
import tls_client.sessions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver

import config
from utils import logger


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
    def __init__(self):
        self.session: tls_client.sessions.Session | None = None

    def interceptor(self,
                    request):
        for current_cookie in self.session.headers.items():
            del request.headers[current_cookie[0]]
            request.headers[current_cookie[0]] = current_cookie[1]

        del request.headers['cookie']
        request.headers['cookie'] = f'auth_token=' + self.session.cookies.get(
            'auth_token') + '; ct0=' + self.session.cookies.get('ct0')

    def solve_captcha(self,
                      session: tls_client.sessions.Session,
                      account_token: str) -> None:
        try:
            self.session = session

            while True:
                task_id, response_text = create_task()

                if not task_id:
                    logger.error(f'{account_token} | Ошибка при создании Task на решение капчи, ответ: {response_text}')
                    continue

                task_result, response_text = get_task_result(task_id=task_id)

                if not task_result:
                    logger.error(f'{account_token} | Ошибка при решении капчи, ответ: {response_text}')
                    continue

                captcha_result: str = response_text
                break

            if self.session.proxies:
                options = {
                    'proxy': {
                        'http': session.proxies['http'],
                        'https': session.proxies['http'],
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
            co.add_experimental_option('excludeSwitches', ['enable-logging'])

            driver = webdriver.Chrome(seleniumwire_options=options,
                                      options=co)
            wait = WebDriverWait(driver, 180)

            driver.get('https://twitter.com/account/access')
            driver.add_cookie({
                'name': 'auth_token',
                'value': self.session.cookies.get('auth_token')
            })
            driver.get('https://twitter.com/account/access')
            wait.until(EC.element_to_be_clickable((By.ID, 'arkose_iframe')))
            driver.switch_to.frame(driver.find_element(By.ID, 'arkose_iframe'))
            driver.execute_script(
                'parent.postMessage(JSON.stringify({eventId:"challenge-complete",payload:{sessionToken:"' + captcha_result + '"}}),"*")')
            wait.until(EC.url_contains("https://twitter.com/home"))

            logger.success(f'{account_token} | Аккаунт успешно разморожен')

        except Exception as error:
            logger.error(f'{account_token} | Неизвестная ошибка при попытке разморозить аккаунт: {error}')
