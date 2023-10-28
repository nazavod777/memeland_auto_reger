[![Telegram channel](https://img.shields.io/endpoint?url=https://runkit.io/damiankrawczyk/telegram-badge/branches/master?url=https://t.me/n4z4v0d)](https://t.me/n4z4v0d)
[![PyPI supported Python versions](https://img.shields.io/pypi/pyversions/better-automation.svg)](https://www.python.org/downloads/release/python-3116/)
[![works badge](https://cdn.jsdelivr.net/gh/nikku/works-on-my-machine@v0.2.0/badge.svg)](https://github.com/nikku/works-on-my-machine)
# Только 3.11.6 Python-версия

### CONFIG.PY  
**SITE_KEY** - _SITEKEY для решения капчи Twitter при разморозке аккаунта, не менять_  
**SITE_URL** - _SITEURL Twitter для разморозки аккаунта_  
**FIRSTCAPTCHA_API_KEY** - _API KEY с https://1stcaptcha.com/ (не забудьте пополнить баланс)_  
**CHANGE_PROXY_URL** - _Ссылка для смены IP при использовании мобильных прокси со сменой по ссылке_  
**REPATS_COUNT** - _Количество попыток для повторения выполнения скрипта в случае ошибки_
**ACCOUNT_TOO_NEW_ATTEMPTS** - _Количество попыток повторного выполнения авторизации MEME при ошибке Account Too New_  
**UNAUTHORIZED_ATTEMPTS** - _Количество попыток повторого выполнения действий при ошибке Unauthorized_  
**SLEEP_BETWEEN_TASKS** - _Время сна между выполнением заданий MEME (число, ex: 1, 5, 10 // диапазон, ex: 1-5, 5-7, 2-6)_  
**SLEEP_AFTER_PROXY_CHANGING** - _Время сна после смены Proxy_  

### accounts.txt  
_Заполняем **auth_token**'s от аккаунтов, каждый с новой строки_  

### private_keys.txt  
_Приват-ключи от кошельков, которые привязывать к аккаунтам (при желании привязывать собственные кошельки. Можно оставить файл пустым - тогда софт будет сам регистрировать кошельки и привязывать их к аккаунту)_  

### proxies.txt  
_Список прокси (можно вставить одну мобильную, софт берет рандомно из файла). Формат - type://user:pass@ip:port // type://ip:port_  

### log files  
_**empty_attemps.txt** - файл с токенами аккаунтов, попытки для повтора которых закончились (см config.py -> REPATS_COUNT)_  
_**registered.txt** - файл успешно зарегистрированных аккаунтов_  
_**suspended_accounts.txt** - файл токенов аккаунтов, заблокированных в Twitter_  
_**account_too_new.txt** - Файл токенов аккаунтов, не подходящих по параметрам_

# DONATE (_any evm_) - 0xDEADf12DE9A24b47Da0a43E1bA70B8972F5296F2