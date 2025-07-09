import random
import time
from datetime import datetime, timezone
import json
import base58
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from fake_useragent import UserAgent
import requests
from colorama import init, Fore, Style
import os
import urllib3
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading

# --- НАСТРОЙКИ ---
# Количество одновременно работающих аккаунтов (потоков)
MAX_WORKERS = 2
# ВАШ API ключ от сервиса 2Captcha
TWOCAPTCHA_API_KEY = "YOUR_TWOCAPTCHA_API_KEY"
# Ключ сайта для решения капчи Turnstile
CAPTCHA_SITE_KEY = "0x4AAAAAABRnkPBT6yl0YKs1"

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ И ИНИЦИАЛИЗАЦИЯ ---
print_lock = threading.Lock()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


class Colors:
    RESET, CYAN, GREEN, YELLOW, RED, WHITE = Style.RESET_ALL, Fore.CYAN, Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.WHITE


class Logger:
    @staticmethod
    def _log(icon, color, msg, account_index=None):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = f" [АККАУНТ {account_index}]" if account_index is not None else ""
        with print_lock:
            print(f"{color}{icon} [{timestamp}]{prefix} {msg}")

    @staticmethod
    def info(msg, account_index=None): Logger._log("ℹ️", Colors.CYAN, msg, account_index)

    @staticmethod
    def warn(msg, account_index=None): Logger._log("⚠️", Colors.YELLOW, msg, account_index)

    @staticmethod
    def error(msg, account_index=None): Logger._log("❌", Colors.RED, msg, account_index)

    @staticmethod
    def success(msg, account_index=None): Logger._log("✅", Colors.GREEN, msg, account_index)

    @staticmethod
    def step(msg, account_index=None): Logger._log("➡️", Colors.WHITE, msg, account_index)


def load_from_file(filename, error_msg):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        Logger.error(f"{error_msg}: {e}")
        return []


def load_private_keys(): return load_from_file('accounts.txt', "Не удалось загрузить accounts.txt")


def load_proxies(): return load_from_file('proxies.txt', "Не удалось загрузить proxies.txt")


def load_prompts():
    try:
        with open('prompts.json', 'r', encoding='utf-8') as f:
            return json.load(f).get('prompts', [])
    except Exception as e:
        Logger.error(f"Не удалось загрузить prompts.json: {e}")
        return []


USER_AGENTS_FILE = "user_agents.json"
user_agents = {}
if os.path.exists(USER_AGENTS_FILE):
    with open(USER_AGENTS_FILE, 'r') as f: user_agents = json.load(f)


def get_user_agent(address):
    if address not in user_agents:
        user_agents[address] = UserAgent().random
        with open(USER_AGENTS_FILE, 'w') as f: json.dump(user_agents, f, indent=2)
    return user_agents[address]


def get_headers(address):
    return {
        'accept': '*/*', 'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/json', 'origin': 'https://www.bitquant.io',
        'referer': 'https://www.bitquant.io/', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site',
        'user-agent': get_user_agent(address),
    }


def create_session(proxy):
    session = requests.Session()
    if proxy: session.proxies.update({'http': proxy, 'https': proxy})
    return session


def sign_message(message, secret_key, account_index):
    try:
        decoded_key = base58.b58decode(secret_key)
        if len(decoded_key) != 64: raise ValueError("Неверная длина приватного ключа")
        signature = SigningKey(decoded_key[:32]).sign(message.encode('utf-8')).signature
        return base58.b58encode(signature).decode('utf-8')
    except Exception as e:
        Logger.error(f"Не удалось подписать сообщение: {e}", account_index)
        raise


async def solve_captcha_2captcha(proxy, account_index):
    Logger.info("Начинаю решение капчи...", account_index)
    task_payload = {"type": "TurnstileTask", "websiteURL": "https://www.bitquant.io", "websiteKey": CAPTCHA_SITE_KEY}
    if proxy:
        try:
            cleaned_proxy = proxy.replace("http://", "").replace("https://", "")
            creds, location = cleaned_proxy.split('@');
            login, password = creds.split(':');
            ip, port = location.split(':')
            task_payload.update({'proxyType': 'http', 'proxyAddress': ip, 'proxyPort': int(port), 'proxyLogin': login,
                                 'proxyPassword': password})
            Logger.info("Прокси будет использован для решения капчи.", account_index)
        except Exception as e:
            Logger.warn(f"Не удалось обработать прокси. Ошибка: {e}. Капча решается без прокси.", account_index)

    full_payload = {"clientKey": TWOCAPTCHA_API_KEY, "task": task_payload}
    try:
        res = await asyncio.to_thread(requests.post, "https://api.2captcha.com/createTask", json=full_payload,
                                      timeout=20)
        res.raise_for_status();
        task_id = res.json().get('taskId')
        if not task_id: raise Exception(f"Ошибка создания задачи 2Captcha: {res.text}")
        Logger.info(f"Задача на решение капчи создана. ID: {task_id}", account_index)
        await asyncio.sleep(15)
        result_payload = {"clientKey": TWOCAPTCHA_API_KEY, "taskId": task_id}
        for _ in range(30):
            res = await asyncio.to_thread(requests.post, "https://api.2captcha.com/getTaskResult", json=result_payload,
                                          timeout=10)
            res.raise_for_status();
            result = res.json()
            if result.get('status') == 'ready':
                Logger.success("Капча успешно решена!", account_index)
                return result['solution']['token']
            if result.get('errorId', 0) > 0: raise Exception(f"Ошибка 2Captcha: {result.get('errorDescription')}")
            await asyncio.sleep(5)
        raise Exception("Время ожидания решения капчи истекло.")
    except Exception as e:
        Logger.error(f"Критическая ошибка при решении капчи: {e}", account_index)
        raise


async def make_request(session, method, url, address, account_index, data=None, headers_extra=None):
    headers = get_headers(address)
    if headers_extra: headers.update(headers_extra)
    try:
        response = await asyncio.to_thread(getattr(session, method.lower()), url, headers=headers, json=data,
                                           timeout=30, verify=False)
        response.raise_for_status()
        return response.json() if response.content else None
    except Exception as e:
        Logger.error(f"Ошибка запроса {method.upper()} {url}: {e}", account_index)
        raise


async def perform_chats(address, id_token, session, proxy, remaining, account_index):
    prompts = load_prompts()
    if not prompts:
        Logger.error("Файл prompts.json не найден или пуст.", account_index);
        return

    Logger.info(f"Начинаю общение. Осталось сообщений: {remaining}", account_index)
    conversation_history = []
    for i in range(remaining):
        prompt = random.choice(prompts)
        Logger.info(f"Отправляю сообщение {i + 1}/{remaining}: '{prompt}'", account_index)
        try:
            captcha_token = await solve_captcha_2captcha(proxy, account_index)
            message_data = {'type': 'user', 'message': prompt}
            payload = {
                'captchaToken': captcha_token,
                'context': {'conversationHistory': conversation_history, 'address': address, 'availablePools': [],
                            'poolPositions': []},
                'message': message_data
            }
            response = await make_request(session, 'post', 'https://quant-api.opengradient.ai/api/v2/agent/run',
                                          address, account_index, data=payload,
                                          headers_extra={'Authorization': f"Bearer {id_token}"})

            assistant_message = response.get('message', 'Нет ответа')
            Logger.success(f"Получен ответ: {assistant_message[:70]}...", account_index)

            conversation_history.append(message_data)
            conversation_history.append({'type': 'assistant', 'message': assistant_message, 'pools': [], 'tokens': []})

            await asyncio.sleep(random.uniform(5, 10))
        except Exception as e:
            Logger.error(f"Не удалось отправить сообщение {i + 1}: {e}", account_index)
            continue
    Logger.success("Общение в чате завершено.", account_index)


async def process_account(index, private_key, total_accounts):
    print(f"\n{Colors.GREEN}{'=' * 80}{Colors.RESET}")
    Logger.step(f"НАЧИНАЮ РАБОТУ С АККАУНТОМ {index}/{total_accounts}")

    proxies = load_proxies()
    proxy = random.choice(proxies) if proxies else None
    session = create_session(proxy)
    try:
        public_key = base58.b58encode(SigningKey(base58.b58decode(private_key)[:32]).verify_key.encode()).decode(
            'utf-8')
        Logger.info(f"Публичный ключ: {public_key}", index)

        response = await make_request(session, 'get',
                                      f"https://quant-api.opengradient.ai/api/whitelisted?address={public_key}",
                                      public_key, index)
        if not response.get('allowed'):
            Logger.warn("Аккаунт не в вайтлисте.", index);
            return
        Logger.success("Аккаунт в вайтлисте!", index)

        nonce, issued_at = int(time.time() * 1000), datetime.now(timezone.utc).isoformat()
        message = (
            f"bitquant.io wants you to sign in with your **blockchain** account:\n{public_key}\n\nURI: https://bitquant.io\nVersion: 1\nChain ID: solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\nNonce: {nonce}\nIssued At: {issued_at}")
        signature = sign_message(message, private_key, index)
        captcha_token = await solve_captcha_2captcha(proxy, index)

        verify_data = {'address': public_key, 'message': message, 'signature': signature}
        token = (await make_request(session, 'post', 'https://quant-api.opengradient.ai/api/verify/solana', public_key,
                                    index, data=verify_data, headers_extra={'x-captcha-token': captcha_token}))['token']
        Logger.success("Подпись проверена, токен получен.", index)

        id_token = (await make_request(session, 'post',
                                       'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM',
                                       public_key, index, data={'token': token, 'returnSecureToken': True}))['idToken']
        Logger.success("Успешный вход в аккаунт!", index)

        stats = await make_request(session, 'get',
                                   f"https://quant-api.opengradient.ai/api/activity/stats?address={public_key}",
                                   public_key, index, headers_extra={'authorization': f"Bearer {id_token}"})
        Logger.info(
            f"Статистика: {stats['points']} очков. Сегодня: {stats['daily_message_count']}/{stats['daily_message_limit']}",
            index)

        remaining = stats['daily_message_limit'] - stats['daily_message_count']
        if remaining > 0:
            await perform_chats(public_key, id_token, session, proxy, remaining, index)
        else:
            Logger.warn("Достигнут дневной лимит сообщений.", index)

        Logger.success(f"Работа с аккаунтом {index} успешно завершена.", index)
    except Exception as e:
        Logger.error(f"Произошла критическая ошибка: {e}", index)
    finally:
        session.close()


async def main():
    private_keys = load_private_keys()
    if not private_keys: return

    first_key, *other_keys = private_keys
    random.shuffle(other_keys);
    sorted_keys = [first_key] + other_keys
    Logger.info(f"Загружено {len(sorted_keys)} аккаунтов. Первый зафиксирован, остальные перемешаны.")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(executor, lambda p=p_key, i=i: asyncio.run(process_account(i, p, len(sorted_keys))), )
            for i, p_key in enumerate(sorted_keys, 1)]
        await asyncio.gather(*tasks)

    Logger.success("Все аккаунты обработаны. Скрипт завершает работу.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        Logger.warn("Скрипт остановлен пользователем.")
    except Exception as e:
        Logger.error(f"Непредвиденная ошибка в main: {e}")
