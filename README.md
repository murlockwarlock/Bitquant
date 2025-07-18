# BitQuant.io Automation Bot

Это многопоточный Python-скрипт для автоматизации ежедневной активности на платформе **BitQuant.io**. Скрипт использует приватные ключи от кошельков **Solana** для аутентификации, решает капчу и отправляет сообщения в чат до исчерпания дневного лимита.

---

## ✨ Ключевые возможности

* **Многопоточность:** Одновременная обработка нескольких аккаунтов для максимальной эффективности.
* **Solana-аутентификация:** Корректная работа с приватными ключами формата Base58 для подписи сообщений.
* **Решение капчи:** Интеграция с сервисом **2Captcha** для автоматического решения Turnstile.
* **Поддержка прокси:** Возможность использования прокси для всех запросов.
* **Автоматическое общение:** Скрипт самостоятельно ведет диалог в чате, используя заранее заготовленные промпты.
* **Проверка вайтлиста:** Автоматическая проверка, находится ли аккаунт в списке допущенных к использованию.
* **Сохранение User-Agent'ов:** Для каждого кошелька генерируется и сохраняется уникальный User-Agent для повышения стабильности сессий.
* **Продвинутое логирование:** Удобный и наглядный вывод информации в консоль с разделением по аккаунтам.

---

## 🛠️ Гайд по установке и настройке

### Шаг 1: Предварительные требования

1.  **Python 3.8+** ([скачать](https://www.python.org/downloads/)).
2.  **Приватные ключи** от ваших Solana-кошельков в формате **Base58**.
3.  **Аккаунт 2Captcha**: Зарегистрируйтесь на [2captcha.com](https://2captcha.com/), пополните баланс и скопируйте ваш **API-ключ**.

### Шаг 2: Установка

1.  Создайте папку для проекта и поместите туда ваш скрипт (например, `bitquant_bot.py`).
2.  В этой же папке создайте файл `requirements.txt` и вставьте в него:
    ```txt
    requests
    fake-useragent
    colorama
    pynacl
    base58
    urllib3
    ```
3.  Откройте терминал (командную строку) в папке проекта и выполните команду для установки зависимостей:
    ```bash
    pip install -r requirements.txt
    ```

### Шаг 3: Конфигурация

1.  **Настройте API-ключ 2Captcha:**
    * Откройте файл скрипта (`bitquant_bot.py`).
    * Найдите строку: `TWOCAPTCHA_API_KEY = "..."`
    * **Замените** значение в кавычках на ваш **API-ключ от 2Captcha**.

2.  **(Опционально) Настройте количество потоков:**
    * Вы можете изменить количество одновременно работающих аккаунтов, изменив значение переменной `MAX_WORKERS`.

3.  **Создайте `accounts.txt`:**
    * Создайте файл и вставьте в него приватные ключи от ваших Solana-кошельков в формате **Base58**, **каждый ключ с новой строки**.
        ```txt
        2AbC...dEfG
        3XyZ...wVuT
        ```
    * ⚠️ **ВНИМАНИЕ!** Это ваши приватные ключи. Никогда и никому не передавайте этот файл.

4.  **Создайте `proxies.txt` (Опционально):**
    * Если вы хотите использовать прокси, создайте этот файл.
    * Добавьте прокси в формате `login:password@ip:port`, **каждый прокси с новой строки**.
        ```txt
        user1:pass1@123.45.67.89:1234
        user2:pass2@98.76.54.32:4321
        ```

5.  **Создайте `prompts.json`:**
    * Создайте файл, который будет содержать список промптов для общения в чате.
    * Структура файла должна быть строго как в примере ниже:
        ```json
        {
          "prompts": [
            "What are the latest trends in DeFi?",
            "Can you explain the difference between proof-of-work and proof-of-stake in simple terms?",
            "Tell me about the Solana ecosystem.",
            "What is the role of AI in quantitative trading?"
          ]
        }
        ```

---

## 🚀 Запуск

1.  Откройте терминал в папке со скриптом.
2.  Выполните команду:
    ```bash
    python bitquant_bot.py
    ```
3.  Скрипт начнет работу в несколько потоков. Наблюдайте за процессом в консоли.

---

## ⚠️ Важная информация

* **Безопасность приватных ключей:** Ваш главный приоритет. Не храните файл `accounts.txt` на публичных репозиториях. Файл `.gitignore` в этом поможет.
* **Ответственность:** Вы используете этот скрипт на свой страх и риск. Автоматизация может нарушать условия использования некоторых сервисов.
