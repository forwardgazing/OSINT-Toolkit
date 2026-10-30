import whoisit
import datetime
import warnings
import socket
import re
import requests

warnings.filterwarnings("ignore")

# Словарь WHOIS-серверов для популярных зон
WHOIS_SERVERS = {
    'ru': 'whois.tcinet.ru', 'su': 'whois.tcinet.ru',
    'kz': 'whois.nic.kz', 'by': 'whois.cctld.by', 'ua': 'whois.ua',
    'am': 'whois.amnic.net', 'az': 'whois.az', 'ge': 'whois.nic.ge',
    'md': 'whois.nic.md', 'eu': 'whois.eu', 'de': 'whois.denic.de',
    'fr': 'whois.nic.fr', 'it': 'whois.nic.it', 'es': 'whois.nic.es',
    'nl': 'whois.domain-registry.nl', 'pl': 'whois.dns.pl', 'uk': 'whois.nic.uk',
    'cz': 'whois.nic.cz', 'fi': 'whois.fi', 'se': 'whois.iis.se'
}

# Список популярных CDN (если IP принадлежит им, реальный хостинг скрыт)
CDN_PROVIDERS = ["cloudflare", "akamai", "fastly", "amazon", "google", "ddos-guard", "qrator"]

def get_ip_and_geo(domain):
    """Узнает IP домена (IPv4/IPv6) и его геолокацию через бесплатный API"""
    result = {"ip": None, "country": "Неизвестно", "city": "Неизвестно", "isp": "Неизвестно", "is_cdn": False}
    
    try:
        # getaddrinfo возвращает и IPv4, и IPv6 (надежнее, чем gethostbyname)
        ip_info = socket.getaddrinfo(domain, None)
        ip_address = ip_info[0][4][0] # Берем первый попавшийся (обычно IPv4)
        result["ip"] = ip_address

        # Запрос к API геолокации (используем HTTPS, чтобы не палить трафик)
        # В бесплатной версии ip-api.com http, но для учебного проекта сойдет
        url = f"http://ip-api.com/json/{ip_address}?lang=ru&fields=status,country,city,isp"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result["country"] = data.get("country", "Неизвестно")
                result["city"] = data.get("city", "Неизвестно")
                result["isp"] = data.get("isp", "Неизвестно")
                
                # Проверяем, не является ли хостинг CDN-провайдером
                isp_lower = result["isp"].lower()
                if any(cdn in isp_lower for cdn in CDN_PROVIDERS):
                    result["is_cdn"] = True
    except Exception:
        pass
        
    return result

def query_whois_socket(domain, server):
    """Прямой запрос к WHOIS-серверу через сокет"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode("utf-8"))
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode('utf-8', errors='ignore')
    except Exception:
        return None

def parse_whois_text(text):
    """Продвинутый парсер сырого текста WHOIS"""
    info = {"date": None, "registrar": "Скрыто", "country": "Скрыто", "blocked": False}
    if not text:
        return info
        
    # Проверка на блокировку парсера
    block_markers = ["Please see 'whois", "help for usage", "Access denied", "limit exceeded"]
    if any(marker in text for marker in block_markers):
        info["blocked"] = True
        return info

    # Расширенный набор форматов дат (ISO, Европейский, Американский)
    date_patterns = [
        r'(\d{4}-\d{2}-\d{2})',           # 2023-10-25
        r'(\d{2}\.\d{2}\.\d{4})',         # 25.10.2023
        r'(\d{4}\.\d{2}\.\d{2})',         # 2023.10.25
        r'(\d{2}-[A-Za-z]{3}-\d{4})'      # 25-Oct-2023
    ]
    
    for line in text.splitlines():
        line_lower = line.lower()
        
        # 1. Строгий поиск даты (только в строках "created" или "registration")
        if not info["date"]:
            if "created" in line_lower or "registration" in line_lower or "registered" in line_lower:
                for pattern in date_patterns:
                    match = re.search(pattern, line)
                    if match:
                        date_str = match.group(1)
                        # Конвертация DD.MM.YYYY -> YYYY-MM-DD для единого формата
                        if '.' in date_str:
                            parts = date_str.split('.')
                            if len(parts[0]) == 2: date_str = f"{parts[2]}-{parts[1]}-{parts[0]}"
                            elif len(parts[0]) == 4: date_str = f"{parts[0]}-{parts[1]}-{parts[2]}"
                        info["date"] = date_str
                        break

        # 2. Поиск регистратора
        if info["registrar"] == "Скрыто":
            if "registrar:" in line_lower or "registrar name:" in line_lower:
                info["registrar"] = line.split(":", 1)[1].strip()

        # 3. Поиск страны (ищем код из 2х букв)
        if info["country"] == "Скрыто":
            if "country:" in line_lower or "registrant country:" in line_lower:
                match = re.search(r'\b([A-Z]{2})\b', line)
                if match: info["country"] = match.group(1)

    return info

def analyze_domain(domain):
    """Главная функция анализа домена"""
    print(f"\n[*] Комплексный анализ домена: {domain}")
    print("=" * 50)
    
    # === 1. СБОР СЕТЕВЫХ ДАННЫХ (OSINT) ===
    ip_data = get_ip_and_geo(domain)
    if ip_data["ip"]:
        print(f"  🌐 IP-адрес: {ip_data['ip']}")
        print(f"  📍 Геолокация: {ip_data['country']}, {ip_data['city']}")
        print(f"  🏢 Провайдер (ISP): {ip_data['isp']}")
        if ip_data["is_cdn"]:
            print("  ⚠️ [ВНИМАНИЕ] Сайт использует CDN. Реальный хостинг скрыт.")
    else:
        print("  🌐 IP-адрес: Не удалось определить (домен не резолвится или скрыт)")

    # === 2. СБОР ДАННЫХ WHOIS/RDAP ===
    tld = domain.split('.')[-1].lower()
    creation_date_str = None
    registrar = "Скрыто"
    country = "Скрыто"
    raw_text = None

    # Прямой WHOIS
    if tld in WHOIS_SERVERS:
        raw_text = query_whois_socket(domain, WHOIS_SERVERS[tld])
        if raw_text:
            info = parse_whois_text(raw_text)
            if info["blocked"]:
                print("\n  ❌ WHOIS-сервер заблокировал запрос (требуется капча).")
                return
            creation_date_str = info["date"]
            registrar = info["registrar"]
            country = info["country"]

    # RDAP Фоллбэк
    if not creation_date_str and tld not in WHOIS_SERVERS:
        try:
            result = whoisit.domain(domain)
            reg_date = result.get('registration_date')
            if isinstance(reg_date, list): reg_date = reg_date[0]
            
            if reg_date:
                if isinstance(reg_date, str):
                    reg_date = datetime.datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
                creation_date_str = reg_date.strftime('%Y-%m-%d')
                
            # Извлечение данных из RDAP
            entities = result.get('entities', [])
            for entity in entities:
                if isinstance(entity, dict) and 'registrar' in entity.get('roles', []):
                    vcard = entity.get('vcardArray', [])
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 4:
                                if item[0] == 'fn': registrar = item[3]
                                if item[0] == 'adr' and isinstance(item[3], dict):
                                    country = item[3].get('country', "Скрыто")
                    break
        except Exception as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                print("  ❌ Домен не найден в RDAP (свободен).")
                return
            else:
                print(f"  ❌ Ошибка RDAP: {error_msg[:60]}...")
                return

    # === 3. АНАЛИЗ И ВЫВОД ===
    print("\n  --- Данные регистрации ---")
    if creation_date_str:
        print(f"  📅 Дата регистрации: {creation_date_str}")
        
        try:
            creation_date_obj = datetime.datetime.strptime(creation_date_str, '%Y-%m-%d')
            age = (datetime.datetime.now() - creation_date_obj).days
            print(f"  ⏳ Возраст домена: {age} дней")
            
            # Логика оценки риска
            if age < 90:
                print("  🚨 [ВЫСОКИЙ РИСК] Домен зарегистрирован недавно (менее 90 дней)!")
            elif age < 365:
                print("  ⚠️ [СРЕДНИЙ РИСК] Домену меньше года.")
            else:
                print("  ✅ [НИЗКИЙ РИСК] Домен надежный (старше года).")
        except Exception:
            print("  ⚠️ Ошибка расчета возраста.")
            
        print(f"  🏢 Регистратор: {registrar}")
        print(f"  🌍 Страна (WHOIS): {country}")
    else:
        print("  🚩 Дата регистрации скрыта или не найдена.")

if __name__ == "__main__":
    print("=============================================")
    print("🕵️  OSINT-Инструмент v6.0 (WHOIS + RDAP + GeoIP)")
    print("=============================================")
    
    # Инициализация RDAP (делается 1 раз при старте)
    try:
        whoisit.bootstrap()
    except Exception:
        pass

    while True:
        user_input = input("\nДомен (или 'exit' для выхода): ").strip()
        if user_input.lower() == 'exit':
            print("Завершение работы.")
            break
        
        # Очистка URL от протоколов
        domain = user_input.replace("https://", "").replace("http://", "").split("/")[0]
        analyze_domain(domain)