#!/usr/bin/env python3
"""
🎀 TetoVPN v2.12 — WARP только через --warp-include (быстрая загрузка в Hiddify)
"""
# ─────────────────────────────────────────────────────────────
# 📦 ИМПОРТЫ
# ─────────────────────────────────────────────────────────────
from __future__ import annotations
import re, json, base64, socket, time, logging, sys, os, random, gzip, argparse, ssl, ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Set
from urllib.parse import urlparse, parse_qs, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────────────────────
# ⚙️ КОНФИГУРАЦИЯ
# ─────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "channels": ["cvedc_vpn", "obhodbelogolista67", "Vlesstrogan", "hiddifycode", "V2RayTunSub", "bypassInterne"],
    "limit_per_channel": 40,
    "modes": {
        "TetoVPN": {"per_country": 3, "max_total": 25, "description": "🎀 TetoVPN — ~25 лучших", "title": "🎀 TetoVPN", "filename": "TetoVPN"},
        "Reserve": {"max_total": 100, "description": "🔁 Reserve — все живые", "title": "🔁 Reserve", "filename": "Reserve"},
        "ТунеядецProxy": {"per_country": 3, "max_total": 25, "description": "🐌 ТунеядецProxy — для друзей", "title": "ТунеядецProxy", "filename": "alt_ussr"},
    },
    "ping_timeout": 3.0, "ping_workers": 50, "min_latency_ms": 2000,
    "output_dir": "configs",
    # ✅ WARP ОТКЛЮЧЁН ПО УМОЛЧАНИЮ (None = не добавлять)
    "warp_detour": None,
    # Значение, которое используется при --warp-include
    "warp_detour_value": "warp://162.159.192.79:3476?ifp=10-20&ifps=20-60&ifpd=5-10&ifpm=m4&&detour=warp://162.159.195.203:8319#⚡ СКОРОСТНОЙ СЕРВЕР ДЛЯ ИИ ИГР И СОЦСЕТЕЙ ⚡",
    "warp_fixed_name": "⚡ СКОРОСТНОЙ СЕРВЕР ДЛЯ ИИ ИГР И СОЦСЕТЕЙ ⚡",
    "update_interval": 12, "total_quota": 10737418240000000, "expire_timestamp": 2546249531,
    "geolite_path": "GeoLite2-Country.mmdb",
    "blacklist_keywords": ["черн", "black", "🏴", "bad", "low", "slow", "test"],
    "whitelist_keywords": ["бел", "white", "🏳️", "good", "premium", "pro", "vip"],
    "ru_whitelist": {
        "enabled": True,
        "cache_dir": ".ru_whitelist_cache",
        "urls": {
            "ip": "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/ipwhitelist.txt",
            "cidr": "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt",
            "domain": "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt",
        },
        "cache_ttl_hours": 24,
    },
}

# ─────────────────────────────────────────────────────────────
# 🔧 УТИЛИТЫ
# ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def b64enc(s: str) -> str: return base64.b64encode(s.encode()).decode()
def b64dec(s: str) -> str: return base64.b64decode(s.encode()).decode()
def now_str() -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def ensure_dir(p: str): os.makedirs(p, exist_ok=True)

def is_gzip(data: bytes) -> bool:
    """Проверяет, является ли байты gzip-сжатыми (magic bytes 0x1f8b)"""
    return len(data) >= 2 and data[:2] == b'\x1f\x8b'

# ─────────────────────────────────────────────────────────────
# 🛡️ RUSSIA WHITELIST CHECKER
# ─────────────────────────────────────────────────────────────
class RussiaWhitelistChecker:
    """Проверка хостов/SNI по Russia Mobile Internet Whitelist"""
    
    def __init__(self, cache_dir: str, ttl_hours: int = 24, urls: Optional[Dict[str, str]] = None):
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_hours * 3600
        self.urls = urls or DEFAULT_CONFIG["ru_whitelist"]["urls"]
        self._ip_whitelist: Set[str] = set()
        self._cidr_whitelist: List[ipaddress.IPv4Network] = []
        self._domain_whitelist: Set[str] = set()
        self._loaded_at: Optional[float] = None
        self._load_or_fetch()
    
    def _load_or_fetch(self):
        """Загружает кэш или скачивает свежие списки"""
        ensure_dir(self.cache_dir)
        cache_file = os.path.join(self.cache_dir, "timestamp.txt")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    loaded_at = float(f.read().strip())
                if time.time() - loaded_at < self.ttl_seconds:
                    self._load_from_cache()
                    logger.info(f"🛡️ Russia whitelist загружен из кэша ({self.cache_dir})")
                    return
            except: pass
        logger.info("🛡️ Скачиваю Russia Mobile Internet Whitelist...")
        try:
            self._fetch_and_save("ip", self.urls["ip"])
            self._fetch_and_save("cidr", self.urls["cidr"])
            self._fetch_and_save("domain", self.urls["domain"])
            with open(os.path.join(self.cache_dir, "timestamp.txt"), "w") as f:
                f.write(str(time.time()))
            self._load_from_cache()
            logger.info(f"✅ Russia whitelist обновлён: {len(self._ip_whitelist)} IP, {len(self._cidr_whitelist)} CIDR, {len(self._domain_whitelist)} доменов")
        except Exception as e:
            logger.warning(f"⚠️ Не удалось обновить Russia whitelist: {e}")
            self._load_from_cache()
    
    def _fetch_and_save(self, name: str, url: str):
        """Скачивает файл и сохраняет в кэш"""
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        path = os.path.join(self.cache_dir, f"{name}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(resp.text)
    
    def _load_from_cache(self):
        """Загружает списки из кэша"""
        self._ip_whitelist.clear()
        self._cidr_whitelist.clear()
        self._domain_whitelist.clear()
        ip_file = os.path.join(self.cache_dir, "ip.txt")
        if os.path.exists(ip_file):
            with open(ip_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._ip_whitelist.add(line)
        cidr_file = os.path.join(self.cache_dir, "cidr.txt")
        if os.path.exists(cidr_file):
            with open(cidr_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            self._cidr_whitelist.append(ipaddress.ip_network(line, strict=False))
                        except: pass
        domain_file = os.path.join(self.cache_dir, "domain.txt")
        if os.path.exists(domain_file):
            with open(domain_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self._domain_whitelist.add(line)
    
    def _resolve_host_to_ip(self, host: str) -> Optional[str]:
        """Пытается резолвить хост в IP (для проверки по IP-списку)"""
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except:
            return None
    
    def is_whitelisted(self, host: str, sni: Optional[str] = None) -> bool:
        """Проверяет, находится ли хост/SNI в России-вайтлисте."""
        host_lower = host.lower()
        for domain in self._domain_whitelist:
            if host_lower == domain or host_lower.endswith("." + domain):
                return True
            if sni:
                sni_lower = sni.lower()
                if sni_lower == domain or sni_lower.endswith("." + domain):
                    return True
        if host in self._ip_whitelist:
            return True
        resolved_ip = self._resolve_host_to_ip(host)
        if resolved_ip and resolved_ip in self._ip_whitelist:
            return True
        if resolved_ip:
            try:
                ip_obj = ipaddress.ip_address(resolved_ip)
                for cidr in self._cidr_whitelist:
                    if ip_obj in cidr:
                        return True
            except: pass
        return False
    
    def get_marker(self, host: str, sni: Optional[str] = None) -> str:
        """✅ Возвращает 🏳️ для вайтлиста, 🏴 для остальных"""
        if self.is_whitelisted(host, sni):
            return "🏳️"
        return "🏴"

# ─────────────────────────────────────────────────────────────
# 🏷️ LIST FILTER: чёрные/белые списки (🏴/🏳️ маркеры)
# ─────────────────────────────────────────────────────────────
class ListFilter:
    def __init__(self, black_keywords: List[str], white_keywords: List[str]):
        self.black_keywords = [k.lower() for k in black_keywords]
        self.white_keywords = [k.lower() for k in white_keywords]
    
    def check(self, text: str) -> Tuple[bool, bool, str]:
        text_low = text.lower()
        is_black = any(kw in text_low for kw in self.black_keywords)
        is_white = any(kw in text_low for kw in self.white_keywords)
        if is_white: marker = "🏳️"
        elif is_black: marker = "🏴"
        else: marker = ""
        return is_black, is_white, marker
    
    def should_include(self, text: str, no_black: bool, white_only: bool) -> bool:
        is_black, is_white, _ = self.check(text)
        if white_only and not is_white: return False
        if no_black and is_black: return False
        return True

# ─────────────────────────────────────────────────────────────
# 🌍 GEO: ТОЛЬКО ЛОКАЛЬНЫЙ GeoLite2 + эвристика
# ─────────────────────────────────────────────────────────────
class GeoLookup:
    COUNTRY_NAMES = {
        "AD": ("🇦🇩", "Андорра"), "AE": ("🇦🇪", "ОАЭ"), "AF": ("🇦🇫", "Афганистан"),
        "AL": ("🇦🇱", "Албания"), "AM": ("🇦🇲", "Армения"), "AO": ("🇦🇴", "Ангола"),
        "AR": ("🇦🇷", "Аргентина"), "AT": ("🇦🇹", "Австрия"), "AU": ("🇦🇺", "Австралия"),
        "AZ": ("🇦🇿", "Азербайджан"), "BA": ("🇧🇦", "Босния"), "BD": ("🇧🇩", "Бангладеш"),
        "BE": ("🇧🇪", "Бельгия"), "BG": ("🇧🇬", "Болгария"), "BH": ("🇧🇭", "Бахрейн"),
        "BR": ("🇧🇷", "Бразилия"), "BY": ("🇧🇾", "Беларусь"), "CA": ("🇨🇦", "Канада"),
        "CH": ("🇨🇭", "Швейцария"), "CL": ("🇨🇱", "Чили"), "CN": ("🇨🇳", "Китай"),
        "CO": ("🇨🇴", "Колумбия"), "CR": ("🇨🇷", "Коста-Рика"), "CZ": ("🇨🇿", "Чехия"),
        "DE": ("🇩🇪", "Германия"), "DK": ("🇩🇰", "Дания"), "EE": ("🇪🇪", "Эстония"),
        "EG": ("🇪🇬", "Египет"), "ES": ("🇪🇸", "Испания"), "FI": ("🇫🇮", "Финляндия"),
        "FR": ("🇫🇷", "Франция"), "GB": ("🇬🇧", "Великобритания"), "GE": ("🇬🇪", "Грузия"),
        "GR": ("🇬🇷", "Греция"), "HK": ("🇭🇰", "Гонконг"), "HR": ("🇭🇷", "Хорватия"),
        "HU": ("🇭🇺", "Венгрия"), "ID": ("🇮🇩", "Индонезия"), "IE": ("🇮🇪", "Ирландия"),
        "IL": ("🇮🇱", "Израиль"), "IN": ("🇮🇳", "Индия"), "IR": ("🇮🇷", "Иран"),
        "IS": ("🇮🇸", "Исландия"), "IT": ("🇮🇹", "Италия"), "JP": ("🇯🇵", "Япония"),
        "KE": ("🇰🇪", "Кения"), "KG": ("🇰🇬", "Кыргызстан"), "KR": ("🇰🇷", "Южная Корея"),
        "KZ": ("🇰🇿", "Казахстан"), "LT": ("🇱🇹", "Литва"), "LU": ("🇱🇺", "Люксембург"),
        "LV": ("🇱🇻", "Латвия"), "MD": ("🇲🇩", "Молдова"), "MK": ("🇲🇰", "Македония"),
        "MN": ("🇲🇳", "Монголия"), "MX": ("🇲🇽", "Мексика"), "MY": ("🇲🇾", "Малайзия"),
        "NG": ("🇳🇬", "Нигерия"), "NL": ("🇳🇱", "Нидерланды"), "NO": ("🇳🇴", "Норвегия"),
        "NZ": ("🇳🇿", "Новая Зеландия"), "PE": ("🇵🇪", "Перу"), "PH": ("🇵🇭", "Филиппины"),
        "PK": ("🇵🇰", "Пакистан"), "PL": ("🇵🇱", "Польша"), "PT": ("🇵🇹", "Португалия"),
        "RO": ("🇷🇴", "Румыния"), "RS": ("🇷🇸", "Сербия"), "RU": ("🇷🇺", "Россия"),
        "SA": ("🇸🇦", "Саудовская Аравия"), "SE": ("🇸🇪", "Швеция"), "SG": ("🇸🇬", "Сингапур"),
        "SI": ("🇸🇮", "Словения"), "SK": ("🇸🇰", "Словакия"), "TH": ("🇹🇭", "Таиланд"),
        "TR": ("🇹🇷", "Турция"), "TW": ("🇹🇼", "Тайвань"), "UA": ("🇺🇦", "Украина"),
        "US": ("🇺🇸", "США"), "UZ": ("🇺🇿", "Узбекистан"), "VN": ("🇻🇳", "Вьетнам"),
        "ZA": ("🇿🇦", "ЮАР"),
    }
    
    def __init__(self, mmdb_path: str):
        self.mmdb_path = mmdb_path
        self._reader = None
        self._load_mmdb()
    
    def _load_mmdb(self):
        if not os.path.exists(self.mmdb_path):
            logger.warning(f"⚠️ GeoLite2 не найден: {self.mmdb_path} → только эвристика")
            return
        try:
            import maxminddb
            self._reader = maxminddb.open_database(self.mmdb_path)
            logger.info(f"🌍 GeoLite2 загружен (оффлайн): {self.mmdb_path}")
        except ImportError:
            logger.warning("⚠️ Установи `maxminddb` для точного гео: pip install maxminddb")
            self._reader = None
        except Exception as e:
            logger.warning(f"⚠️ Ошибка загрузки GeoLite2: {e}")
            self._reader = None
    
    def _is_ip(self, s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False
    
    def lookup(self, host: str) -> Optional[str]:
        if not self._is_ip(host):
            return self._heuristic_lookup(host)
        if self._reader:
            try:
                result = self._reader.get(host)
                if result and "country" in result and "iso_code" in result["country"]:
                    return result["country"]["iso_code"]
            except: pass
        return self._heuristic_lookup(host)
    
    def _heuristic_lookup(self, host: str) -> Optional[str]:
        host = host.lower()
        for code in self.COUNTRY_NAMES:
            code_l = code.lower()
            if f".{code_l}" in host or f"{code_l}." in host or f"-{code_l}-" in host:
                return code
        tld_map = {
            ".ru":"RU",".ua":"UA",".by":"BY",".kz":"KZ",".md":"MD",".ge":"GE",".am":"AM",".az":"AZ",
            ".de":"DE",".fr":"FR",".nl":"NL",".uk":"GB",".co.uk":"GB",".us":"US",".pl":"PL",".tr":"TR",
            ".jp":"JP",".sg":"SG",".in":"IN",".br":"BR",".ca":"CA",".au":"AU",".kr":"KR",".it":"IT",
            ".es":"ES",".fi":"FI",".se":"SE",".no":"NO",".cz":"CZ",".at":"AT",".ch":"CH",".ee":"EE",
            ".lv":"LV",".lt":"LT",".ro":"RO",".bg":"BG",".rs":"RS",".hr":"HR",".hu":"HU",".sk":"SK",
            ".si":"SI",".gr":"GR",".pt":"PT",".ie":"IE",".dk":"DK",".il":"IL",".ae":"AE",".hk":"HK",
            ".tw":"TW",".th":"TH",".vn":"VN",".my":"MY",".id":"ID",".ph":"PH",".za":"ZA",".eg":"EG",
            ".mx":"MX",".ar":"AR",".cl":"CL",".co":"CO",".pe":"PE",".nz":"NZ",
        }
        for tld, code in tld_map.items():
            if host.endswith(tld): return code
        return None
    
    def get_flag_name(self, code: Optional[str]) -> Tuple[str, str]:
        if code and code in self.COUNTRY_NAMES:
            return self.COUNTRY_NAMES[code]
        return ("🌐", "Мир")
    
    def close(self):
        if self._reader and hasattr(self._reader, "close"):
            self._reader.close()

# ─────────────────────────────────────────────────────────────
# 🏷️ RENAMER: ❤️ Резерв для "Мир", 🏴/🏳️ ПОСЛЕ флага, НАСИЛЬНОЕ переименование
# ─────────────────────────────────────────────────────────────
class ConfigRenamer:
    TYPE_KEYWORDS = {"lte": ["lte", "4g", "mobile", "мобильный", "сот", "cellular"]}
    
    @classmethod
    def detect_type(cls, original_name: str, host: str) -> Optional[str]:
        text = (original_name + " " + host).lower()
        if any(kw in text for kw in cls.TYPE_KEYWORDS["lte"]): return "LTE"
        return None
    
    @classmethod
    def rename(cls, cfg: ProxyConfig, geo: GeoLookup, rank_in_group: int, 
               list_filter: Optional[ListFilter] = None, 
               ru_whitelist: Optional[RussiaWhitelistChecker] = None) -> str:
        # ✅ НАСИЛЬНОЕ ПЕРЕИМЕНОВАНИЕ: игнорируем cfg.nickname, берём только хост
        country_code = geo.lookup(cfg.host)
        flag, country_ru = geo.get_flag_name(country_code)
        cfg_type = cls.detect_type("", cfg.host)
        
        # ✅ ФИКС: если страна "Мир" → используем "❤️ Резерв"
        if country_ru == "Мир":
            flag = "❤️"
            country_ru = "Резерв"
        
        # Маркеры от списков (🏴/🏳️)
        marker = ""
        if list_filter:
            _, _, marker = list_filter.check(cfg.host)
        
        # Маркер от Russia whitelist (🏳️/🏴)
        ru_marker = ""
        if ru_whitelist:
            sni = None
            try:
                parsed = urlparse(cfg.raw)
                params = parse_qs(parsed.query)
                if "sni" in params:
                    sni = params["sni"][0]
            except: pass
            ru_marker = ru_whitelist.get_marker(cfg.host, sni)
        
        # ✅ Порядок: флаг → маркер списка → [RU] → тип → страна → номер
        parts = [flag]
        if marker: parts.append(marker)
        if ru_marker: parts.append(ru_marker)
        if cfg_type: parts.append(cfg_type)
        parts.append(country_ru)
        parts.append(str(rank_in_group))
        
        return " ".join(parts)

# ─────────────────────────────────────────────────────────────
# 🤖 AUTO CONFIG GENERATOR
# ─────────────────────────────────────────────────────────────
class AutoConfigGenerator:
    @staticmethod
    def generate_auto_configs(configs: List[ProxyConfig], geo: GeoLookup, 
                              list_filter: Optional[ListFilter] = None,
                              ru_whitelist: Optional[RussiaWhitelistChecker] = None) -> List[ProxyConfig]:
        auto_configs = []
        filtered = [c for c in configs if c.is_alive and (not list_filter or list_filter.should_include(c.host, no_black=False, white_only=False))]
        lte_configs = [c for c in filtered if ConfigRenamer.detect_type("", c.host) == "LTE"]
        regular_configs = [c for c in filtered if ConfigRenamer.detect_type("", c.host) is None]
        lte_configs.sort(key=lambda c: c.latency_ms or 9999)
        regular_configs.sort(key=lambda c: c.latency_ms or 9999)
        if lte_configs:
            best = lte_configs[0]
            auto_configs.append(ProxyConfig(raw=best.raw, protocol=best.protocol, host=best.host, port=best.port, nickname="🏳️ LTE Авто", country="🏳️", latency_ms=best.latency_ms, is_alive=True, meta={"auto": True, "type": "lte"}))
        if regular_configs:
            best = regular_configs[0]
            auto_configs.append(ProxyConfig(raw=best.raw, protocol=best.protocol, host=best.host, port=best.port, nickname="🏴 Авто", country="🏴", latency_ms=best.latency_ms, is_alive=True, meta={"auto": True, "type": "regular"}))
        return auto_configs

# ─────────────────────────────────────────────────────────────
# 🌐 HTTP-КЛИЕНТ
# ─────────────────────────────────────────────────────────────
class HTTPClient:
    HEADERS_DEFAULT = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8", "Accept-Encoding": "gzip, deflate, br",
        "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120"', "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"', "Connection": "keep-alive",
    }
    HEADERS_HAPP = {
        "User-Agent": "Happ/3.13.0", "X-Device-Os": "Android", "X-Device-Locale": "ru",
        "X-Device-Model": "ELP-NX1", "X-Ver-Os": "15", "Accept-Encoding": "gzip",
        "Connection": "close", "X-Hwid": "", "X-Real-Ip": "", "X-Forwarded-For": ""
    }
    HEADERS_V2RAYTUN = {"User-Agent": "V2RayTun/5.23.73 (Android; 16)"}
    _session: Optional[requests.Session] = None
    _proxy: Optional[str] = None
    
    @staticmethod
    def _randomize_happ(headers: dict) -> dict:
        h = headers.copy()
        h["X-Hwid"] = ''.join(random.choices("0123456789abcdef", k=16))
        h["X-Real-Ip"] = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        h["X-Forwarded-For"] = h["X-Real-Ip"]
        return h
    
    @classmethod
    def init_session(cls, proxy: Optional[str] = None) -> requests.Session:
        cls._proxy = proxy
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter); session.mount("http://", adapter)
        ctx = ssl.create_default_context()
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return session
    
    @classmethod
    def get(cls, url: str, timeout: float = 20, mode: str = "default") -> Optional[str]:
        if cls._session is None: cls._session = cls.init_session(cls._proxy)
        headers = {"default": cls.HEADERS_DEFAULT, "happ": cls._randomize_happ(cls.HEADERS_HAPP),
                   "v2raytun": cls.HEADERS_V2RAYTUN, "gist": {"User-Agent": "curl/8.4.0"}}.get(mode, cls.HEADERS_DEFAULT).copy()
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
        proxies = {"http": cls._proxy, "https": cls._proxy} if cls._proxy else None
        try:
            time.sleep(random.uniform(0.3, 1.2))
            resp = cls._session.get(url, headers=headers, timeout=timeout, allow_redirects=True, proxies=proxies)
            resp.raise_for_status()
            if (resp.headers.get("Content-Encoding") == "gzip" or resp.content[:2] == b'\x1f\x8b') and is_gzip(resp.content):
                try: return gzip.decompress(resp.content).decode("utf-8", errors="ignore")
                except: pass
            return resp.text
        except Exception as e:
            logger.debug(f"HTTP error {url}: {e}")
            return None

# ─────────────────────────────────────────────────────────────
# 📡 TELEGRAM SCRAPER
# ─────────────────────────────────────────────────────────────
class TGScraper:
    URI_PATTERN = re.compile(r'(?:vmess|vless|trojan|ss|ssr|warp)://[^\s\'"<>{}\[\]|\^`]+', re.IGNORECASE)
    SELECTORS = {"post": "div.tgme_widget_message", "text": "div.tgme_widget_message_text"}
    
    @staticmethod
    def scrape(username: str, limit: int = 40, debug: bool = False) -> List[str]:
        username = username.lstrip("@"); url = f"https://t.me/s/{username}"; texts = []
        try:
            html = HTTPClient.get(url, mode="default")
            if not html: return []
            if debug:
                with open(f"debug_{username}.html", "w", encoding="utf-8") as f: f.write(html)
            soup = BeautifulSoup(html, "html.parser")
            for el in soup.select(TGScraper.SELECTORS["post"])[:limit]:
                code_el = el.select_one("code, pre")
                if code_el:
                    text = code_el.get_text(separator="\n", strip=True)
                    if TGScraper.URI_PATTERN.search(text): texts.append(text); continue
                text_el = el.select_one(TGScraper.SELECTORS["text"])
                if text_el:
                    for br in text_el.find_all("br"): br.replace_with("\n")
                    raw = text_el.get_text(separator="\n", strip=True)
                    uris = TGScraper.URI_PATTERN.findall(raw)
                    if uris: texts.append("\n".join(uris)); continue
                post_text = el.get_text(separator=" ", strip=True)
                uris = TGScraper.URI_PATTERN.findall(post_text)
                if uris: texts.append("\n".join(uris))
            logger.info(f"✅ @{username}: {len(texts)} постов с конфигами")
            return texts
        except Exception as e:
            logger.warning(f"⚠️ @{username}: {e}")
            return []

# ─────────────────────────────────────────────────────────────
# 🔗 SUBSCRIPTION FETCHER
# ─────────────────────────────────────────────────────────────
class SubFetcher:
    URI_RE = re.compile(r'(?:vmess|vless|trojan|ss|ssr|warp)://[^\s\'"<>{}\[\]|\^`]+', re.IGNORECASE)
    SUB_LINK_RE = re.compile(r'https?://[^\s<>"{}]+', re.IGNORECASE)
    
    @classmethod
    def extract_links(cls, text: str) -> Tuple[List[str], List[str]]:
        uris = cls.URI_RE.findall(text)
        subs = []
        for m in cls.SUB_LINK_RE.finditer(text):
            url = m.group(0).rstrip(").,;")
            if url.startswith(("http://", "https://")):
                subs.append(url)
        return list(set(uris)), list(set(subs))
    
    @classmethod
    def fetch_subscription(cls, url: str) -> List[str]:
        if not url.startswith(("http://", "https://")):
            logger.debug(f"⏭️ Пропускаю не-http ссылку: {url}")
            return []
        mode = "default"
        if "happ" in url.lower() or any(h in url.lower() for h in ["obhod","belogo","lista"]):
            mode = "happ"
        elif "v2raytun" in url.lower():
            mode = "v2raytun"
        elif "gist" in url.lower() or "raw" in url.lower():
            mode = "gist"
        content = HTTPClient.get(url, mode=mode)
        if not content:
            logger.debug(f"⚠️ Не удалось получить {url}")
            return []
        try:
            decoded = b64dec(content.strip())
            if decoded.count("://") > 2:
                content = decoded
                logger.debug(f"✅ {url}: base64-декодировано")
        except:
            pass
        found_uris = cls.URI_RE.findall(content)
        if found_uris:
            logger.debug(f"✅ {url}: найдено {len(found_uris)} proxy-URI (подписка)")
            return [u.strip() for u in found_uris if u.strip()]
        logger.debug(f"⏭️ {url}: proxy-URI не найдены")
        return []

# ─────────────────────────────────────────────────────────────
# 🧩 CONFIG PARSER & MODEL
# ─────────────────────────────────────────────────────────────
@dataclass
class ProxyConfig:
    raw: str; protocol: str; host: str; port: int; nickname: str
    country: Optional[str] = None; latency_ms: Optional[float] = None
    is_alive: bool = False; meta: Dict[str, Any] = field(default_factory=dict)
    @property
    def key(self) -> str: return f"{self.host}:{self.port}"

class ConfigParser:
    @classmethod
    def parse(cls, uri: str) -> Optional[ProxyConfig]:
        try:
            proto = uri.split("://")[0].lower()
            if proto == "warp": return cls._parse_warp(uri)
            if proto == "vmess": return cls._parse_vmess(uri)
            if proto == "vless": return cls._parse_vless(uri)
            if proto == "trojan": return cls._parse_trojan(uri)
            if proto in ("ss","ssr"): return cls._parse_ss(uri, proto)
            return cls._fallback(uri, proto)
        except: return None
    
    @classmethod
    def _parse_vmess(cls, uri: str) -> Optional[ProxyConfig]:
        b64 = uri.split("://",1)[1].strip(); b64 += "="*(4-len(b64)%4)
        data = json.loads(base64.b64decode(b64))
        host, port = data.get("add",""), int(data.get("port",0))
        if not host or not port: return None
        return ProxyConfig(raw=uri, protocol="vmess", host=host, port=port, nickname=data.get("ps","vmess"), country=None, meta=data)
    
    @classmethod
    def _parse_vless(cls, uri: str) -> Optional[ProxyConfig]:
        p = urlparse(uri); host, port = p.hostname or "", p.port or 443
        if not host: return None
        return ProxyConfig(raw=uri, protocol="vless", host=host, port=port, nickname=unquote(p.fragment) or "vless", country=None, meta={"params":parse_qs(p.query)})
    
    @classmethod
    def _parse_trojan(cls, uri: str) -> Optional[ProxyConfig]:
        p = urlparse(uri); host, port = p.hostname or "", p.port or 443
        if not host: return None
        return ProxyConfig(raw=uri, protocol="trojan", host=host, port=port, nickname=unquote(p.fragment) or "trojan", country=None)
    
    @classmethod
    def _parse_ss(cls, uri: str, proto: str) -> Optional[ProxyConfig]:
        raw = uri.split("://",1)[1]
        if "@" not in raw: return None
        userinfo, hostport = raw.rsplit("@",1)
        try: decoded = base64.b64decode(userinfo).decode()
        except: decoded = unquote(userinfo)
        host = hostport.split(":")[0].split("#")[0]
        port_s = hostport.split(":")[1].split("#")[0]
        port = int(port_s) if port_s.isdigit() else 443
        nick = unquote(hostport.split("#")[1]) if "#" in hostport else f"{proto}-{host}"
        return ProxyConfig(raw=uri, protocol=proto, host=host, port=port, nickname=nick, country=None)
    
    @classmethod
    def _parse_warp(cls, uri: str) -> Optional[ProxyConfig]:
        p = urlparse(uri); host, port = p.hostname or "", p.port or 2408
        return ProxyConfig(raw=uri, protocol="warp", host=host, port=port, nickname=unquote(p.fragment) or "WARP", country="🌐", meta={"params":parse_qs(p.query)})
    
    @classmethod
    def _fallback(cls, uri: str, proto: str) -> Optional[ProxyConfig]:
        p = urlparse(uri)
        if p.hostname and p.port:
            return ProxyConfig(raw=uri, protocol=proto, host=p.hostname, port=p.port, nickname=f"{proto}", country=None)
        return None

# ─────────────────────────────────────────────────────────────
# 🏓 PINGER
# ─────────────────────────────────────────────────────────────
class Pinger:
    @staticmethod
    def check(cfg: ProxyConfig, timeout: float = 3.0) -> ProxyConfig:
        t0 = time.monotonic()
        try:
            with socket.create_connection((cfg.host, cfg.port), timeout=timeout): cfg.is_alive = True
        except: cfg.is_alive = False
        finally: cfg.latency_ms = round((time.monotonic() - t0) * 1000, 2)
        return cfg
    
    @staticmethod
    def ping_batch(configs: List[ProxyConfig], timeout: float, workers: int) -> List[ProxyConfig]:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(Pinger.check, c, timeout) for c in configs]
            for f in as_completed(futures):
                try: f.result()
                except: pass
        configs.sort(key=lambda c: (not c.is_alive, c.latency_ms if c.is_alive else 9999))
        return configs

# ─────────────────────────────────────────────────────────────
# 📋 SUB GENERATOR (✅ v2.12: WARP только через --warp-include)
# ─────────────────────────────────────────────────────────────
class SubGenerator:
    # ✅ Регулярка для проверки правильного формата имени: флаг + [маркер] + [тип] + страна + номер
    VALID_NAME_PATTERN = re.compile(r'^[🇦-🇿❤️].*?\s\d+$')
    
    @staticmethod
    def _is_valid_name(fragment: str) -> bool:
        """Проверяет, соответствует ли имя ожидаемому формату"""
        if not fragment:
            return False
        decoded = unquote(fragment).strip()
        return bool(SubGenerator.VALID_NAME_PATTERN.match(decoded))
    
    @staticmethod
    def _force_rename(uri: str, geo: GeoLookup, list_filter: Optional[ListFilter], 
                      ru_whitelist: Optional[RussiaWhitelistChecker], rank: int = 1) -> str:
        """✅ Принудительно переименовывает URI, даже если что-то пошло не так"""
        try:
            cfg = ConfigParser.parse(uri)
            if not cfg or not cfg.host:
                return uri  # Не можем переименовать, возвращаем как есть
            new_name = ConfigRenamer.rename(cfg, geo, rank, list_filter, ru_whitelist)
            # Добавляем # с новым именем, даже если его не было
            if "#" in uri:
                base, _ = uri.rsplit("#", 1)
                return f"{base}#{quote(new_name)}"
            else:
                return f"{uri}#{quote(new_name)}"
        except Exception as e:
            logger.debug(f"⚠️ Не удалось переименовать: {e}")
            return uri  # В крайнем случае возвращаем оригинал
    
    @staticmethod
    def generate(configs: List[ProxyConfig], title: str, mode_cfg: dict, warp: Optional[str], 
                 geo: GeoLookup, list_filter: Optional[ListFilter], ru_whitelist: Optional[RussiaWhitelistChecker],
                 no_black: bool, white_only: bool) -> str:
        lines = [
            f"//profile-title: base64:{b64enc(title)}",
            f"//profile-update-interval: {DEFAULT_CONFIG['update_interval']}",
            f"//subscription-userinfo: upload=0; download=0; total={DEFAULT_CONFIG['total_quota']}; expire={DEFAULT_CONFIG['expire_timestamp']}",
            f"//last update on: {now_str()}",
            f"//mode: {mode_cfg.get('description', '')}", ""
        ]
        alive = [c for c in configs if c.is_alive and (c.latency_ms or 9999) <= DEFAULT_CONFIG['min_latency_ms']
                 and (not list_filter or list_filter.should_include(c.host, no_black, white_only))]
        groups: Dict[str, List[ProxyConfig]] = {}
        for c in alive:
            code = geo.lookup(c.host)
            cfg_type = ConfigRenamer.detect_type("", c.host) or ""
            key = f"{code}_{cfg_type}"
            if key not in groups: groups[key] = []
            groups[key].append(c)
        renamed = []
        for key, group in groups.items():
            def sort_key(c):
                is_black, is_white, _ = list_filter.check(c.host) if list_filter else (False, False, "")
                priority = 0 if is_white else (2 if is_black else 1)
                return (priority, c.latency_ms or 9999)
            group.sort(key=sort_key)
            for rank, cfg in enumerate(group, 1):
                new_name = ConfigRenamer.rename(cfg, geo, rank, list_filter, ru_whitelist)
                renamed.append(SubGenerator._update_uri_name(cfg, new_name))
        auto_configs = AutoConfigGenerator.generate_auto_configs(alive, geo, list_filter, ru_whitelist)
        for ac in auto_configs: lines.append(ac.raw)
        if "per_country" in mode_cfg:
            limit = mode_cfg["per_country"]; max_total = mode_cfg.get("max_total", 25)
            by_country: Dict[str, List[ProxyConfig]] = {}
            for c in renamed:
                cc = geo.lookup(c.host) or "XX"
                if cc not in by_country: by_country[cc] = []
                if len(by_country[cc]) < limit: by_country[cc].append(c)
            selected = []
            for flag in sorted(by_country.keys()):
                for cfg in by_country[flag]:
                    if len(selected) < max_total: selected.append(cfg)
            for cfg in selected: lines.append(cfg.raw)
        elif "max_total" in mode_cfg:
            for c in renamed[:mode_cfg["max_total"]]: lines.append(c.raw)
        
        # ✅ WARP: добавляем ТОЛЬКО если warp не None и не пустая строка
        if warp:
            warp_name = DEFAULT_CONFIG.get("warp_fixed_name", "⚡ СКОРОСТНОЙ СЕРВЕР ДЛЯ ИИ ИГР И СОЦСЕТЕЙ ⚡")
            if "#" in warp:
                base, _ = warp.rsplit("#", 1)
                lines.append(f"{base}#{quote(warp_name)}")
            else:
                lines.append(f"{warp}#{quote(warp_name)}")
        
        # ✅✅✅ ФИНАЛЬНАЯ ПРОВЕРКА: гарантируем, что ВСЕ конфиги имеют правильное имя
        final_lines = []
        for line in lines:
            # Пропускаем заголовки и пустые строки
            if line.startswith("//") or not line.strip():
                final_lines.append(line)
                continue
            # Проверяем только proxy-URI
            if any(line.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "ssr://", "warp://"]):
                # Для WARP с фиксированным именем — пропускаем проверку
                if line.startswith("warp://") and "СКОРОСТНОЙ СЕРВЕР" in line:
                    final_lines.append(line)
                    continue
                # Извлекаем фрагмент (имя)
                if "#" in line:
                    base, fragment = line.rsplit("#", 1)
                    # Если имя пустое или не соответствует формату — принудительно переименовываем
                    if not SubGenerator._is_valid_name(fragment):
                        logger.debug(f"🔧 Принудительное переименование: {fragment[:30]}...")
                        final_lines.append(SubGenerator._force_rename(line, geo, list_filter, ru_whitelist))
                    else:
                        final_lines.append(line)
                else:
                    # Если # вообще нет — добавляем с новым именем
                    logger.debug(f"🔧 Добавление # для: {line[:50]}...")
                    final_lines.append(SubGenerator._force_rename(line, geo, list_filter, ru_whitelist))
            else:
                final_lines.append(line)
        
        return "\n".join(final_lines)
    
    @staticmethod
    def _update_uri_name(cfg: ProxyConfig, new_name: str) -> ProxyConfig:
        """✅ ФИКС: если нет #, добавляем его с новым именем"""
        try:
            if "#" in cfg.raw:
                base, _ = cfg.raw.rsplit("#", 1)
                new_uri = f"{base}#{quote(new_name)}"
            else:
                # ✅ Если # нет — добавляем его в конец
                new_uri = f"{cfg.raw}#{quote(new_name)}"
            return ProxyConfig(raw=new_uri, protocol=cfg.protocol, host=cfg.host, port=cfg.port,
                              nickname=new_name, country=cfg.country, latency_ms=cfg.latency_ms,
                              is_alive=cfg.is_alive, meta=cfg.meta.copy())
        except:
            return cfg

# ─────────────────────────────────────────────────────────────
# 🚀 MAIN + ARGPARSE
# ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="🎀 TetoVPN v2.12 — WARP только через --warp-include")
    p.add_argument("-c","--channels",type=str,help="Каналы через запятую")
    p.add_argument("-l","--limit",type=int,default=40,help="Лимит постов")
    p.add_argument("-o","--output",type=str,default="configs",help="Папка вывода")
    p.add_argument("-d","--debug",action="store_true",help="Режим отладки")
    p.add_argument("-n","--no-ping",action="store_true",help="Пропустить пинг")
    p.add_argument("-m","--modes",type=str,help="Режимы через запятую")
    p.add_argument("-w","--warp",type=str,help="WARP-детур (переопределяет значение по умолчанию)")
    p.add_argument("-p","--proxy",type=str,help="Прокси URL")
    p.add_argument("--geo-path",type=str,help="Путь к GeoLite2-Country.mmdb")
    p.add_argument("--no-black",action="store_true",help="Исключить чёрные списки")
    p.add_argument("--white-only",action="store_true",help="Только белые списки")
    p.add_argument("--no-ru-whitelist",action="store_true",help="Отключить Russia whitelist проверку")
    p.add_argument("--ru-cache",type=str,help="Путь для кэша Russia whitelist")
    # ✅ НОВЫЙ ФЛАГ: включать WARP только явно
    p.add_argument("--warp-include", action="store_true", help="Включить WARP detour (по умолчанию отключён)")
    return p.parse_args()

def main():
    args = parse_args()
    if args.channels: DEFAULT_CONFIG["channels"] = [ch.strip().lstrip("@") for ch in args.channels.split(",")]
    DEFAULT_CONFIG["limit_per_channel"] = args.limit
    DEFAULT_CONFIG["output_dir"] = args.output
    # ✅ WARP: по умолчанию None, включается только через --warp-include или --warp
    if args.warp is not None:
        # Если пользователь явно указал --warp "значение" — используем его
        DEFAULT_CONFIG["warp_detour"] = args.warp if args.warp else None
    elif args.warp_include:
        # Если указан --warp-include — используем значение из конфига
        DEFAULT_CONFIG["warp_detour"] = DEFAULT_CONFIG.get("warp_detour_value")
    # Иначе оставляем None (WARP отключён)
    
    if args.modes: DEFAULT_CONFIG["modes"] = {k:v for k,v in DEFAULT_CONFIG["modes"].items() if k in [m.strip() for m in args.modes.split(",")]}
    if args.debug: logging.getLogger().setLevel(logging.DEBUG)
    if args.proxy: HTTPClient._proxy = args.proxy
    geo_path = args.geo_path or DEFAULT_CONFIG["geolite_path"]
    geo = GeoLookup(mmdb_path=geo_path)
    list_filter = ListFilter(DEFAULT_CONFIG["blacklist_keywords"], DEFAULT_CONFIG["whitelist_keywords"])
    ru_whitelist = None
    if not args.no_ru_whitelist and DEFAULT_CONFIG["ru_whitelist"]["enabled"]:
        cache_dir = args.ru_cache or DEFAULT_CONFIG["ru_whitelist"]["cache_dir"]
        urls = DEFAULT_CONFIG["ru_whitelist"]["urls"]
        ttl = DEFAULT_CONFIG["ru_whitelist"]["cache_ttl_hours"]
        try:
            ru_whitelist = RussiaWhitelistChecker(cache_dir=cache_dir, ttl_hours=ttl, urls=urls)
            logger.info("🛡️ Russia Mobile Whitelist активен")
        except Exception as e:
            logger.warning(f"⚠️ Не удалось инициализировать Russia whitelist: {e}")
    
    warp_status = "✅ ВКЛЮЧЁН" if DEFAULT_CONFIG.get("warp_detour") else "❌ ОТКЛЮЧЁН"
    logger.info(f"🎀 TetoVPN v2.12 | {now_str()} | 📁 {DEFAULT_CONFIG['output_dir']}/ | WARP: {warp_status}")
    logger.info(f"🌍 Гео: {geo_path} ({'GeoLite2+эвристика' if geo._reader else 'только эвристика'})")
    if args.no_black: logger.info("⚫ Исключаем чёрные списки")
    if args.white_only: logger.info("⚪ Только белые списки")
    if ru_whitelist: logger.info("🛡️ Russia whitelist: активен")
    ensure_dir(DEFAULT_CONFIG["output_dir"])
    logger.info(f"📡 Каналы: {', '.join(DEFAULT_CONFIG['channels'])}")
    all_texts = []
    for ch in DEFAULT_CONFIG["channels"]:
        posts = TGScraper.scrape(ch, DEFAULT_CONFIG["limit_per_channel"], args.debug)
        all_texts.extend(posts)
    if not all_texts: logger.error("❌ Нет данных"); geo.close(); return
    logger.info("🔍 Парсинг..."); direct, subs = [], []
    for t in all_texts:
        u,s = SubFetcher.extract_links(t); direct.extend(u); subs.extend(s)
    logger.info(f"   URI: {len(direct)} | Подписки: {len(subs)}")
    fetched = []
    for url in subs:
        uris = SubFetcher.fetch_subscription(url)
        if uris: logger.info(f"   ✅ {url}: +{len(uris)}"); fetched.extend(uris)
    all_uris = list(set(direct + fetched)); logger.info(f"🔑 Уникальных: {len(all_uris)}")
    configs = [c for c in (ConfigParser.parse(u) for u in all_uris) if c and c.host and c.port]
    logger.info(f"✅ Распарсено: {len(configs)}")
    if not args.no_ping:
        logger.info(f"⏳ Пинг {len(configs)}..."); configs = Pinger.ping_batch(configs, DEFAULT_CONFIG["ping_timeout"], DEFAULT_CONFIG["ping_workers"])
    else:
        logger.info("⏭️ Без пинга"); [setattr(c,'is_alive',True) or setattr(c,'latency_ms',0) for c in configs]
    alive = [c for c in configs if c.is_alive]; logger.info(f"✅ Живых: {len(alive)}")
    for name, cfg in DEFAULT_CONFIG["modes"].items():
        logger.info(f"📦 {name}")
        title = cfg.get("title", "🎀 TetoVPN")
        filename = cfg.get("filename", name)
        sub = SubGenerator.generate(configs, title, cfg, DEFAULT_CONFIG.get("warp_detour"), 
                                    geo, list_filter, ru_whitelist, args.no_black, args.white_only)
        with open(f"{DEFAULT_CONFIG['output_dir']}/{filename}.txt","w",encoding="utf-8") as f: f.write(sub)
        with open(f"{DEFAULT_CONFIG['output_dir']}/{filename}.b64","w",encoding="utf-8") as f: f.write(base64.b64encode(sub.encode()).decode())
        logger.info(f"   💾 {filename}.b64 | 🔗 http://127.0.0.1:8080/{filename}.b64")
    geo.close()
    logger.info(f"\n✨ Готово! 📁 {DEFAULT_CONFIG['output_dir']}/")
    logger.info("🎀 TetoVPN loves you 💜")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: logger.info("\n⛔ Стоп")
    except Exception as e: logger.error(f"💥 {e}", exc_info=True); sys.exit(1)
