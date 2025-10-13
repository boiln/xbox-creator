#!/usr/bin/env python3
"""
OPERATION MERCY - XBOX CREATOR
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import string
import time
import weakref
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import rnet

try:
    from colorama import Back, Fore, Style, init

    init(autoreset=True)
    COLORS_AVAILABLE = True

except ImportError:

    class MockColor:
        def __getattr__(self, name):
            return ""

    Fore = Back = Style = MockColor()
    COLORS_AVAILABLE = False


DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"

CLIENT_ID = "1f907974-e22b-4810-a9de-d9647380c97e"
REDIRECT_URI = "https://www.xbox.com/auth/msa?action=loggedIn&locale_hint=en-US"
SCOPE = "xboxlive.signin openid profile offline_access"

XBOX_LIVE_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
SISU_BASE_URL = "https://sisu.xboxlive.com"
XSTS_RELYING_PARTY_PROFILE = "http://xboxlive.com"

FLOW_TOKEN_PATTERNS = [
    re.compile(r'name="PPFT"[^>]*value="([^"]*)"'),
    re.compile(r'name=\\"PPFT\\"[^>]*value=\\"([^\\"]*)\\"\s*/>'),
    re.compile(r'id="i0327"[^>]*value="([^"]*)"'),
    re.compile(r'id=\\"i0327\\"[^>]*value=\\"([^\\"]*)\\"\s*/>'),
]

ACTION_PATTERN = re.compile(r'action="([^"]*)"')
INPUT_PATTERN = re.compile(r'<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"[^>]*>')
CODE_PATTERN = re.compile(r"[?#&]code=([^&]+)")
OPID_PATTERN = re.compile(r"opid=(.+?)&")
ACCESS_TOKEN_PATTERN = re.compile(r"accessToken=([^&]+)")

RANDOM_CHARS = string.ascii_letters + string.digits
RANDOM_CHOICES = list(RANDOM_CHARS)


@dataclass(frozen=True)
class XboxConfig:
    # Network timeouts
    DEFAULT_REQUEST_TIMEOUT: float = 20.0
    DEFAULT_RATE_LIMIT_WAIT: float = 30.0
    KEEPALIVE_EXPIRY: float = 30.0

    # Connection pool settings
    DEFAULT_CONNECTION_POOL_SIZE: int = 100
    DEFAULT_MAX_KEEPALIVE_CONNECTIONS: int = 50

    # Retry settings
    DEFAULT_MAX_RETRIES: int = 3
    DEFAULT_RETRY_DELAY: float = 0.5

    # Concurrency settings
    DEFAULT_MAX_WORKERS: int = 8

    # String generation
    CODE_VERIFIER_LENGTH: int = 43
    CLIENT_REQUEST_ID_LENGTH: int = 32
    STATE_ID_LENGTH: int = 36
    NONCE_LENGTH: int = 36
    GAMERTAG_SUFFIX_LENGTH: int = 15
    GAMERTAG_PREFIX: str = "Gamer"

    # Gamertag reservation
    MAX_GAMERTAG_ATTEMPTS: int = 20
    GAMERTAG_ATTEMPT_DELAY: float = 0.1
    RESERVATION_DURATION: str = "1:00:00"

    # Output formatting
    MAX_LOG_MESSAGE_LENGTH: int = 100
    LOG_TRUNCATION_SUFFIX: str = " .."

    # File paths
    DEFAULT_ACCOUNTS_FILE: str = "accounts.txt"
    GAMERTAGS_FILE: str = "gamertags.txt"
    TOKENS_FILE: str = "tokens.txt"

    # Avatar URL
    DEFAULT_AVATAR_URL: str = "https://dlassets-ssl.xboxlive.com/public/content/ppl/gamerpics/00052-00000-md.png?w=320&h=320"

    # Rate limiting
    RATE_LIMIT_STATUS_CODE: int = 429
    RATE_LIMIT_BUFFER_SECONDS: int = 10

    # Output truncation
    MAX_OUTPUT_SIZE_BYTES: int = 60 * 1024  # 60KB


class XboxLogFormatter(logging.Formatter):
    def __init__(self, max_length: int = XboxConfig.MAX_LOG_MESSAGE_LENGTH) -> None:
        super().__init__()
        self.max_length = max_length

        self.colors: Dict[str, str] = {
            "OK": f"{Fore.GREEN}[   OK   ]{Style.RESET_ALL}",
            "FAILED": f"{Fore.RED}[ FAILED ]{Style.RESET_ALL}",
            "WARN": f"{Fore.YELLOW}[  WARN  ]{Style.RESET_ALL}",
            "INFO": f"{Fore.CYAN}[  INFO  ]{Style.RESET_ALL}",
            "DEBUG": f"{Fore.BLUE}[ DEBUG  ]{Style.RESET_ALL}",
        }

    def _truncate_message(self, message: str) -> str:
        if len(message) <= self.max_length:
            return message
        return message[: self.max_length - 2] + XboxConfig.LOG_TRUNCATION_SUFFIX

    def _get_status_prefix(self, record: logging.LogRecord) -> str:
        message = record.getMessage().lower()

        if "successfully" in message or "created" in message or "obtained" in message:
            return self.colors["OK"]
        elif "failed" in message or "error" in message or "invalid" in message:
            return self.colors["FAILED"]
        elif record.levelname == "WARNING":
            return self.colors["WARN"]
        elif record.levelname == "DEBUG":
            return self.colors["DEBUG"]
        else:
            return self.colors["INFO"]

    def format(self, record: logging.LogRecord) -> str:
        if record.levelname in ("DEBUG", "ERROR", "WARNING", "CRITICAL") or record.exc_info:
            message = record.getMessage()
        else:
            message = self._truncate_message(record.getMessage())

        status = self._get_status_prefix(record)

        return f"{status} {message}"


class Session:
    """Session wrapper that auto-manages cookies"""

    def __init__(self, client: rnet.Client):
        self.client = client
        self.cookies: Dict[str, str] = {}

    def _update_cookies(self, response: rnet.Response) -> None:
        """Extract and store cookies from response"""
        for cookie in response.cookies:
            self.cookies[cookie.name] = cookie.value

    def _apply_cookies(self, headers: Dict[str, str]) -> None:
        """Apply stored cookies to request headers"""
        if self.cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

    def get_cookie(self, name: str) -> Optional[str]:
        """Get cookie value by name"""
        return self.cookies.get(name)

    async def get(
        self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs
    ) -> rnet.Response:
        """GET request with automatic cookie management"""
        headers = headers or {}
        self._apply_cookies(headers)
        response = await self.client.get(url, headers=headers, **kwargs)
        self._update_cookies(response)
        return response

    async def post(
        self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs
    ) -> rnet.Response:
        """POST request with automatic cookie management"""
        headers = headers or {}
        self._apply_cookies(headers)
        response = await self.client.post(url, headers=headers, **kwargs)
        self._update_cookies(response)
        return response


@dataclass
class AccountCredentials:
    email: str
    password: str

    @classmethod
    def from_string(cls, account_string: str, separator: str = ":") -> "AccountCredentials":
        parts = account_string.strip().split(separator, 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid account format: {account_string}")

        return cls(email=parts[0], password=parts[1])


@dataclass
class XboxAccountResult:
    credentials: AccountCredentials
    success: bool
    gamertag: Optional[str] = None
    xuid: Optional[str] = None
    error_message: Optional[str] = None
    processing_time: Optional[float] = None
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class RateLimitInfo:
    current_requests: int
    max_requests: int
    period_seconds: int
    reset_time: Optional[datetime] = None


class XboxAccountCreator:
    def __init__(
        self,
        max_workers: int = XboxConfig.DEFAULT_MAX_WORKERS,
        max_retries: int = XboxConfig.DEFAULT_MAX_RETRIES,
        retry_delay: float = XboxConfig.DEFAULT_RETRY_DELAY,
        request_timeout: float = XboxConfig.DEFAULT_REQUEST_TIMEOUT,
        rate_limit_wait: float = XboxConfig.DEFAULT_RATE_LIMIT_WAIT,
        debug_mode: bool = False,
        proxy_url: Optional[str] = None,
        connection_pool_size: int = XboxConfig.DEFAULT_CONNECTION_POOL_SIZE,
        max_keepalive_connections: int = XboxConfig.DEFAULT_MAX_KEEPALIVE_CONNECTIONS,
    ) -> None:
        self.max_workers: int = max_workers
        self.max_retries: int = max_retries
        self.retry_delay: float = retry_delay
        self.request_timeout: float = request_timeout
        self.rate_limit_wait: float = rate_limit_wait
        self.debug_mode: bool = debug_mode
        self.proxy_url: Optional[str] = proxy_url or os.getenv("HTTPS_PROXY")
        self.connection_pool_size: int = connection_pool_size
        self.max_keepalive_connections: int = max_keepalive_connections

        self._stats_lock: asyncio.Lock = asyncio.Lock()
        self.stats: Dict[str, Union[int, datetime]] = {
            "processed": 0,
            "successful": 0,
            "failed": 0,
            "start_time": datetime.now(),
        }

        self.logger: logging.Logger
        self._setup_logging()

        proxies = None
        if self.proxy_url:

            def _ensure_scheme(url: str) -> str:
                if not url:
                    return url
                if url.startswith("http://") or url.startswith("https://"):
                    return url
                return f"http://{url}"

            prox_val = _ensure_scheme(self.proxy_url)
            proxies = [rnet.Proxy.all(prox_val)]
            self.logger.debug(
                f"Configured single proxy for rnet: {prox_val} (original={self.proxy_url})"
            )

        self.client_config: Dict[str, Any] = {
            "timeout": int(self.request_timeout),
            "read_timeout": int(self.request_timeout),
            "allow_redirects": True,
            "history": True,
            "pool_max_size": self.connection_pool_size,
            "pool_max_idle_per_host": self.max_keepalive_connections,
            "pool_idle_timeout": int(XboxConfig.KEEPALIVE_EXPIRY),
            "verify": False,
            "danger_accept_invalid_certs": True,
            "gzip": True,
            "brotli": True,
            "deflate": True,
            "user_agent": DEFAULT_USER_AGENT,
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Sec-Ch-Ua": '"Not A(Brand";v="99", "Microsoft Edge";v="121", "Chromium";v="121"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
            },
        }

        if proxies:
            self.client_config["proxies"] = proxies

        self._session_cache: weakref.WeakValueDictionary[str, Any] = weakref.WeakValueDictionary()

    def _setup_logging(self) -> None:
        log_level = logging.DEBUG if self.debug_mode else logging.INFO

        self.logger = logging.getLogger("XboxCreator")
        self.logger.setLevel(log_level)

        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = XboxLogFormatter(max_length=100)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

    def _create_client(self) -> rnet.Client:
        config = self.client_config.copy()
        config["cookie_store"] = True
        return rnet.Client(**config)

    def _generate_random_string(self, length: int) -> str:
        return "".join(random.choices(RANDOM_CHOICES, k=length))

    @staticmethod
    def _dict_to_form(data: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Convert a dictionary to a list of tuples for rnet form/query parameters."""
        return [(k, str(v)) for k, v in data.items()]

    @staticmethod
    def _get_header(response: rnet.Response, header_name: str) -> Optional[str]:
        """Get header value from response, handling bytes/string conversion."""
        header_name_lower = header_name.lower()
        for name, value in response.headers.items():
            name_str = name.decode() if isinstance(name, bytes) else name
            if name_str.lower() == header_name_lower:
                return value.decode() if isinstance(value, bytes) else value
        return None

    def _format_duration(self, seconds: float) -> str:
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        else:
            minutes = int(seconds // 60)
            remaining_seconds = seconds % 60

            return f"{minutes}m {remaining_seconds:.1f}s"

    def _extract_flow_token(self, html_content: str) -> Optional[str]:
        for pattern in FLOW_TOKEN_PATTERNS:
            match = pattern.search(html_content)
            if match:
                return match.group(1)

        return None

    def _extract_form_data(self, html_content: str) -> Optional[Dict[str, str]]:
        action_match = ACTION_PATTERN.search(html_content)
        if not action_match:
            return None

        form_data = {"action": action_match.group(1)}

        inputs = INPUT_PATTERN.findall(html_content)
        form_data.update(inputs)

        return form_data

    async def _handle_rate_limit(self, response: rnet.Response) -> Optional[RateLimitInfo]:
        if response.status_code.as_int() != 429:
            return None

        try:
            data = await response.json()
            rate_limit = RateLimitInfo(
                current_requests=data.get("currentRequests", 0),
                max_requests=data.get("maxRequests", 100),
                period_seconds=data.get("periodInSeconds", 600),
            )

            if rate_limit.current_requests >= rate_limit.max_requests:
                wait_time = rate_limit.period_seconds + 10
                self.logger.warning(f"Rate limited. Waiting {wait_time}s ..")
                await asyncio.sleep(wait_time)
            else:
                self.logger.warning(f"Rate limited. Waiting {self.rate_limit_wait}s ..")
                await asyncio.sleep(self.rate_limit_wait)

            return rate_limit

        except Exception:
            await asyncio.sleep(self.rate_limit_wait)

            return None

    async def authenticate_microsoft_account(
        self, client: rnet.Client, credentials: AccountCredentials
    ) -> Optional[Tuple[str, str, Session]]:
        """
        Perform Microsoft OAuth2 authentication flow asynchronously.

        Returns:
            Tuple of (authorization_code, code_verifier, session) if successful, None otherwise
        """
        try:
            self.logger.info(f"Starting auth flow: {credentials.email}")
            self.logger.debug("Creating client_request_id")

            client_request_id: str = self._generate_random_string(
                XboxConfig.CLIENT_REQUEST_ID_LENGTH
            )
            code_verifier: bytes = self._generate_random_string(
                XboxConfig.CODE_VERIFIER_LENGTH
            ).encode()
            code_challenge: str = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest())
                .rstrip(b"=")
                .decode()
            )

            state_data: Dict[str, Any] = {
                "id": self._generate_random_string(XboxConfig.STATE_ID_LENGTH),
                "meta": {"interactionType": "redirect"},
            }
            state = (
                base64.b64encode(json.dumps(state_data).encode()).decode()
                + "|https%3A%2F%2Fwww.xbox.com%2Fen-US%2Fxbox-game-pass%2Fpc-game-pass"
            )

            params: Dict[str, str] = {
                "client_id": CLIENT_ID,
                "scope": SCOPE,
                "redirect_uri": REDIRECT_URI,
                "client-request-id": client_request_id,
                "response_mode": "fragment",
                "response_type": "code",
                "x-client-SKU": "msal.js.browser",
                "x-client-VER": "3.7.0",
                "client_info": "1",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "select_account",
                "nonce": self._generate_random_string(XboxConfig.NONCE_LENGTH),
                "state": state,
            }

            headers = self.client_config["headers"].copy()
            session = Session(client)

            self.logger.debug("About to make OAuth init request")
            response = await session.get(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
                query=self._dict_to_form(params),
                headers=headers,
            )

            self.logger.debug("OAuth init request completed, extracting status")
            response_status = response.status_code.as_int()
            self.logger.debug(f"Extracted status: {response_status}")
            response_url = str(response.url)
            self.logger.debug(f"Extracted URL: {response_url}")
            response_cookies = list(response.cookies) if self.debug_mode else []

            if self.debug_mode:
                self.logger.debug(f"OAuth init status: {response_status}")
                self.logger.debug(f"OAuth init URL: {response_url}")
                self.logger.debug(f"OAuth init cookies: {[c.name for c in response_cookies]}")

            if response_status != 200:
                self.logger.error(f"OAuth2 init failed: {response_status}")
                return None

            response_text = await response.text()
            flow_token = self._extract_flow_token(response_text)
            if not flow_token:
                self.logger.error("Could not extract flow token")
                return None

            uaid = session.get_cookie("uaid")
            if not uaid:
                self.logger.error("Could not extract UAID from cookies")
                return None

            opid_match = OPID_PATTERN.search(response_text)
            if not opid_match:
                self.logger.error("Could not extract OPID")
                return None

            opid = opid_match.group(1)

            email_body = {
                "username": credentials.email,
                "uaid": uaid,
                "isOtherIdpSupported": False,
                "checkPhones": False,
                "isRemoteNGCSupported": True,
                "isCookieBannerShown": False,
                "isFidoSupported": True,
                "forceotclogin": False,
                "otclogindisallowed": False,
                "isExternalFederationDisallowed": False,
                "isRemoteConnectSupported": False,
                "federationFlags": 3,
                "isSignup": False,
                "flowToken": flow_token,
            }

            response = await session.post(
                "https://login.live.com/GetCredentialType.srf",
                json=email_body,
                headers=headers,
            )

            response_status = response.status_code.as_int()
            response_url = str(response.url)
            response_cookies_count = len(list(response.cookies)) if self.debug_mode else 0

            if self.debug_mode:
                self.logger.debug(f"GetCredentialType status: {response_status}")
                self.logger.debug(f"GetCredentialType URL: {response_url}")
                self.logger.debug(f"Cookies after GetCredentialType: {response_cookies_count}")

            if response_status != 200:
                self.logger.error(f"Email submission failed: {response_status}")
                return None

            response_json = await response.json()
            if response_json.get("IfExistsResult") == 1:
                self.logger.error("Microsoft account does not exist")
                return None

            password_body = {
                "i13": "0",
                "login": credentials.email,
                "loginfmt": credentials.email,
                "type": "11",
                "LoginOptions": "3",
                "lrt": "",
                "lrtPartition": "",
                "hisRegion": "",
                "hisScaleUnit": "",
                "passwd": credentials.password,
                "ps": "2",
                "psRNGCDefaultType": "",
                "psRNGCEntropy": "",
                "psRNGCSLK": "",
                "canary": "",
                "ctx": "",
                "hpgrequestid": "",
                "PPFT": flow_token,
                "PPSX": "P",
                "NewUser": "1",
                "FoundMSAs": "",
                "fspost": "0",
                "i21": "0",
                "CookieDisclosure": "0",
                "IsFidoSupported": "1",
                "isSignupPost": "0",
                "isRecoveryAttemptPost": "0",
                "i19": "060601",
            }

            response = await session.post(
                f"https://login.live.com/ppsecure/post.srf?opid={opid}&uaid={uaid}",
                form=self._dict_to_form(password_body),
                headers=headers,
            )

            response_status = response.status_code.as_int()
            response_url = str(response.url)
            response_headers = list(response.headers.items()) if self.debug_mode else []

            if self.debug_mode:
                self.logger.debug(f"Password submission status: {response_status}")
                self.logger.debug(f"Password submission URL: {response_url}")
                for name, value in response_headers:
                    name_str = name.decode() if isinstance(name, bytes) else name
                    value_str = value.decode() if isinstance(value, bytes) else value
                    if name_str.lower() in ["location", "set-cookie"]:
                        self.logger.debug(f"Header {name_str}: {value_str[:100]}")

            if response_status != 200:
                self.logger.error(f"Password submission failed: {response_status}")
                return None

            response_text = await response.text()
            if "Account or password is incorrect" in response_text:
                self.logger.error("Invalid credentials")
                return None

            response, location, response_url = await self._handle_post_auth_forms(
                response_text, response, session, headers, opid, uaid, flow_token, credentials
            )

            url_code_match = CODE_PATTERN.search(response_url)
            location_code_match = CODE_PATTERN.search(location)

            code_match = location_code_match or url_code_match

            if code_match:
                self.logger.info("Successfully obtained auth code")
                return code_match.group(1), code_verifier.decode(), session
            else:
                self.logger.error(
                    f"Could not extract authorization code. Location: {location}, URL: {response.url}"
                )
                return None

        except Exception as e:
            import traceback

            self.logger.error(f"Authentication failed: {e}")
            traceback.print_exc()

            return None

    async def _handle_post_auth_forms(
        self,
        response_text: str,
        response: rnet.Response,
        session: Session,
        headers: Dict[str, str],
        opid: str,
        uaid: str,
        flow_token: str,
        credentials: AccountCredentials,
    ) -> Tuple[rnet.Response, str, str]:
        current_response = response
        current_response_text = response_text

        privacy_form = self._extract_form_data(current_response_text)
        if privacy_form and "privacynotice" in privacy_form.get("action", "").lower():
            self.logger.debug("Submitting privacy notice acceptance")
            current_response = await session.post(
                privacy_form["action"],
                form=self._dict_to_form(privacy_form),
                headers=headers,
            )
            current_response_text = await current_response.text()

        if "Stay signed in?" in current_response_text or "kmsi" in current_response_text.lower():
            self.logger.debug("Handling 'Stay signed in' prompt")
            keep_login_url = (
                f"https://login.live.com/ppsecure/post.srf?nopa=2&uaid={uaid}&opid={opid}"
            )
            keep_login_body = {
                "LoginOptions": "3",
                "type": "28",
                "ctx": "",
                "hpgrequestid": "",
                "PPFT": flow_token,
                "canary": "",
            }

            self.logger.debug("Cancelling keep login state")
            current_response = await session.post(
                keep_login_url,
                form=self._dict_to_form(keep_login_body),
                headers=headers,
                allow_redirects=False,
            )

            if self.debug_mode:
                resp_status = current_response.status_code.as_int()
                resp_headers = list(current_response.headers.items())
                self.logger.debug(f"Response status: {resp_status}")
                self.logger.debug("All headers:")
                for name, value in resp_headers:
                    name_str = name.decode() if isinstance(name, bytes) else name
                    value_str = value.decode() if isinstance(value, bytes) else value
                    self.logger.debug(
                        f"  {name_str}: {value_str[:200] if len(value_str) > 200 else value_str}"
                    )

        for _ in range(10):
            status = current_response.status_code.as_int()
            location = self._get_header(current_response, "location")
            current_url = str(current_response.url)

            if status not in (301, 302, 303, 307, 308):
                break

            if not location:
                break

            if "#code=" in location or "?code=" in location or "&code=" in location:
                self.logger.debug(f"Found code in redirect Location header: {location}")
                return current_response, location, current_url

            self.logger.debug(f"Following final redirect ({status}) to: {location}")
            current_response = await session.get(location, headers=headers)

            new_url = str(current_response.url)
            if "#" in new_url or "code=" in new_url:
                self.logger.debug(f"Found code in redirected URL: {new_url}")
                new_location = self._get_header(current_response, "location") or ""
                return current_response, new_location, new_url

        final_location = self._get_header(current_response, "location") or ""
        final_url = str(current_response.url)
        return current_response, final_location, final_url

    async def create_xbox_account(
        self,
        client: rnet.Client,
        authorization_code: str,
        code_verifier: str,
        credentials: AccountCredentials,
        auth_session: Session,
    ) -> Optional[Dict[str, Any]]:
        """
        Create Xbox Live account.

        Returns:
            Dict with gamertag and XUID if successful, None otherwise
        """
        try:
            self.logger.info("Exchanging auth code for XBL tokens")

            token_body = {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "code": authorization_code,
                "x-client-SKU": "msal.js.browser",
                "x-client-VER": "3.7.0",
                "x-ms-lib-capability": "retry-after, h429",
                "x-client-current-telemetry": "",
                "x-client-last-telemetry": "",
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "client_info": "1",
                "client-request-id": self._generate_random_string(32),
                "X-AnchorMailbox": "",
            }

            headers = self.client_config["headers"].copy()
            headers["origin"] = "https://www.xbox.com"

            session = auth_session

            response = await session.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                form=self._dict_to_form(token_body),
                headers=headers,
            )

            if response.status_code.as_int() != 200:
                self.logger.error(f"Token exchange failed: {response.status_code.as_int()}")
                return None

            token_data = await response.json()
            access_token = token_data.get("access_token")
            id_token = token_data.get("id_token")

            if not access_token or not id_token:
                self.logger.error("Missing tokens in response")
                return None

            try:
                jwt_parts = id_token.split(".")
                if len(jwt_parts) < 2:
                    raise ValueError("Invalid JWT format")

                payload = base64.urlsafe_b64decode(jwt_parts[1] + "=" * (4 - len(jwt_parts[1]) % 4))
                user_data = json.loads(payload)

                login_hint = user_data.get("login_hint")
                msa_id = f"{user_data.get('oid', '')}.{user_data.get('tid', '')}"

            except Exception as e:
                self.logger.error(f"Failed to decode ID token: {e}")
                return None

            self.logger.info("Authenticating with Xbox Live")

            rps_ticket = f"d={access_token}"

            xbox_auth_body = {
                "Properties": {
                    "AuthMethod": "RPS",
                    "RpsTicket": rps_ticket,
                    "SiteName": "user.auth.xboxlive.com",
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            }

            response = await session.post(XBOX_LIVE_AUTH_URL, json=xbox_auth_body, headers=headers)
            if response.status_code.as_int() != 200:
                self.logger.error(f"Xbox Live auth failed: {response.status_code.as_int()}")
                return None

            user_token_data = await response.json()
            user_token = user_token_data["Token"]

            self.logger.info("Connecting to Xbox Live")

            connect_params = {
                "ru": "https://www.xbox.com/auth/msa?action=loggedIn",
                "login_hint": login_hint,
                "userPrompts": "XboxOptionalDataCollection",
                "consent": "required",
                "cv": "",
                "state": f'{{"ru":"https://www.xbox.com/en-US/xbox-game-pass/pc-game-pass","msaId":"{msa_id}","sid":"RETAIL"}}',
            }

            response = await session.get(
                f"{SISU_BASE_URL}/connect/XboxLive",
                query=self._dict_to_form(connect_params),
                headers=headers,
                allow_redirects=False,
            )

            self.logger.debug(f"Initial SISU response status: {response.status_code.as_int()}")
            self.logger.debug(f"Initial SISU response URL: {response.url}")

            redirect_history = []
            for i in range(10):
                status = response.status_code.as_int()
                if status not in (301, 302, 303, 307, 308):
                    self.logger.debug(f"Redirect {i}: Non-redirect status {status}, stopping")
                    break

                redirect_history.append(response)
                location = self._get_header(response, "location")
                if not location:
                    self.logger.debug(f"Redirect {i}: No Location header, stopping")
                    break

                self.logger.debug(f"Redirect {i}: Following to {location[:100]} ..")
                location = location.replace(" ", "%20")
                response = await session.get(location, headers=headers, allow_redirects=False)

            redirect_history.append(response)
            self.logger.debug(f"Total redirect chain length: {len(redirect_history)}")
            self.logger.debug(f"Final response status: {response.status_code.as_int()}")
            self.logger.debug(f"Final response URL: {str(response.url)[:150]}")

            history_list = redirect_history[:-1]

            if "xbox.com" in str(response.url) and "accessToken=" in str(response.url):
                self.logger.info("Xbox Live connection successful")

                url_str = str(response.url)
                access_token_match = ACCESS_TOKEN_PATTERN.search(url_str)

                if access_token_match:
                    xbox_access_token = access_token_match.group(1)
                    existing_profile = await self._check_existing_xbox_profile(
                        xbox_access_token, user_token, credentials
                    )

                    if existing_profile:
                        return existing_profile

            result = await self._create_new_xbox_profile(
                response, history_list, session, headers, user_token, credentials
            )

            if result:
                xsts_body = {
                    "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
                    "RelyingParty": XSTS_RELYING_PARTY_PROFILE,
                    "TokenType": "JWT",
                }

                xsts_response = await session.post(XSTS_AUTH_URL, json=xsts_body, headers=headers)
                if xsts_response.status_code.as_int() != 200:
                    self.logger.error(f"XSTS auth failed: {xsts_response.status_code.as_int()}")
                    if xsts_response.status_code.as_int() == 401:
                        self.logger.info(
                            "Account needs Xbox profile creation - this should not happen after profile creation"
                        )
                    return None

                xsts_data = await xsts_response.json()
                uhs = xsts_data["DisplayClaims"]["xui"][0]["uhs"]
                xsts_token = xsts_data["Token"]

                result["uhs"] = uhs
                result["xsts_token"] = xsts_token

                xbl_token = f"XBL3.0 x={uhs};{xsts_token}"
                self.logger.debug(
                    f"Generated XSTS token for profile API (relyingParty={XSTS_RELYING_PARTY_PROFILE}, uhs={uhs}, token_len={len(xsts_token)})"
                )
                await self._save_account_data(result["gamertag"], xbl_token, credentials)

            return result

        except Exception as e:
            self.logger.error(f"Xbox account creation failed: {e}")

            return None

    async def _check_existing_xbox_profile(
        self, xbox_access_token: str, user_token: str, credentials: AccountCredentials
    ) -> Optional[Dict[str, Any]]:
        try:
            padded_token = xbox_access_token + "=" * (4 - len(xbox_access_token) % 4)
            token_data = json.loads(base64.b64decode(padded_token))

            if isinstance(token_data, list) and len(token_data) > 0:
                xbox_claims = token_data[0]
                item2 = xbox_claims.get("Item2", {})
                display_claims = item2.get("DisplayClaims", {})
                xui = display_claims.get("xui", [{}])[0] if display_claims.get("xui") else {}

                gamertag = xui.get("gtg", "")
                xuid = xui.get("xid", "")

                if gamertag and xuid:
                    self.logger.info(f"Existing Xbox profile found: {gamertag} (XUID: {xuid})")

                    xsts_body = {
                        "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
                        "RelyingParty": XSTS_RELYING_PARTY_PROFILE,
                        "TokenType": "JWT",
                    }

                    headers = self.client_config["headers"].copy()
                    temp_client = self._create_client()
                    xsts_response = await temp_client.post(
                        XSTS_AUTH_URL, json=xsts_body, headers=headers
                    )
                    if xsts_response.status_code.as_int() == 200:
                        xsts_data = await xsts_response.json()
                        actual_uhs = xsts_data["DisplayClaims"]["xui"][0]["uhs"]
                        xsts_token = xsts_data["Token"]

                        xbl_token = f"XBL3.0 x={actual_uhs};{xsts_token}"
                        self.logger.debug(
                            f"Existing profile XSTS token (relyingParty={XSTS_RELYING_PARTY_PROFILE}, uhs={actual_uhs}, token_len={len(xsts_token)})"
                        )
                        await self._save_account_data(gamertag, xbl_token, credentials)

                        return {
                            "gamertag": gamertag,
                            "xuid": xuid,
                            "uhs": actual_uhs,
                            "xsts_token": xsts_token,
                            "existing": True,
                        }
                    else:
                        self.logger.warning(
                            f"XSTS auth failed for existing profile: {xsts_response.status_code.as_int()}"
                        )
                        return None

            self.logger.info("No existing Xbox profile found - will create new one")
            return None

        except Exception as e:
            self.logger.debug(f"Could not decode existing profile (will create new): {e}")

            return None

    async def _create_new_xbox_profile(
        self,
        logged_in_response: rnet.Response,
        redirect_history: list,
        session: Session,
        headers: Dict[str, str],
        user_token: str,
        credentials: AccountCredentials,
    ) -> Optional[Dict[str, Any]]:
        try:
            self.logger.info("Creating new Xbox profile")

            logged_in_redirects = redirect_history
            if len(logged_in_redirects) <= 2:
                self.logger.error(f"Expected more than 2 redirects, got {len(logged_in_redirects)}")
                return None

            redirect_location = None
            for name, value in logged_in_redirects[2].headers.items():
                name_str = name.decode() if isinstance(name, bytes) else name
                if name_str.lower() == "location":
                    redirect_location = value.decode() if isinstance(value, bytes) else value
                    break

            if not redirect_location:
                self.logger.error("Could not find Location header in redirect")
                return None

            session_id_match = re.search(r"sid=(.+?)&", redirect_location)
            if not session_id_match:
                self.logger.error("Could not find session ID in redirect")
                return None

            session_id = session_id_match.group(1)
            self.logger.debug(f"Found session ID: {session_id}")

            spt_match = re.search(r"spt=(.+?)&", redirect_location)
            if not spt_match:
                self.logger.error("Could not find SPT token in redirect")
                return None

            headers["authorization"] = spt_match.group(1)
            self.logger.debug("Set authorization header with SPT token")

            proxy_url = f"{SISU_BASE_URL}/proxy?sessionid={session_id}"

            gamertag_result = await self._reserve_gamertag(session, proxy_url, headers)
            if not gamertag_result:
                return None

            gamertag, reservation_id = gamertag_result

            create_body = {
                "CreateAccountWithGamertag": {
                    "Gamertag": gamertag,
                    "ReservationId": reservation_id,
                }
            }

            self.logger.info(f"Creating Xbox account with gamertag: {gamertag}")
            response = await session.post(proxy_url, json=create_body, headers=headers)

            if response.status_code.as_int() != 200:
                response_text = await response.text()
                self.logger.error(
                    f"Failed to create Xbox account: {response.status_code.as_int()} - {response_text}"
                )
                return None

            try:
                account_response = await response.json()
                created_gamertag = account_response.get("gamerTag", gamertag)

                is_existing = created_gamertag != gamertag

                if is_existing:
                    self.logger.info(f"Existing Xbox profile found: {created_gamertag}")
                else:
                    self.logger.info(f"Xbox account created with gamertag: {created_gamertag}")

            except Exception:
                created_gamertag = gamertag
                is_existing = False
                self.logger.info(f"Xbox account created (assuming gamertag: {gamertag})")

            if not is_existing:
                await self._set_avatar(session, proxy_url, headers)

            return {
                "gamertag": created_gamertag,
                "xuid": "new_account",
                "user_token": user_token,
                "existing": is_existing,
            }

        except Exception as e:
            self.logger.error(f"Failed to create Xbox profile: {e}")

            return None

    async def _reserve_gamertag(
        self, session: Session, proxy_url: str, headers: Dict[str, str]
    ) -> Optional[Tuple[str, int]]:
        try:
            reservation_id: int = random.randint(1000000000, 9999999999)
            xbox_prefix: str = XboxConfig.GAMERTAG_PREFIX
            max_attempts: int = XboxConfig.MAX_GAMERTAG_ATTEMPTS

            self.logger.debug("Starting gamertag reservation process")

            for attempt in range(max_attempts):
                suffix_length: int = XboxConfig.GAMERTAG_SUFFIX_LENGTH - len(xbox_prefix)
                xbox_gamertag: str = xbox_prefix + self._generate_random_string(suffix_length)

                reserve_body: Dict[str, Dict[str, Union[str, int]]] = {
                    "GamertagReserve": {
                        "Gamertag": xbox_gamertag,
                        "ReservationId": reservation_id,
                        "Duration": XboxConfig.RESERVATION_DURATION,
                    }
                }

                self.logger.debug(
                    f"Testing gamertag: {xbox_gamertag} (attempt {attempt + 1}/{max_attempts})"
                )
                response = await session.post(proxy_url, json=reserve_body, headers=headers)

                if response.status_code.as_int() == XboxConfig.RATE_LIMIT_STATUS_CODE:
                    await self._handle_rate_limit(response)
                    continue

                if response.status_code.as_int() == 200:
                    self.logger.info(f"Successfully reserved gamertag: {xbox_gamertag}")
                    return xbox_gamertag, reservation_id
                else:
                    self.logger.debug(
                        f"Gamertag {xbox_gamertag} not available: {response.status_code.as_int()}"
                    )

                    await asyncio.sleep(XboxConfig.GAMERTAG_ATTEMPT_DELAY)

            self.logger.error(f"Failed to find available gamertag after {max_attempts} attempts")
            return None

        except Exception as e:
            self.logger.error(f"Gamertag reservation failed: {e}")

            return None

    async def _set_avatar(self, session: Session, proxy_url: str, headers: Dict[str, str]) -> None:
        try:
            avatar_body: Dict[str, Dict[str, str]] = {
                "SetGamerpic": {"GamerPic": XboxConfig.DEFAULT_AVATAR_URL}
            }

            self.logger.debug("Setting default avatar")
            response = await session.post(proxy_url, json=avatar_body, headers=headers)

            if response.status_code.as_int() == 201:
                self.logger.debug("Avatar set successfully")
            else:
                self.logger.warning(f"Failed to set avatar: {response.status_code.as_int()}")

        except Exception as e:
            self.logger.warning(f"Avatar setting failed (non-critical): {e}")

    async def _save_account_data(
        self, gamertag: str, xbl_token: str, credentials: AccountCredentials
    ) -> None:
        """Save account data to files asynchronously."""
        try:
            loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()

            gamertags_file: Path = Path(__file__).parent / "data" / XboxConfig.GAMERTAGS_FILE
            tokens_file: Path = Path(__file__).parent / "data" / XboxConfig.TOKENS_FILE
            tokens_file.parent.mkdir(exist_ok=True)

            await loop.run_in_executor(
                None,
                lambda: gamertags_file.write_text(
                    gamertags_file.read_text(encoding="utf-8") + f"{gamertag}\n"
                    if gamertags_file.exists()
                    else f"{gamertag}\n",
                    encoding="utf-8",
                ),
            )

            await loop.run_in_executor(
                None,
                lambda: tokens_file.write_text(
                    tokens_file.read_text(encoding="utf-8") + f"{xbl_token}\n"
                    if tokens_file.exists()
                    else f"{xbl_token}\n",
                    encoding="utf-8",
                ),
            )

            self.logger.info(f"GAMERTAG FOUND: {gamertag}")
            self.logger.info(f"XBL TOKEN: {xbl_token}")

        except Exception as e:
            self.logger.error(f"Failed to save account data: {e}")

    async def process_account(self, credentials: AccountCredentials) -> XboxAccountResult:
        start_time = time.time()

        try:
            client = self._create_client()
            auth_result = await self.authenticate_microsoft_account(client, credentials)
            if not auth_result:
                return XboxAccountResult(
                    credentials=credentials,
                    success=False,
                    error_message="Microsoft authentication failed",
                    processing_time=time.time() - start_time,
                )

            authorization_code, code_verifier, auth_session = auth_result

            xbox_result = await self.create_xbox_account(
                client, authorization_code, code_verifier, credentials, auth_session
            )

            if not xbox_result:
                return XboxAccountResult(
                    credentials=credentials,
                    success=False,
                    error_message="Xbox account creation failed",
                    processing_time=time.time() - start_time,
                )

            action = "Retrieved existing" if xbox_result.get("existing") else "Created"
            processing_time = time.time() - start_time
            time_str = self._format_duration(processing_time)
            self.logger.info(
                f"{action} Xbox: {xbox_result['gamertag']} | {credentials.email} | {time_str}"
            )

            result = XboxAccountResult(
                credentials=credentials,
                success=True,
                gamertag=xbox_result["gamertag"],
                xuid=xbox_result.get("xuid"),
                processing_time=time.time() - start_time,
            )

        except Exception as e:
            self.logger.error(f"Unexpected error processing account {credentials.email}: {e}")
            result = XboxAccountResult(
                credentials=credentials,
                success=False,
                error_message=str(e),
                processing_time=time.time() - start_time,
            )

        async with self._stats_lock:
            self.stats["processed"] += 1
            if result.success:
                self.stats["successful"] += 1
            else:
                self.stats["failed"] += 1

        return result

    async def process_accounts_batch(
        self, accounts: List[AccountCredentials]
    ) -> List[XboxAccountResult]:
        semaphore = asyncio.Semaphore(self.max_workers)

        async def process_with_semaphore(account: AccountCredentials) -> XboxAccountResult:
            async with semaphore:
                return await self.process_account(account)

        tasks = [process_with_semaphore(account) for account in accounts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Task failed for {accounts[i].email}: {result}")
                processed_results.append(
                    XboxAccountResult(
                        credentials=accounts[i],
                        success=False,
                        error_message=f"Task execution error: {result}",
                    )
                )
            else:
                processed_results.append(result)

        return processed_results

    def load_accounts_from_file(
        self, filepath: Path = Path(__file__).parent / "data" / XboxConfig.DEFAULT_ACCOUNTS_FILE
    ) -> List[AccountCredentials]:
        if not filepath.exists():
            self.logger.warning(f"Accounts file not found: {filepath}")
            return []

        accounts: List[AccountCredentials] = []
        try:
            content: str = filepath.read_text(encoding="utf-8")
            lines: List[str] = content.strip().split("\n")

            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    account = AccountCredentials.from_string(line)
                    accounts.append(account)

                except ValueError as e:
                    self.logger.warning(f"Invalid account format on line {line_num}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to load accounts from {filepath}: {e}")

        self.logger.info(f"Loaded {len(accounts)} accounts from {filepath}")

        return accounts

    def print_statistics(self) -> None:
        elapsed = datetime.now() - self.stats["start_time"]
        success_rate = (self.stats["successful"] / max(self.stats["processed"], 1)) * 100

        total_seconds = elapsed.total_seconds()
        accounts_per_second = self.stats["processed"] / max(total_seconds, 1)
        duration_str = self._format_duration(total_seconds)

        print(f"\n{Fore.WHITE + Style.BRIGHT}OPERATION MERCY{Style.RESET_ALL}")
        print(
            f"{Fore.GREEN}[   OK   ]{Style.RESET_ALL} Successful: {Fore.GREEN + Style.BRIGHT}{self.stats['successful']}{Style.RESET_ALL}"
        )

        if self.stats["failed"] > 0:
            print(
                f"{Fore.RED}[ FAILED ]{Style.RESET_ALL} Failed: {Fore.RED + Style.BRIGHT}{self.stats['failed']}{Style.RESET_ALL}"
            )

        print(
            f"{Fore.CYAN}[  INFO  ]{Style.RESET_ALL} Processed: {Fore.CYAN + Style.BRIGHT}{self.stats['processed']}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN}[  INFO  ]{Style.RESET_ALL} Success Rate: {Fore.GREEN + Style.BRIGHT}{success_rate:.1f}%{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN}[  INFO  ]{Style.RESET_ALL} Speed: {Fore.YELLOW + Style.BRIGHT}{accounts_per_second:.2f}{Style.RESET_ALL} accounts/sec"
        )
        print(
            f"{Fore.CYAN}[  INFO  ]{Style.RESET_ALL} Duration: {Fore.MAGENTA + Style.BRIGHT}{duration_str}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN}[  INFO  ]{Style.RESET_ALL} Workers: {Fore.BLUE + Style.BRIGHT}{self.max_workers}{Style.RESET_ALL}"
        )


async def amain():
    import argparse

    parser = argparse.ArgumentParser(description="Blazing Fast Xbox Account Creator")
    parser.add_argument(
        "--accounts",
        type=Path,
        default=Path(__file__).parent / "data" / XboxConfig.DEFAULT_ACCOUNTS_FILE,
        help="Path to accounts file",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=XboxConfig.DEFAULT_MAX_WORKERS,
        help="Number of concurrent workers",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--proxy", type=str, help="HTTP proxy URL")
    parser.add_argument(
        "--pool-size",
        type=int,
        default=XboxConfig.DEFAULT_CONNECTION_POOL_SIZE,
        help="Connection pool size",
    )

    args = parser.parse_args()

    creator = XboxAccountCreator(
        max_workers=args.workers,
        debug_mode=args.debug,
        proxy_url=args.proxy,
        connection_pool_size=args.pool_size,
    )

    accounts = creator.load_accounts_from_file(args.accounts)
    if not accounts:
        creator.logger.error("No valid accounts found")

        return

    creator.logger.info(f"Processing of {len(accounts)} accounts with {args.workers} workers")
    await creator.process_accounts_batch(accounts)
    creator.print_statistics()


def main():
    try:
        asyncio.run(amain())

    except KeyboardInterrupt:
        print("\nOperation cancelled")

    except Exception as e:
        print(f"Fatal error: {e}")


if __name__ == "__main__":
    main()
