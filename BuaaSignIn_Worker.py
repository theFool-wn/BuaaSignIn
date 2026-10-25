# @             Project: BuaaSignIn -> BuaaSignIn_Worker.py
# @              Author: WangNan
# @       Creation Date: 2025/11/1 23:15
# @         Description: BUAA course sign-in on Cloudflare Python Worker
# @ Version Information: Created by WangNan, 2025/11/1
#                        Revised by WangNan, 2025/11/4, add robots()
#                        Revised by WangNan, 2025/11/4, add get_client_ip() and favicon()
#                        Revised by WangNan, 2026/3/24, add 36000 for cache bug
#                        Revised by WangNan, 2026/4/11, add -3000 for signing failure bug
#                        Revised by WangNan, 2026/4/16, add UA, and remove -3000
#                        Revised by WangNan, 2026/4/18, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/5/10, add timestamp_url
#                        Revised by WangNan, 2026/5/14, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/5/20, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/6/3, change the login method to username and password,
#                                                      add several functions such as sso(),
#                                                      and restructured the overall code architecture
#                        Revised by WangNan, 2026/6/4, update WHITELIST_STUDENT_IDS
#                        Revised by WangNan, 2026/10/17, refactor the frontend and backend,
#                                                        adapt for Cloudflare Python Worker,
#                                                        switch to VPN mode
#                        Revised by WangNan, 2026/10/25, add safety redundancy to prevent potential errors,
#                                                        remove useless code
# =============================================================================================================


import re
import time
import base64
import hashlib
import hmac
import json
from contextvars import ContextVar

from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

from js import console, crypto, Object, Uint8Array, AbortController, setTimeout, clearTimeout
from pyodide.ffi import run_sync, to_js as _to_js
from flask import Flask, Response as FlaskResponse, request as flask_request
from workers import Response, fetch, wsgi


app = Flask(__name__)
WORKER_STARTED_AT = datetime.now(timezone.utc)
ACCESS_IDENTITY = ContextVar('access_identity', default=None)


def config(env, name, default=''):
    return getattr(env, name, default)


def api_result(status, message, http_status=200, **values):
    return Response.json({'STATUS': status, 'message': message, **values}, status=http_status,
                         headers={'Cache-Control': 'no-store'})


def enabled(env):
    return str(config(env, 'SERVICE_ENABLED', 'true')).lower() == 'true'


def local_now(env):
    return datetime.now(timezone(timedelta(hours=int(config(env, 'TIMEZONE_OFFSET_HOURS', 8)))))


def secret_json(env, name, default):
    try:
        return json.loads(config(env, name, ''))
    except (ValueError, TypeError):
        return default


def client_ip(request):
    # Only Cloudflare's trusted connecting-IP header is used; forwarded headers are client controlled.
    return request.headers.get('CF-Connecting-IP', '')[:64]


def set_access_identity(student_id='', real_name=''):
    identity = ACCESS_IDENTITY.get()
    if identity is not None:
        identity['student_id'] = str(student_id or '')[:64]
        identity['real_name'] = str(real_name or '')[:100]


def js_bytes(raw):
    result = Uint8Array.new(len(raw))
    result.assign(raw)
    return result


def js_object(data):
    return _to_js(data, dict_converter=Object.fromEntries)


async def session_key(env):
    secret = hashlib.sha256(config(env, 'SESSION_SECRET').encode()).digest()
    return await crypto.subtle.importKey(
        'raw',
        js_bytes(secret), 
        js_object({'name': 'AES-GCM'}),
        False,
        _to_js(['encrypt', 'decrypt'])
    )


async def make_ticket(env, data):
    iv = crypto.getRandomValues(Uint8Array.new(12))
    payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()
    encrypted = await crypto.subtle.encrypt(
        js_object({
            'name': 'AES-GCM',
            'iv': iv
            }),
        await session_key(env),
        js_bytes(payload)
    )
    return base64.urlsafe_b64encode(iv.to_bytes() + encrypted.to_bytes()).decode()


async def read_ticket(env, token):
    try:
        if len(token) > 12000:
            return None
        raw = base64.urlsafe_b64decode(token)
        decrypted = await crypto.subtle.decrypt(
            js_object({
                'name': 'AES-GCM',
                'iv': js_bytes(raw[:12])
            }),
            await session_key(env),
            js_bytes(raw[12:])
        )
        data = json.loads(decrypted.to_bytes())
        if data['expires_at'] < int(time.time()):
            return None
        return data
    except Exception:
        return None


def vpn_url(env, key):
    return config(env, 'VPN_BASE_URL').rstrip('/') + '/' + config(env, key).lstrip('/')


def safe_vpn_url(env, url):
    parsed = urlparse(url)
    base = urlparse(config(env, 'VPN_BASE_URL'))
    return parsed.scheme == 'https' and parsed.netloc == base.netloc


class VpnClient:
    """One request owns one cookie jar; sessions never leak between Worker requests."""

    def __init__(self, env):
        self.env = env
        self.cookies = {}

    def save_cookies(self, response):
        try:
            values = list(response.js_object.headers.getSetCookie())
        except Exception:
            values = response.headers.get_all('Set-Cookie') or []
        for value in values:
            if not value:
                continue
            cookie = SimpleCookie()
            try:
                cookie.load(value)
                for key, item in cookie.items():
                    self.cookies[key] = item.value
            except Exception:
                console.warn('VPN Cookie 解析失败')

    async def request(self, url, method='GET', body=None, headers=None, redirects=0):
        if not safe_vpn_url(self.env, url):
            raise ValueError('VPN 返回了非预期地址')
        outgoing = {'User-Agent': config(self.env, 'USER_AGENT')}
        if self.cookies:
            outgoing['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        if headers:
            outgoing.update(headers)
        
        timeout_ms = int(config(self.env, 'REQUEST_TIMEOUT', 15000))
        controller = AbortController.new()
        timer = setTimeout(controller.abort.bind(controller), timeout_ms)
        try:
            response = await fetch(
                url,
                method=method,
                headers=outgoing,
                body=body,
                redirect='manual',
                signal=controller.signal
            )
            response_text = await response.text()
        except Exception as error:
            if controller.signal.aborted:
                raise ValueError('上游请求超时，请重试') from error
            raise
        finally:
            clearTimeout(timer)

        self.save_cookies(response)
        if redirects and response.status in (301, 302, 303, 307, 308):
            location = response.headers.get('Location')
            if location:
                next_url = urljoin(url, location)
                next_method = method if response.status in (307, 308) else 'GET'
                return await self.request(next_url, method=next_method,
                                          body=body if next_method == method else None,
                                          redirects=redirects - 1)
        return response, response_text

    async def get_json(self, url, headers=None):
        response, text = await self.request(url, headers=headers)
        if response.status != 200:
            raise ValueError(f'上游 HTTP {response.status}')
        return json.loads(text)


def execution_of(html):
    class ExecutionParser(HTMLParser):
        value = None

        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if tag == 'input' and values.get('name') == 'execution':
                self.value = values.get('value')

    parser = ExecutionParser()
    parser.feed(html)
    return parser.value


class SsoLoginError(ValueError):
    """A known SSO rejection that should keep the original business response."""


async def get_login_name(client):
    env = client.env
    jump, _ = await client.request(vpn_url(env, 'VPN_JUMP_PATH'), redirects=6)
    target = jump.headers.get('Location') or jump.url
    login_name = parse_qs(urlparse(target).query).get('loginName', [''])[0]
    if not login_name:
        match = re.search(r'loginName=([^&\s]+)', target)
        login_name = match.group(1) if match else ''
    if not login_name:
        raise SsoLoginError('请求 iclass 失败')
    return login_name


async def sso_login(client, username, password, is_admin=False):
    env = client.env
    login_url = vpn_url(env, 'VPN_SSO_PATH')
    response, html = await client.request(login_url, redirects=6)

    if response.status != 200:
        raise SsoLoginError(f'SSO 登录页异常，状态码 {response.status}')
    if response.url.rstrip('/') == config(env, 'VPN_BASE_URL').rstrip('/'):
        if is_admin:
            return
        return await get_login_name(client)
    
    submit_url = response.url if safe_vpn_url(env, response.url) else login_url
    execution = execution_of(html)
    if not execution:
        raise SsoLoginError('SSO 登录页缺少 execution')

    form = {
        'username' : username,
        'password' : password,
        'submit'   : '登录',
        'type'     : 'username_password',
        'execution': execution,
        '_eventId' : 'submit'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    response, html = await client.request(
        submit_url,
        method='POST',
        body=urlencode(form),
        headers=headers,
        redirects=0
    )

    if response.status == 302:
        pass
    elif response.status == 200:
        if 'continueForm' not in html:
            raise SsoLoginError('SSO 登录页未知错误')
        
        risk_execution = execution_of(html)
        if not risk_execution:
            raise SsoLoginError('账号存在安全风险，登录失败')
        risk_form = urlencode({
            'execution': risk_execution,
            '_eventId': 'ignoreAndContinue'
        })

        try:
            response, _ = await client.request(
                submit_url,
                method='POST',
                body=risk_form,
                headers=headers,
                redirects=0
            )
        except Exception as error:
            raise SsoLoginError('账号存在安全风险，登录失败') from error
        
        if response.status != 302:
            raise SsoLoginError('账号存在安全风险，登录失败')
    elif response.status == 401:
        raise SsoLoginError('账号或密码错误')
    else:
        raise SsoLoginError(f'SSO 登录异常，状态码 {response.status}')

    # Follow the CAS redirect with the same isolated VPN cookies.
    redirect_url = response.headers.get('Location')
    if not redirect_url:
        raise SsoLoginError('SSO 登录响应缺少跳转地址')
    await client.request(urljoin(submit_url, redirect_url), redirects=8)
    if is_admin:
        return
    return await get_login_name(client)


async def decrypt_password(env, ciphertext):
    pem = config(env, 'PRIVATE_KEY_PEM')
    match = re.search(r'-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----', pem, re.DOTALL)
    der = base64.b64decode(re.sub(r'\s+', '', match.group(1)), validate=True)
    key = await crypto.subtle.importKey(
        'pkcs8',
        js_bytes(der),
        js_object({
            'name': 'RSA-OAEP',
            'hash': 'SHA-256'
        }),
        False,
        _to_js(['decrypt'])
    )
    plaintext = await crypto.subtle.decrypt(
        js_object({'name': 'RSA-OAEP'}),
        key,
        js_bytes(base64.b64decode(ciphertext, validate=True))
    )
    return plaintext.to_bytes().decode()


def allowed_user(env, username):
    users = secret_json(env, 'WHITELIST_STUDENT_IDS', [])
    return isinstance(users, list) and username.upper() in {str(item).upper() for item in users}


def blocked_ip(env, request):
    addresses = secret_json(env, 'BLOCKLIST_IPS', [])
    return isinstance(addresses, list) and client_ip(request) in addresses


def service_configured(env):
    return (len(config(env, 'SESSION_SECRET')) >= 32 and
            bool(config(env, 'PRIVATE_KEY_PEM')) and
            bool(config(env, 'PUBLIC_KEY_PEM')) and
            bool(config(env, 'WHITELIST_STUDENT_IDS')))


async def get_identity(client, login_name):
    url = vpn_url(client.env, 'VPN_ICLASS_LOGIN_PATH')
    params = {
        'password': '',
        'phone': login_name,
        'userLevel': '1',
        'verificationType': '2',
        'verificationUrl': ''
    }
    data = await client.get_json(url + '?' + urlencode(params))
    if data.get('STATUS') != '0' or not isinstance(data.get('result'), dict):
        raise ValueError('课程系统登录失败')
    return str(data['result']['id']), str(data['result'].get('realName') or '')


async def get_schedule(client, session_id, user_id, env):
    url = vpn_url(env, 'VPN_SCHEDULE_PATH')
    query = urlencode({
        'dateStr': local_now(env).strftime('%Y%m%d'),
        'id': user_id
    })
    data = await client.get_json(url + '?' + query, headers={'sessionId': session_id})
    if data.get('STATUS') == '2':
        return {'STATUS': '0', 'result': []}
    if data.get('STATUS') != '0':
        raise ValueError(data.get('ERRMSG') or '课程查询失败')
    return data


async def schedule(body, env):
    if not isinstance(body, dict):
        return api_result('1', '请求数据格式错误', 400)
    
    username = str(body.get('username', '')).strip()
    if not username or len(username) > 64:
        return api_result('1', '缺少账号 (学号)', 400)
    set_access_identity(username)

    special = secret_json(env, 'ADMIN_ACCOUNT', {})
    is_admin = username.upper() in {str(x).upper() for x in special.get('aliases', [])}

    if not is_admin and not allowed_user(env, username):
        return api_result('3', '外部成员，禁止访问', 403)

    token_data = await read_ticket(env, str(body.get('ticket', ''))) if body.get('ticket') else None
    if body.get('ticket') and (not token_data or token_data.get('username') != username.upper()):
        return api_result('6', '会话已过期，请重新查询', 401)
    if token_data:
        session_id, user_id = token_data['session_id'], token_data['user_id']
        student_id = token_data.get('student_id', username)
        real_name = token_data.get('real_name', '')
        set_access_identity(student_id, real_name)
        client = VpnClient(env)
        client.cookies = token_data.get('cookies', {})
    else:
        ciphertext = str(body.get('password', ''))
        if not ciphertext or len(ciphertext) > 4096:
            return api_result('1', '请填写密码', 400)
        try:
            password = await decrypt_password(env, ciphertext)
        except Exception:
            return api_result('1', '密码解密失败', 400)

        if is_admin:
            expected = config(env, 'ADMIN_PASSWORD', '')
            if not expected or not hmac.compare_digest(password, expected):
                return api_result('1', '账号或密码错误', 403)
            
            client = VpnClient(env)
            admin_user, admin_pass = special.get('username'), str(special.get('password'))
            if not admin_user or not admin_pass:
                return api_result('1', '特殊模式未配置', 503)
            
            await sso_login(client, admin_user, admin_pass, is_admin=True)
            session_id, user_id = special.get('session_id'), str(special.get('user_id'))
            student_id = str(special.get('student_id') or admin_user)
            real_name = str(special.get('real_name') or '')
            set_access_identity(student_id, real_name)

            if not session_id or not user_id:
                return api_result('1', '特殊模式未配置', 503)
        else:
            try:
                client = VpnClient(env)
                session_id = await sso_login(client, username, password)
                user_id, real_name = await get_identity(client, session_id)
                student_id = username
                set_access_identity(student_id, real_name)
            except Exception as error:
                console.warn(f'SSO 登录失败: {type(error).__name__}')
                return api_result('1', str(error) if isinstance(error, ValueError) else 'SSO 登录失败', 502)

    try:
        data = await get_schedule(client, session_id, user_id, env)
        courses = data.get('result') or []
        if not isinstance(courses, list):
            raise ValueError('课程数据格式错误')
        
        valid_courses = {}
        for item in courses:
            course_id = str(item.get('id', ''))
            if course_id:
                valid_courses[course_id] = [item.get('classBeginTime', ''), item.get('classEndTime', '')]
        
        ticket = await make_ticket(
            env,
            {
                'username': username.upper(),
                'student_id': student_id,
                'real_name': real_name,
                'session_id': session_id,
                'user_id': user_id,
                'cookies': client.cookies,
                'courses': valid_courses,
                'expires_at': int(time.time()) + int(config(env, 'SESSION_TTL_SECONDS', 1800))
            })
        return api_result('0', '课程查询成功', result=courses, ticket=ticket)
    except Exception as error:
        console.warn(f'课程查询失败: {type(error).__name__}')
        return api_result('1', str(error) if isinstance(error, ValueError) else '课程查询失败', 502)


def in_sign_window(env, begin, end):
    now = local_now(env)
    try:
        start = datetime.fromisoformat(begin.replace(' ', 'T'))
        finish = datetime.fromisoformat(end.replace(' ', 'T'))
        if start.tzinfo is None:
            start = start.replace(tzinfo=now.tzinfo)
        if finish.tzinfo is None:
            finish = finish.replace(tzinfo=now.tzinfo)
        return start - timedelta(minutes=int(config(env, 'SIGN_WINDOW_MINUTES', 10))) <= now <= finish
    except ValueError:
        return False


async def sign_in(body, env):
    if not isinstance(body, dict):
        return api_result('1', '请求数据格式错误', 400)

    ticket = await read_ticket(env, str(body.get('ticket', '')))
    if not ticket:
        return api_result('6', '会话已过期，请重新查询', 401)
    ticket_user = ticket.get('username', '')
    special = secret_json(env, 'ADMIN_ACCOUNT', {})
    is_admin = ticket_user.upper() in {str(x).upper() for x in special.get('aliases', [])}
    if not is_admin and not allowed_user(env, ticket_user):
        return api_result('3', '外部成员，禁止访问', 403)
    set_access_identity(ticket.get('student_id', ticket_user), ticket.get('real_name', ''))
    
    course_id = str(body.get('id', ''))
    course_time = ticket.get('courses', {}).get(course_id)
    if not course_time:
        return api_result('3', '课程不属于当前会话，请重新查询', 403)
    if not in_sign_window(env, *course_time):
        return api_result('2', '未到签到时间或签到时间已过')

    client = VpnClient(env)
    client.cookies = ticket.get('cookies', {})
    try:
        timestamp_data = await client.get_json(vpn_url(env, 'VPN_TIMESTAMP_PATH'))
        if timestamp_data.get('STATUS') != '0':
            raise ValueError('获取服务器时间失败')
        
        timestamp = timestamp_data.get('timestamp')
        if not timestamp or timestamp == 'null':
            timestamp = int(time.time() * 1000)
        
        query = urlencode({
            'courseSchedId': course_id,
            'timestamp': timestamp,
            'id': ticket['user_id']
        })
        response, text = await client.request(
            vpn_url(env, 'VPN_SIGN_PATH') + '?' + query,
            method='POST',
            headers={'sessionId': ticket['session_id']
        })

        if response.status != 200:
            raise ValueError(f'签到上游 HTTP {response.status}')
        
        result = json.loads(text)
        return Response.json(result, headers={'Cache-Control': 'no-store'})
    except Exception as error:
        console.warn(f'签到失败: {type(error).__name__}')
        return api_result('1', str(error) if isinstance(error, ValueError) else '签到失败', 502)


def service_start_time(env):
    configured = config(env, 'START_TIME', '').strip()
    if configured:
        try:
            return datetime.fromisoformat(configured)
        except ValueError:
            console.warn(f'START_TIME 配置格式无效: {configured}')
    return WORKER_STARTED_AT


def health(env):
    started = service_start_time(env)
    uptime = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
    configured = service_configured(env)
    return {
        'status': 'paused' if not enabled(env) else ('healthy' if configured else 'unconfigured'),
        'responsive': True,
        'configured': configured,
        'service': 'BuaaSignIn',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'started_at': started.isoformat(),
        'uptime_seconds': uptime,
        'paused_message': config(env, 'SERVICE_PAUSED_MESSAGE'),
        'resume_time': config(env, 'SERVICE_RESUME_TIME')
    }


async def log_access(env, request, path, status, elapsed_ms, identity):
    try:
        # A SQLite upsert reserves one of today's log slots atomically across isolates.
        now = datetime.now(timezone.utc)
        day = int(now.strftime('%Y%m%d'))
        daily_limit = max(0, min(int(config(env, 'LOG_DAILY_MAX_ENTRIES', 10000)), 10000))
        
        if not daily_limit:
            return
        
        budget = await env.DB.prepare(
            'INSERT INTO log_budget (day, used) VALUES (?, 1) '
            'ON CONFLICT(day) DO UPDATE SET used = used + 1 WHERE used < ?'
        ).bind(
            day,
            daily_limit
        ).run()

        if not budget.meta.changes:
            return

        # Free D1 allows 500 MB per database. Stop early if cleanup is not keeping up.
        stop_bytes = max(1, min(int(config(env, 'LOG_STORAGE_STOP_MB', 300)), 400)) * 1024 * 1024
        size_after = getattr(budget.meta, 'size_after', None)
        if size_after is None or size_after >= stop_bytes:
            return
        await env.DB.prepare(
            'INSERT INTO access_logs (at, ip, method, path, status, user_agent, referer, duration_ms, student_id, real_name) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(
            now.isoformat(),
            client_ip(request),
            request.method,
            path[:256],
            status,
            request.headers.get('User-Agent', '')[:300],
            request.headers.get('Referer', '')[:300],
            elapsed_ms,
            identity.get('student_id') or None,
            identity.get('real_name') or None
        ).run()
    except Exception as error:
        console.error(f'D1 访问日志写入失败: {type(error).__name__}')


async def clean_access_logs(env):
    now = datetime.now(timezone.utc)
    day = int(now.strftime('%Y%m%d'))
    # Keep the entire previous calendar month plus the current month.
    previous_month_end = now.replace(day=1) - timedelta(days=1)
    cutoff = previous_month_end.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    for attempt in range(3):
        try:
            results = await env.DB.batch(_to_js([
                env.DB.prepare(
                    'DELETE FROM access_logs WHERE NOT EXISTS ('
                    'SELECT 1 FROM cleanup_budget WHERE day = ?) AND id IN ('
                    'SELECT id FROM access_logs WHERE at < ? ORDER BY at LIMIT 40000)'
                ).bind(day, cutoff),
                env.DB.prepare(
                    'INSERT INTO cleanup_budget (day, reserved) VALUES (?, 40000) '
                    'ON CONFLICT(day) DO NOTHING'
                ).bind(day)
            ]))
            break
        except Exception as error:
            console.error(f'D1 日志清理失败 ({attempt + 1}/3): {type(error).__name__}: {error}')
            if attempt == 2:
                raise

    if results[1].meta.changes:
        console.log(json.dumps({
            'task': 'access_log_cleanup',
            'deleted': results[0].meta.changes,
            'rows_written': results[0].meta.rows_written
        }))


def environment():
    return flask_request.environ['workers.env']


def flask_result(response):
    return FlaskResponse(run_sync(response.bytes()), status=response.status, headers=response.headers)


def asset(path):
    response = run_sync(environment().ASSETS.fetch('https://assets.local/' + path))
    return flask_result(response)


def api_guard():
    env = environment()
    if blocked_ip(env, flask_request):
        return api_result('3', '受限制 IP，禁止访问', 403)
    if not enabled(env):
        return api_result('5', config(env, 'SERVICE_PAUSED_MESSAGE', '服务暂停'), 503,
                          resume_time=config(env, 'SERVICE_RESUME_TIME'))
    if not service_configured(env):
        return api_result('1', '服务尚未完成配置', 503)
    return None


@app.get('/')
def index():
    return asset('index.html')


@app.get('/health')
def health_page():
    if 'application/json' in flask_request.headers.get('Accept', ''):
        return flask_result(Response.json(health(environment()), headers={'Cache-Control': 'no-store'}))
    return asset('health.html')


@app.get('/api/config')
def public_config():
    env = environment()
    return flask_result(Response.json({'public_key': config(env, 'PUBLIC_KEY_PEM'), **health(env)},
                                      headers={'Cache-Control': 'no-store'}))


@app.post('/api/iClassSchedule')
def course_schedule():
    guard = api_guard()
    if guard is not None:
        return flask_result(guard)
    return flask_result(run_sync(schedule(flask_request.get_json(silent=True), environment())))


@app.post('/api/iClassSign')
def course_sign_in():
    guard = api_guard()
    if guard is not None:
        return flask_result(guard)
    return flask_result(run_sync(sign_in(flask_request.get_json(silent=True), environment())))


@app.errorhandler(404)
@app.errorhandler(405)
def missing_route(error):
    if flask_request.path.startswith('/api/'):
        return flask_result(api_result('4', '接口不存在或请求方法不正确', error.code))
    return asset('404.html')


FlaskEntrypoint = wsgi.entrypoint(app)


class Default(FlaskEntrypoint):
    async def scheduled(self, controller, env, ctx):
        await clean_access_logs(env)

    async def fetch(self, request):
        started = time.monotonic()
        path = urlparse(request.url).path
        identity = {}
        identity_token = ACCESS_IDENTITY.set(identity)
        try:
            try:
                response = await super().fetch(request)
            except Exception as error:
                console.error(f'请求处理失败: {type(error).__name__}')
                response = (api_result('1', '服务暂时不可用', 500) if path.startswith('/api/')
                            else Response('服务暂时不可用', status=500))
            elapsed = int((time.monotonic() - started) * 1000)
            console.log(json.dumps({'method': str(request.method), 'path': path,
                                    'status': response.status, 'duration_ms': elapsed}, ensure_ascii=False))
            await log_access(self.env, request, path, response.status, elapsed, identity)
            return response
        finally:
            ACCESS_IDENTITY.reset(identity_token)
