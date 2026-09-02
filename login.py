#!/usr/bin/env python3
"""
breakout-cli Linux 扫码登录工具
================================
与 Windows/macOS 一致的登录体验：
生成授权链接 → 浏览器打开 → 微信扫码 → token 写入系统 keyring → CLI 全通。

登录流程（官方桌面授权机制）：
  1. 发起设备授权，获取一次性授权链接
  2. 浏览器打开链接 → 官网微信扫码登录 → 确认授权设备
  3. 检测到授权完成后，换取访问凭证
  4. 凭证写入系统 keyring（service=breakout-cli），CLI 自动续期

安全边界：
  - 不接收账号密码；扫码由用户在官网完成，凭据不经本工具
  - token 仅写入系统 keyring，不落盘、不打印
  - 本工具不含任何个人数据
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import webbrowser

BASE = os.environ.get('AIPOJU_BASE', 'https://aipoju.com/server')
POLL_INTERVAL = 3          # 轮询间隔秒
AUTH_TIMEOUT = 300         # 扫码超时（5 分钟，与 expiresAt 对齐）


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def s256_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


def http_json(method: str, path: str, body=None, params=None):
    url = f"{BASE}{path}"
    if params:
        url += '?' + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0',
        'Origin': 'https://aipoju.com',
        'Referer': 'https://aipoju.com/',
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode('utf-8', 'ignore'))
        except Exception:
            raise RuntimeError(f"HTTP {e.code}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"网络错误: {e.reason}")


def ensure_keyring() -> None:
    if 'DBUS_SESSION_BUS_ADDRESS' not in os.environ or not os.environ['DBUS_SESSION_BUS_ADDRESS']:
        out = subprocess.run(['dbus-launch', '--sh-syntax'], capture_output=True, text=True, timeout=10)
        for line in out.stdout.strip().splitlines():
            if '=' in line:
                k, _, v = line.partition('=')
                os.environ[k.strip()] = v.strip().strip("'")


def secret_tool_store(service: str, username_key: str, secret: str, label: str) -> None:
    proc = subprocess.run(
        ['secret-tool', 'store', '--label', label, 'service', service, 'username', username_key],
        input=secret.encode('utf-8'), capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"secret-tool store 失败: {proc.stderr.decode('utf-8', 'ignore')[:300]}")


def write_cli_config(device_id: str) -> None:
    cfg_dir = os.path.expanduser('~/.breakout')
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, 'config.json')
    cfg = {"baseUrl": BASE, "deviceId": device_id}
    if os.path.exists(cfg_path):
        try:
            old = json.load(open(cfg_path))
            if old.get('deviceId'):
                cfg['deviceId'] = old['deviceId']
        except Exception:
            pass
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f)
    os.chmod(cfg_path, 0o600)


def main():
    ap = argparse.ArgumentParser(description='breakout-cli Linux 扫码登录器（与 Windows 体验一致）')
    ap.add_argument('--platform', default='win32', help='设备平台标识（默认 win32，保持与官方一致）')
    ap.add_argument('--service', default='breakout-cli', help='keyring service 名（默认 breakout-cli）')
    ap.add_argument('--no-browser', action='store_true', help='不自动打开浏览器，只打印链接')
    ap.add_argument('--device-id', default=None, help='deviceId（默认随机生成）')
    args = ap.parse_args()

    # ---------- 1. 发起设备授权 ----------
    verifier = b64url(secrets.token_bytes(32))
    challenge = s256_challenge(verifier)
    device_id = args.device_id or f'cli-{secrets.token_hex(8)}'
    platform = args.platform

    print('→ 正在发起设备授权...')
    result = http_json('POST', '/desktop-auth/authorizations', {
        'platform': platform,
        'deviceId': device_id,
        'codeChallenge': challenge,
        'deviceName': 'breakout-cli',
    })
    if result.get('code') != 200:
        print(f"✗ 发起失败: {result.get('msg', result)}", file=sys.stderr)
        sys.exit(2)
    data = result['data']
    login_id = data['loginId']
    uri = data['verificationUri']
    expires_at = data.get('expiresAt', '?')

    # ---------- 2. 引导扫码 ----------
    print()
    print('=' * 60)
    print('  请在浏览器中打开以下链接，使用微信扫码完成授权：')
    print('=' * 60)
    print(f'  {uri}')
    print('=' * 60)
    print(f'  授权有效期至: {expires_at}')
    if not args.no_browser:
        try:
            if webbrowser.open(uri):
                print('  （已尝试自动打开浏览器）')
        except Exception:
            pass
    print()
    print('  等待扫码授权中...（Ctrl+C 取消）')

    # ---------- 3. 轮询授权状态 ----------
    deadline = time.time() + AUTH_TIMEOUT
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            st = http_json('GET', f'/desktop-auth/authorizations/{login_id}')
        except Exception as e:
            print(f'  ! 轮询异常: {e}，重试中...')
            continue
        if st.get('code') != 200:
            continue
        status = st.get('data', {}).get('status')
        if status == 'approved':
            print('✓ 已授权！正在换取 token...')
            break
        if status == 'expired' or status == 'rejected':
            print(f'✗ 授权已{status}，请重新运行登录', file=sys.stderr)
            sys.exit(3)
        if status == 'pending':
            print(f'  · 等待授权... ({int(deadline - time.time())}s 剩余)', end='\r')
    else:
        print()
        print('✗ 等待超时，请重新运行', file=sys.stderr)
        sys.exit(4)
    print()

    # ---------- 4. 交换 token ----------
    tok = http_json('POST', '/desktop-auth/token', {
        'loginId': login_id,
        'codeVerifier': verifier,
        'grantType': 'authorization_code',
    })
    if tok.get('code') != 200:
        print(f"✗ token 交换失败: {tok.get('msg', tok)}", file=sys.stderr)
        sys.exit(5)
    tdata = tok['data']
    token = tdata.get('token') or tdata.get('accessToken') or tdata.get('access_token')
    refresh = tdata.get('refreshToken') or tdata.get('refresh_token')
    if not token:
        print(f'✗ 响应缺少 token，请反馈结构: {json.dumps(tdata, ensure_ascii=False)[:300]}', file=sys.stderr)
        sys.exit(6)

    # ---------- 5. 写 keyring + config ----------
    ensure_keyring()
    svc = args.service
    secret_tool_store(svc, 'access-token', token, 'breakout access-token')
    if refresh:
        secret_tool_store(svc, 'refresh-token', refresh, 'breakout refresh-token')
    write_cli_config(device_id)
    print('✓ keyring + config 写入完成')

    print()
    print('🎉 登录成功！验证：')
    print('    breakout doctor')
    print('    breakout auth status --json')


if __name__ == '__main__':
    main()
