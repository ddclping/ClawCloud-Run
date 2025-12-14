#!/usr/bin/env python3
"""
ClawCloud 自动登录脚本
- 支持等待设备验证批准
- 自动保存 Cookie 供下次使用
- Telegram 通知
"""

import os
import sys
import time
import json
import base64
import requests
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
CLAW_CLOUD_URL = "https://eu-central-1.run.claw.cloud"
SIGNIN_URL = f"{CLAW_CLOUD_URL}/signin"
DEVICE_VERIFY_WAIT = 30  # 等待设备验证的秒数


class TelegramNotifier:
    """Telegram 通知"""
    
    def __init__(self):
        self.bot_token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.enabled = bool(self.bot_token and self.chat_id)
    
    def send(self, message):
        if not self.enabled:
            return False
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            requests.post(url, data={
                "chat_id": self.chat_id, 
                "text": message, 
                "parse_mode": "HTML"
            }, timeout=30)
            return True
        except:
            return False
    
    def send_photo(self, path, caption=""):
        if not self.enabled or not os.path.exists(path):
            return False
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendPhoto"
            with open(path, 'rb') as f:
                requests.post(url, data={
                    "chat_id": self.chat_id, 
                    "caption": caption[:1024]
                }, files={"photo": f}, timeout=60)
            return True
        except:
            return False


class GitHubSecretsManager:
    """GitHub Secrets 管理器"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.enabled = bool(self.token and self.repo)
    
    def update_secret(self, name, value):
        """更新 GitHub Secret"""
        if not self.enabled:
            return False
        
        try:
            # 获取公钥
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            key_url = f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key"
            key_resp = requests.get(key_url, headers=headers, timeout=30)
            
            if key_resp.status_code != 200:
                print(f"获取公钥失败: {key_resp.status_code}")
                return False
            
            key_data = key_resp.json()
            public_key = key_data['key']
            key_id = key_data['key_id']
            
            # 加密 secret
            from nacl import encoding, public
            
            public_key_bytes = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
            sealed_box = public.SealedBox(public_key_bytes)
            encrypted = sealed_box.encrypt(value.encode("utf-8"))
            encrypted_value = base64.b64encode(encrypted).decode("utf-8")
            
            # 更新 secret
            secret_url = f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}"
            resp = requests.put(secret_url, headers=headers, json={
                "encrypted_value": encrypted_value,
                "key_id": key_id
            }, timeout=30)
            
            if resp.status_code in [201, 204]:
                print(f"✅ 已更新 Secret: {name}")
                return True
            else:
                print(f"更新 Secret 失败: {resp.status_code}")
                return False
                
        except Exception as e:
            print(f"更新 Secret 异常: {e}")
            return False


class AutoLogin:
    """自动登录"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION')
        self.screenshot_count = 0
        self.screenshots = []
        self.telegram = TelegramNotifier()
        self.secrets = GitHubSecretsManager()
        self.logs = []
        self.new_session_cookie = None
        
    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        self.logs.append(line)
    
    def screenshot(self, page, name):
        self.screenshot_count += 1
        filename = f"{self.screenshot_count:02d}_{name}.png"
        page.screenshot(path=filename)
        self.screenshots.append(filename)
        self.log(f"截图: {filename}")
        return filename
    
    def get_github_cookies(self):
        """获取预存的 GitHub Cookies"""
        cookies = []
        if self.gh_session:
            cookies.append({
                'name': 'user_session',
                'value': self.gh_session,
                'domain': '.github.com',
                'path': '/',
                'httpOnly': True,
                'secure': True
            })
            cookies.append({
                'name': 'logged_in',
                'value': 'yes',
                'domain': '.github.com',
                'path': '/',
                'secure': True
            })
        return cookies
    
    def extract_session_cookie(self, context):
        """提取 GitHub Session Cookie"""
        cookies = context.cookies()
        for cookie in cookies:
            if cookie['name'] == 'user_session' and 'github.com' in cookie.get('domain', ''):
                return cookie['value']
        return None
    
    def save_session_cookie(self, session_value):
        """保存 Session Cookie"""
        if not session_value:
            return
        
        self.new_session_cookie = session_value
        self.log(f"新 Session Cookie: {session_value[:20]}...{session_value[-10:]}", "SUCCESS")
        
        # 尝试自动更新 GitHub Secret
        if self.secrets.enabled:
            if self.secrets.update_secret('GH_SESSION', session_value):
                self.log("已自动更新 GH_SESSION Secret", "SUCCESS")
                self.telegram.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已自动保存到 GitHub Secrets")
            else:
                self.send_cookie_to_telegram(session_value)
        else:
            self.send_cookie_to_telegram(session_value)
    
    def send_cookie_to_telegram(self, session_value):
        """通过 Telegram 发送 Cookie"""
        msg = f"""🔑 <b>新的 GitHub Session Cookie</b>

请手动更新 GitHub Secret:
<b>名称:</b> GH_SESSION
<b>值:</b>
<code>{session_value}</code>

⚠️ 此 Cookie 有效期约 14-30 天"""
        
        self.telegram.send(msg)
        self.log("已通过 Telegram 发送新 Cookie", "SUCCESS")
    
    def find_and_click(self, page, selectors, desc="元素"):
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=3000):
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except:
                continue
        return False
    
    def wait_for_device_approval(self, page):
        """等待设备验证批准"""
        self.log(f"检测到设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.screenshot(page, "设备验证")
        
        # 发送 Telegram 通知
        self.telegram.send(f"""⚠️ <b>需要设备验证</b>

GitHub 检测到新设备登录，请在 {DEVICE_VERIFY_WAIT} 秒内批准：

1️⃣ 检查邮箱，点击验证链接
2️⃣ 或在 GitHub App 中批准

⏰ 等待中...""")
        
        # 发送截图
        if self.screenshots:
            self.telegram.send_photo(self.screenshots[-1], "设备验证页面")
        
        # 等待并检查
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            
            # 每5秒检查一次页面状态
            if i % 5 == 0:
                current_url = page.url
                self.log(f"  等待中... ({i}/{DEVICE_VERIFY_WAIT}秒) - {current_url[:50]}")
                
                # 检查是否已通过验证
                if 'verified-device' not in current_url and 'device-verification' not in current_url:
                    self.log("设备验证已通过！", "SUCCESS")
                    self.telegram.send("✅ <b>设备验证已通过</b>")
                    return True
                
                # 刷新页面检查状态
                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
        
        # 最后再检查一次
        current_url = page.url
        if 'verified-device' not in current_url and 'device-verification' not in current_url:
            self.log("设备验证已通过！", "SUCCESS")
            return True
        
        self.log("设备验证超时", "ERROR")
        self.telegram.send("❌ <b>设备验证超时</b>\n\n请手动完成验证后重新运行")
        return False
    
    def login_github(self, page, context):
        """登录 GitHub"""
        self.log("登录 GitHub...", "STEP")
        self.screenshot(page, "github_登录页")
        
        # 输入凭据
        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            self.log("已输入凭据")
        except Exception as e:
            self.log(f"输入凭据失败: {e}", "ERROR")
            return False
        
        self.screenshot(page, "github_已填写")
        
        # 点击登录
        try:
            page.locator('input[type="submit"], button[type="submit"]').first.click()
        except:
            pass
        
        time.sleep(3)
        page.wait_for_load_state('networkidle', timeout=30000)
        self.screenshot(page, "github_登录后")
        
        url = page.url
        self.log(f"当前页面: {url}")
        
        # 检查设备验证
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_for_device_approval(page):
                return False
            
            # 验证通过后，重新加载页面
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.screenshot(page, "验证后")
            url = page.url
            self.log(f"验证后页面: {url}")
        
        # 检查 2FA
        if 'two-factor' in url:
            self.log("需要两步验证！", "ERROR")
            self.telegram.send("❌ <b>需要两步验证</b>\n\n此脚本无法处理 2FA，请关闭 2FA 或使用其他方式")
            return False
        
        # 检查错误
        try:
            error = page.locator('.flash-error').first
            if error.is_visible(timeout=2000):
                self.log(f"登录错误: {error.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        # 提取并保存新的 Session Cookie
        new_session = self.extract_session_cookie(context)
        if new_session and new_session != self.gh_session:
            self.save_session_cookie(new_session)
        
        return True
    
    def handle_oauth(self, page):
        """处理 OAuth"""
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("处理 OAuth 授权...", "STEP")
            self.screenshot(page, "oauth")
            self.find_and_click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权按钮")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def wait_redirect(self, page, max_wait=60):
        """等待重定向"""
        self.log("等待重定向到 ClawCloud...", "STEP")
        
        for i in range(max_wait):
            url = page.url
            
            if 'claw.cloud' in url and 'signin' not in url.lower():
                self.log("重定向成功！", "SUCCESS")
                return True
            
            if 'github.com/login/oauth/authorize' in url:
                self.handle_oauth(page)
            
            time.sleep(1)
            if i % 10 == 0:
                self.log(f"  等待中... ({i}秒)")
        
        self.log("重定向超时", "ERROR")
        return False
    
    def verify_and_keepalive(self, page, context):
        """验证登录并保活"""
        url = page.url
        self.log(f"最终页面: {url}")
        
        if 'claw.cloud' not in url or 'signin' in url.lower():
            self.log("登录验证失败", "ERROR")
            return False
        
        # 保活
        self.log("访问页面保活...", "STEP")
        for target_url, name in [(f"{CLAW_CLOUD_URL}/", "控制台"), (f"{CLAW_CLOUD_URL}/apps", "应用")]:
            try:
                page.goto(target_url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=15000)
                self.log(f"已访问: {name}", "SUCCESS")
                time.sleep(2)
            except:
                pass
        
        self.screenshot(page, "完成")
        return True
    
    def send_notification(self, success, error=""):
        if not self.telegram.enabled:
            return
        
        status = "✅ 成功" if success else "❌ 失败"
        msg = f"""<b>🤖 ClawCloud 自动登录</b>

<b>状态:</b> {status}
<b>用户:</b> {self.username}
<b>时间:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        if error:
            msg += f"\n<b>错误:</b> {error}"
        
        if self.new_session_cookie:
            msg += "\n\n🔑 已获取新的 Session Cookie"
        
        recent = self.logs[-6:]
        if recent:
            msg += "\n\n<b>日志:</b>\n" + "\n".join(recent)
        
        self.telegram.send(msg)
        
        # 发送截图
        if self.screenshots:
            if not success:
                for ss in self.screenshots[-3:]:
                    self.telegram.send_photo(ss, ss)
            else:
                self.telegram.send_photo(self.screenshots[-1], "完成")
    
    def run(self):
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录")
        print("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session Cookie: {'已配置' if self.gh_session else '未配置'}")
        self.log(f"密码: {'已配置' if self.password else '未配置'}")
        self.log(f"自动更新 Secret: {'已启用' if self.secrets.enabled else '未启用'}")
        
        if not self.username or not self.password:
            self.log("未配置用户名或密码", "ERROR")
            self.send_notification(False, "凭据未配置")
            sys.exit(1)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            
            page = context.new_page()
            
            try:
                # 预加载 Cookie
                if self.gh_session:
                    context.add_cookies(self.get_github_cookies())
                    self.log("已预加载 Session Cookie", "SUCCESS")
                
                # 步骤1: 访问 ClawCloud
                self.log("步骤1: 打开 ClawCloud", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(2)
                self.screenshot(page, "clawcloud")
                
                # 已登录检查
                if 'signin' not in page.url.lower():
                    self.log("已经登录！", "SUCCESS")
                    if self.verify_and_keepalive(page, context):
                        self.send_notification(True)
                        print("\n✅ 成功！\n")
                        return
                
                # 步骤2: 点击 GitHub 登录
                self.log("步骤2: 点击 GitHub 登录", "STEP")
                
                if not self.find_and_click(page, [
                    'button:has-text("GitHub")',
                    'a:has-text("GitHub")',
                    '[data-provider="github"]'
                ], "GitHub 按钮"):
                    self.log("找不到 GitHub 按钮", "ERROR")
                    self.send_notification(False, "找不到 GitHub 按钮")
                    sys.exit(1)
                
                time.sleep(3)
                page.wait_for_load_state('networkidle', timeout=30000)
                self.screenshot(page, "点击后")
                
                url = page.url
                self.log(f"当前: {url}")
                
                # 步骤3: GitHub 登录
                self.log("步骤3: GitHub 认证", "STEP")
                
                if 'github.com/login' in url or 'github.com/session' in url:
                    if not self.login_github(page, context):
                        self.screenshot(page, "登录失败")
                        self.send_notification(False, "GitHub 登录失败")
                        print("\n❌ GitHub 登录失败！\n")
                        sys.exit(1)
                elif 'github.com/login/oauth/authorize' in url:
                    self.log("Cookie 有效，处理 OAuth...", "SUCCESS")
                    self.handle_oauth(page)
                
                # 步骤4: 等待重定向
                self.log("步骤4: 等待重定向", "STEP")
                
                if not self.wait_redirect(page):
                    self.screenshot(page, "重定向失败")
                    self.send_notification(False, "重定向失败")
                    print("\n❌ 重定向失败！\n")
                    sys.exit(1)
                
                self.screenshot(page, "重定向成功")
                
                # 步骤5: 验证并保活
                self.log("步骤5: 验证并保活", "STEP")
                
                if not self.verify_and_keepalive(page, context):
                    self.send_notification(False, "验证失败")
                    print("\n❌ 验证失败！\n")
                    sys.exit(1)
                
                # 最后再提取一次 Cookie
                new_session = self.extract_session_cookie(context)
                if new_session and new_session != self.gh_session:
                    self.save_session_cookie(new_session)
                
                self.send_notification(True)
                print("\n" + "="*50)
                print("✅ 自动登录成功！")
                print("="*50 + "\n")
                
            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                self.screenshot(page, "异常")
                self.send_notification(False, str(e))
                sys.exit(1)
            
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()
