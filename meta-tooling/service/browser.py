import argparse
import time
import os
from playwright.sync_api import sync_playwright

def start_browser_service(port):
    with sync_playwright() as p:
        if os.getenv('NO_VISION'):
            headless=True
        else:
            headless=False
        browser = p.chromium.launch(
            headless=headless,
            args=[
                f'--remote-debugging-port={port}',
            ],
            proxy={
                "server": f"http://localhost:{os.getenv('CAIDO_PORT')}",
                "bypass": "localhost, 127.0.0.1, .google.com, .google.com.hk, .googleapis.com, .gvt1.com, .gvt1-cn.com, .gstatic.com, .ggpht.com"
            }
        )
        print(f"Browser service started on port {port}")
        contexts = browser.contexts
        if contexts:
            contexts[0].new_page()
        else:
            browser.new_context().new_page()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping browser service...")
            browser.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9222)
    args = parser.parse_args()
    start_browser_service(port=args.port)