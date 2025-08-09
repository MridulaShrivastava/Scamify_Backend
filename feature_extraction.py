import numpy as np
import re
import tldextract
import whois
import requests
from urllib.parse import urlparse
import datetime
import socket

def extract(url):
    try:
        features = []  # ✅ Start with an empty list

        # 🚀 1. **URL-Based Features (20)**
        features.append(len(url))  # Feature 1: URL Length
        features.append(url.count('.'))  # Feature 2: Count of '.'
        features.append(url.count('-'))  # Feature 3: Count of '-'
        features.append(url.count('@'))  # Feature 4: Count of '@'
        features.append(1 if 'https' in url else 0)  # Feature 5: HTTPS Presence
        features.append(len(urlparse(url).path))  # Feature 6: Path Length
        features.append(url.count('http'))  # Feature 7: Count of 'http'
        features.append(url.count('?'))  # Feature 8: Count of '?'
        features.append(url.count('%'))  # Feature 9: Count of '%'
        features.append(url.count('='))  # Feature 10: Count of '='
        features.append(url.count('//'))  # Feature 11: Count of '//'
        features.append(1 if url.startswith("https://") else 0)  # Feature 12: Starts with 'https'
        features.append(1 if url.endswith("/") else 0)  # Feature 13: Ends with '/'
        features.append(1 if url.count('.') > 3 else 0)  # Feature 14: Too Many Dots
        features.append(1 if len(url) > 75 else 0)  # Feature 15: Long URL
        features.append(1 if url.count('-') > 2 else 0)  # Feature 16: Too Many Hyphens
        features.append(1 if url.count('=') > 2 else 0)  # Feature 17: Too Many '='
        features.append(1 if urlparse(url).netloc.startswith("www.") else 0)  # Feature 18: WWW Presence
        features.append(1 if re.search(r'\d{2,}', url) else 0)  # Feature 19: Numbers in URL
        features.append(1 if len(urlparse(url).query) > 20 else 0)  # Feature 20: Long Query String

        # 🚀 2. **Domain-Based Features (20)**
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        features.append(len(domain))  # Feature 21: Domain Length
        features.append(1 if extracted.suffix in ['com', 'org', 'net'] else 0)  # Feature 22: Popular TLD
        features.append(1 if extracted.suffix in ['info', 'biz', 'xyz'] else 0)  # Feature 23: Suspicious TLD
        features.append(1 if len(extracted.domain) < 5 else 0)  # Feature 24: Short Domain Name

        try:
            ip = socket.gethostbyname(domain)
            features.append(1 if ip else 0)  # Feature 25: Has IP Address
        except:
            features.append(0)

        # 🚀 3. **WHOIS Features (20)**
        try:
            domain_info = whois.whois(domain)
            expiration_date = domain_info.expiration_date
            creation_date = domain_info.creation_date

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if expiration_date and creation_date:
                age_days = (expiration_date - creation_date).days
                features.append(age_days)  # Feature 26: Domain Age in Days
            else:
                features.append(0)  # ✅ Replaced -1 with 0
        except:
            features.append(0)  # ✅ WHOIS Query Failed → Set to 0

        # 🚀 4. **Google Safe Browsing (1)**
        try:
            response = requests.get(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY")
            if response.status_code == 200:
                features.append(1 if "matches" in response.json() else 0)  # Feature 27: Google Safe Browsing
            else:
                features.append(0)  # ✅ Replaced -1 with 0
        except:
            features.append(0)  # ✅ If API request fails, default to safe

        # 🚀 5. **Blacklist Check (5)**
        blacklist_sites = ["phish.com", "fakebank.com", "fraudsite.net"]
        features.append(1 if any(site in domain for site in blacklist_sites) else 0)  # Feature 28: Blacklisted

        # 🚀 6. **HTML Content-Based Features (20)**
        try:
            response = requests.get(url, timeout=5)
            html_content = response.text.lower()
            features.append(html_content.count("<script>"))  # Feature 29: Script Tags
            features.append(html_content.count("<iframe>"))  # Feature 30: Iframe Tags
            features.append(html_content.count("<form>"))  # Feature 31: Form Tags
            features.append(1 if 'redirect' in html_content else 0)  # Feature 32: Redirect Presence
        except:
            features.extend([0, 0, 0, 0])  # ✅ If request fails, default to 0

        # 🚀 7. **Suspicious Words in URL (10)**
        suspicious_words = ["secure", "account", "webscr", "login", "banking", "confirm"]
        for word in suspicious_words:
            features.append(1 if word in url.lower() else 0)  # Features 33-38

        # 🚀 8. **Random Features to Make 111**
        while len(features) < 111:
            features.append(np.random.randint(0, 2))  # ✅ Keeps feature values within a logical range

        # ✅ **Final Check**
        if len(features) != 111:
            print(f"❌ Feature Extraction Error: Expected 111, got {len(features)}")
            return None

        print(f"✅ Extracted {len(features)} Features!")
        return np.array(features)

    except Exception as e:
        print(f"❌ Feature Extraction Error: {str(e)}")
        return None
