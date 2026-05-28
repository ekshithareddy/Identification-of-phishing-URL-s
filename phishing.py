import re
import tkinter as tk 
from tkinter import ttk, messagebox
from urllib.parse import urlparse, unquote
import ipaddress

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        return bool(parsed.netloc)
    except Exception:
        return False

def has_ip_address_domain(netloc: str) -> bool:
    # strip port if present
    host = netloc.split(':')[0]
    try:
      ipaddress.ip_address(host)
      return True
        
    except Exception:
        return False

def contains_at_symbol(url: str) -> bool:
    return '@' in url

def has_long_url(url: str, threshold: int = 75) -> bool:
    return len(url) > threshold

def contains_encoded_chars(url: str) -> bool:
    # percent-encoded or many % signs
    return '%' in url

def too_many_subdomains(netloc: str, threshold: int = 3) -> bool:
    host = netloc.split(':')[0]
    parts = [p for p in host.split('.') if p and p.lower() not in ('www',)]
    return len(parts) > threshold

def suspicious_tld(netloc: str) -> bool:
    suspicious = {
        'country': ['tk','ml','cf','gq','ga'],    
        'others': ['xyz','top','club','online','site','info','ru','cn']
    }
    host = netloc.split(':')[0].lower()
    if '.' not in host:
        return False
    tld = host.rsplit('.', 1)[-1]
    return tld in suspicious['others'] or tld in suspicious['country']

def suspicious_keywords_in_domain(netloc: str) -> bool:
    host = netloc.split(':')[0].lower()
    keywords = ['login','signin','update','secure','account','verify','bank','ebay','paypal']
    return any(k in host for k in keywords)

def suspicious_keywords_in_path(url: str) -> bool:
    path = urlparse(url if '://' in url else 'http://' + url).path.lower()
    keywords = ['confirm','verify','password','wp-admin','signin','login','secure','update']
    return any(k in path for k in keywords)

def has_dash_in_domain(netloc: str) -> bool:
    host = netloc.split(':')[0]
    return '-' in host

def unusual_port(netloc: str) -> bool:
    if ':' not in netloc:
        return False
    try:
        port = int(netloc.split(':')[-1])
        return port not in (80, 443)
    except ValueError:
        return False

def many_numeric_chars(host: str, threshold_ratio=0.3) -> bool:
    chars = [c for c in host if c.isdigit()]
    return len(chars) / max(len(host),1) >= threshold_ratio

def multiple_redirect_like_tokens(url: str) -> bool:
    parsed = urlparse(url if '://' in url else 'http://' + url)
    check = parsed.path + '?' + (parsed.query or '')
    return '//' in check or '///' in check

def analyze_url(url: str) -> dict:
    result = {
        'url': url,
        'valid': False,
        'score': 0,
        'max_score': 100,
        'issues': [],
        'advice': []
    }

    if not url.strip():
        result['issues'].append("No URL provided.")
        return result

    # normalize
    orig = url.strip()
    if not ('://' in orig):
        url = 'http://' + orig
    else:
        url = orig

    if not is_valid_url(url):
        result['issues'].append("Invalid URL format.")
        return result

    parsed = urlparse(url)
    netloc = parsed.netloc
    host = netloc.split(':')[0].lower()
    path = unquote(parsed.path + ('?' + parsed.query if parsed.query else ''))

    result['valid'] = True

    score = 50

    if has_ip_address_domain(netloc):
        score -= 10
        result['issues'].append("Domain is an IP address (suspicious).")
        result['advice'].append("Avoid links that use raw IP addresses for sensitive actions.")

    if contains_at_symbol(orig):
        score -= 50
        result['issues'].append("URL contains '@' which hides real domain.")
        result['advice'].append("Remove everything before '@' — legitimate sites rarely use this.")

    if has_long_url(orig):
        score -= 10
        result['issues'].append(f"Very long URL (length={len(orig)}).")
        result['advice'].append("Long obfuscated URLs are often used for phishing.")

    if contains_encoded_chars(orig):
        score -= 8
        result['issues'].append("URL contains encoded characters (percent-encoding).")
        result['advice'].append("Be cautious: attackers often encode payload or redirect information.")

    if too_many_subdomains(netloc):
        score -= 10
        result['issues'].append("Many subdomains present (possibly impersonation).")
        result['advice'].append("Check the registered domain name (the right-most two labels).")

    if suspicious_tld(netloc):
        score -= 8
        result['issues'].append("Top-level domain looks suspicious/rare.")
        result['advice'].append("Some TLDs are frequently abused; prefer well-known TLDs for financial/corporate sites.")

    if suspicious_keywords_in_domain(netloc):
        score -= 12
        result['issues'].append("Domain contains words like 'login'/'secure' (commonly abused).")
        result['advice'].append("Phishers often add such words to domains to trick users.")

    if suspicious_keywords_in_path(orig):
        score -= 10
        result['issues'].append("URL path contains suspicious keywords (e.g., 'verify', 'confirm').")
        result['advice'].append("Legitimate services rarely ask to 'verify' via a random link; use official site directly.")

    if has_dash_in_domain(netloc):
        score -= 10
        result['issues'].append("Domain contains hyphen(s); could be lookalike domain.")
        result['advice'].append("Be careful: attackers register domains with hyphens to mimic legitimate domains.")

    if unusual_port(netloc):
        score -= 10
        result['issues'].append("URL explicitly uses an unusual port.")
        result['advice'].append("Unusual ports can indicate hosting on non-standard servers.")

    if many_numeric_chars(host):
        score -= 8
        result['issues'].append("Domain has many numeric characters (suspicious).")
        result['advice'].append("Numeric-heavy domains can be auto-generated and malicious.")

    if multiple_redirect_like_tokens(orig):
        score -= 5
        result['issues'].append("URL contains redirect-like sequences ('//' in path/query).")
        result['advice'].append("Redirects may be used to hide the final destination.")

   
    if host.startswith('www.') or len(host) < 25:
        score += 35

    score = max(0, min(100, score))
    result['score'] = score

    if score >= 75:
        result['rating'] = 'Low Risk'
        result['summary'] = 'Likely safe — still verify if unexpected.'
    elif score >= 55:
        result['rating'] = 'Medium Risk'
        result['summary'] = 'Suspicious indicators found — exercise caution.'
    else:
        result['rating'] = 'High Risk'
        result['summary'] = 'Likely phishing or malicious — do not click or provide credentials.'

    # general advice if no specific ones
    if not result['advice']:
        result['advice'].append("If unsure, visit the site by typing the main domain in a browser yourself instead of following links.")

    return result

class PhishCheckerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Phishing URL Checker (Python + Tkinter)")
        root.resizable(False, False)
        self.build_ui()

    def build_ui(self):
        pad = 8
        main = ttk.Frame(self.root, padding=pad)
        main.grid(row=0, column=0, sticky="nsew")

        ttk.Label(main, text="Enter URL to analyze:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky="w")

        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(main, textvariable=self.url_var, width=70)
        url_entry.grid(row=1, column=0, pady=(4,10))
        url_entry.bind("<Return>", lambda e: self.run_check())

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=2, column=0, sticky="w")
        ttk.Button(btn_frame, text="Analyze URL", command=self.run_check).grid(row=0, column=0, padx=(0,6))
        ttk.Button(btn_frame, text="Clear", command=self.clear_all).grid(row=0, column=1)

        # Results area
        sep = ttk.Separator(main, orient="horizontal")
        sep.grid(row=3, column=0, sticky="ew", pady=10)

        result_frame = ttk.Frame(main)
        result_frame.grid(row=4, column=0, sticky="nsew")

        ttk.Label(result_frame, text="Risk Score:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        self.score_label = ttk.Label(result_frame, text="-", font=("Segoe UI", 12))
        self.score_label.grid(row=0, column=1, sticky="w", padx=(8,0))

        ttk.Label(result_frame, text="Rating:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w")
        self.rating_label = ttk.Label(result_frame, text="-", font=("Segoe UI", 12))
        self.rating_label.grid(row=1, column=1, sticky="w", padx=(8,0))

        ttk.Label(result_frame, text="Summary:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="nw", pady=(6,0))
        self.summary_box = tk.Text(result_frame, height=3, width=60, wrap="word")
        self.summary_box.grid(row=2, column=1, pady=(6,0), sticky="w")
        self.summary_box.configure(state="disabled")

        ttk.Label(result_frame, text="Detected Issues:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="nw", pady=(8,0))
        self.issues_box = tk.Text(result_frame, height=6, width=60, wrap="word")
        self.issues_box.grid(row=3, column=1, pady=(8,0), sticky="w")
        self.issues_box.configure(state="disabled")

        ttk.Label(result_frame, text="Advice:", font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="nw", pady=(8,0))
        self.advice_box = tk.Text(result_frame, height=5, width=60, wrap="word")
        self.advice_box.grid(row=4, column=1, pady=(8,0), sticky="w")
        self.advice_box.configure(state="disabled")

        # Footer / demo examples
        ttk.Label(main, text="Tip: Try urls like 'http://192.168.1.1/login' or 'http://paypal-login.example.com/verify' for testing.", font=("Segoe UI", 8)).grid(row=5, column=0, pady=(10,0), sticky="w")

    def run_check(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input required", "Please enter a URL to analyze.")
            return
        result = analyze_url(url)
        self.show_result(result)

    def show_result(self, res: dict):
        # update labels
        self.score_label.config(text=f"{res.get('score', '-')}/100")
        self.rating_label.config(text=res.get('rating', '-'))

        # update summary
        self.summary_box.configure(state="normal")
        self.summary_box.delete("1.0", "end")
        self.summary_box.insert("1.0", res.get('summary', '-'))
        self.summary_box.configure(state="disabled")

        # issues
        self.issues_box.configure(state="normal")
        self.issues_box.delete("1.0", "end")
        if res.get('issues'):
            for i, it in enumerate(res['issues'], 1):
                self.issues_box.insert("end", f"{i}. {it}\n")
        else:
            self.issues_box.insert("end", "No suspicious patterns detected.")
        self.issues_box.configure(state="disabled")

        # advice
        self.advice_box.configure(state="normal")
        self.advice_box.delete("1.0", "end")
        for a in res.get('advice', []):
            self.advice_box.insert("end", f"- {a}\n")
        self.advice_box.configure(state="disabled")

    def clear_all(self):
        self.url_var.set("")
        self.score_label.config(text='-')
        self.rating_label.config(text='-')
        for tb in (self.summary_box, self.issues_box, self.advice_box):
            tb.configure(state="normal")
            tb.delete("1.0", "end")
            tb.configure(state="disabled")


def main():
    root = tk.Tk()
    style = ttk.Style(root)
    # Attempt to set a modern theme if available
    try:
        style.theme_use('clam')
    except Exception:
        pass
    PhishCheckerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    try:
        print("Starting app...")
        main()
    except Exception as e:
        print("ERROR:", e)