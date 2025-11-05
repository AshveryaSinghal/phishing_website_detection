
import re
import numpy as np
import pandas as pd
import streamlit as st
from joblib import load
import tldextract
from sklearn.base import BaseEstimator, TransformerMixin
from PIL import Image

class UrlNumericFeatures(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.suspicious = [
            "login","signin","secure","account","update","verify","bank",
            "confirm","wp-content","paypal","ebay","amazon","apple","google",
            "microsoft","facebook","netflix","adobe"
        ]
        self.brands = ["paypal","google","amazon","microsoft","apple",
                       "facebook","netflix","adobe","bank","ebay"]
        self.ip_pattern = re.compile(r"(^|://)?(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?(/|$)")

    def _strip_scheme_host(self, url):
        return re.split(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', str(url), maxsplit=1)[-1]

    def _host_only(self, url):
        s = self._strip_scheme_host(url)
        return s.split('/', 1)[0].split(':', 1)[0]

    def _path_depth(self, url):
        s = self._strip_scheme_host(url)
        path = s.split('/', 1)[1] if '/' in s else ''
        return len([p for p in path.split('/') if p])

    def _num_query_params(self, url):
        if '?' not in url: return 0
        query = url.split('?', 1)[1].split('#', 1)[0]
        if not query: return 0
        return sum(1 for kv in query.split('&') if kv.strip() != '')

    def _num_subdomains(self, url):
        host = self._host_only(url)
        if self.ip_pattern.search(host):
            return 0
        parts = [p for p in host.split('.') if p]
        return max(0, len(parts) - 2)

    def _tld_length(self, url):
        host = self._host_only(url)
        ext = tldextract.extract(host)
        suffix = ext.suffix or ""
        return len(suffix.split('.')[-1]) if suffix else 0

    def _registered_domain(self, url):
        host = self._host_only(url)
        ext = tldextract.extract(host)
        reg = ext.top_domain_under_public_suffix or host
        return reg.lower()

    def _brand_flags(self, url):
        u = str(url).lower()
        reg = self._registered_domain(url)
        brand_in_domain = int(any(b in reg for b in self.brands))
        brand_in_path_only = int(any(b in u for b in self.brands) and not brand_in_domain)
        return brand_in_domain, brand_in_path_only

    def fit(self, X, y=None): return self

    def transform(self, X):
        urls = pd.Series(X.iloc[:,0] if isinstance(X, pd.DataFrame) else X).astype(str)
        url_length = urls.str.len().fillna(0).astype(int).values
        num_dots = urls.str.count(r"\.").values
        num_hyphens = urls.str.count(r"-").values
        num_at = urls.str.count(r"@").values
        has_ip = urls.apply(lambda u: 1 if self.ip_pattern.search(self._host_only(u)) else 0).values
        path_depth = urls.apply(self._path_depth).values
        num_query_params = urls.apply(self._num_query_params).values
        num_subdomains = urls.apply(self._num_subdomains).values
        suspicious_count = urls.apply(lambda u: sum(1 for k in self.suspicious if k in u.lower())).values
        tld_len = urls.apply(self._tld_length).values
        brand_in_domain, brand_in_path_only = zip(*urls.apply(self._brand_flags))
        brand_in_domain = np.array(brand_in_domain)
        brand_in_path_only = np.array(brand_in_path_only)

        return np.column_stack([
            url_length, num_dots, num_hyphens, num_at, has_ip,
            path_depth, num_query_params, num_subdomains,
            suspicious_count, tld_len, brand_in_domain, brand_in_path_only
        ])

# ------- Helpers -------
SAFE_DOMAINS = {
    # Big legit brands to avoid false positives
    "google.com", "apple.com", "microsoft.com", "amazon.com",
    "wikipedia.org", "facebook.com", "netflix.com", "adobe.com",
    "paytm.com", "paypal.com"
}

def registered_domain(url: str) -> str:
    ext = tldextract.extract(str(url))
    return (ext.top_domain_under_public_suffix or "").lower()

def normalize_url(u: str) -> str | None:
    s = u.strip()
    if not s:
        return None
    # If there's no scheme and it looks like a domain, add https://
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', s):
        if "." in s:
            s = "https://" + s
        else:
           
            return None
    return s

# ------- Streamlit UI -------
st.set_page_config(page_title="Phishing URL Checker", page_icon="🛡️")
st.title("🛡️ Phishing URL Checker")
st.write("")   
st.write("")   

img = Image.open("original.jpg")


col1, col2, col3 = st.columns([1, 2, 1])

with col2:   
    st.image(img, width=300)

st.write("")  
st.write("")   

MODEL_PATH = "phishing_url_model.joblib"

@st.cache_resource
def load_pipeline(path):
    return load(path)

try:
    model = load_pipeline(MODEL_PATH)
except Exception as e:
    st.error(f"Failed to load model at '{MODEL_PATH}'. Make sure the file exists.\n\n{e}")
    st.stop()

url_input = st.text_input("🔗 URL", placeholder="https://example.com")

if st.button("Check URL"):
    norm = normalize_url(url_input)
    if norm is None:
        st.warning("Please paste a **full URL** (including domain), e.g., `https://paytm.com`.")
    else:
       
        X = pd.DataFrame({"URL": [norm]})
        pred = model.predict(X)
        label = pred[0]  

        
        rd = registered_domain(norm)
        if rd in SAFE_DOMAINS:
            label = "good"

        if label == "bad":
            st.error("🚨 This link appears to be **PHISHING / UNSAFE**")
        else:
            st.success("✅ This link appears to be **SAFE / LEGIT**")

        with st.expander("Details"):
            st.write({"input": url_input, "normalized": norm, "registered_domain": rd, "prediction": label})
