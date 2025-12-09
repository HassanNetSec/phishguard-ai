# main.py

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import socket
import requests
from datetime import datetime

# --- 1. Load the Model ---
try:
    MODEL_PATH = 'randomforestmodel.joblib'
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully.")
except FileNotFoundError:
    print(f"ERROR: Model file not found at {MODEL_PATH}. Prediction will use mock data.")
    model = None
except Exception as e:
    print(f"ERROR loading model: {e}")
    model = None

# --- 2. Setup FastAPI App ---
app = FastAPI(title="Phishing URL Scanner API")

# Allow CORS for your Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UrlRequest(BaseModel):
    link: str

class ScanResult(BaseModel):
    status: str
    message: str
    details: list
    prediction_score: float

# --- 3. Feature Extraction Functions ---

def is_valid_domain(domain: str) -> bool:
    """Check if domain has valid TLD"""
    if not domain:
        return False
    
    # Common valid TLDs including country-specific academic domains
    valid_tlds = [
        '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
        '.co', '.io', '.ai', '.app', '.dev', '.tech', '.info',
        '.biz', '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp',
        '.cn', '.in', '.br', '.ru', '.it', '.es', '.nl', '.se',
        '.no', '.dk', '.fi', '.pl', '.tr', '.za', '.mx', '.ar',
        # Academic domains (country-specific)
        '.edu.pk', '.edu.au', '.edu.cn', '.edu.in', '.edu.sg',
        '.ac.uk', '.ac.za', '.ac.jp', '.ac.kr', '.ac.nz',
        '.edu.tr', '.edu.bd', '.edu.my', '.edu.eg', '.edu.sa'
    ]
    
    return any(domain.endswith(tld) for tld in valid_tlds)

def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address (IPv4 or IPv6)"""
    # Check for IPv4
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_pattern.match(domain):
        return True
    
    # Check for IPv6
    try:
        socket.inet_pton(socket.AF_INET6, domain)
        return True
    except socket.error:
        pass
    
    return False

def count_subdomains(domain: str) -> int:
    """Count the number of subdomains in a domain"""
    if not domain:
        return 0
    
    # Remove www. if present for accurate counting
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Split domain into parts
    parts = domain.split('.')
    
    # Handle country-specific TLDs like .edu.pk, .ac.uk, .co.uk
    # These have 3 parts for base domain (e.g., giki.edu.pk)
    if len(parts) >= 3:
        # Check if last two parts form a known multi-part TLD
        last_two = '.' + '.'.join(parts[-2:])
        multi_part_tlds = [
            '.edu.pk', '.edu.au', '.edu.cn', '.edu.in', 
            '.ac.uk', '.ac.za', '.co.uk', '.co.jp', '.co.in',
            '.gov.uk', '.org.uk', '.net.au', '.com.au'
        ]
        
        if last_two in multi_part_tlds:
            # Base domain is 3 parts (e.g., giki.edu.pk)
            # Anything beyond that is a subdomain
            return max(0, len(parts) - 3)
    
    # Standard TLD (e.g., .com, .org)
    # Base domain is 2 parts (e.g., example.com)
    # Anything beyond that is a subdomain
    return max(0, len(parts) - 2)

def has_valid_dns(domain: str) -> bool:
    """Check if domain has valid DNS record"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def check_url_reputation(url: str) -> dict:
    """Check URL against VirusTotal API (free tier)"""
    try:
        # Using Google Safe Browsing Lookup API as alternative
        # For production, get your own API key from https://developers.google.com/safe-browsing
        
        # Simple heuristic checks
        domain = urlparse(url).netloc.lower()
        
        # Check for common phishing keywords
        phishing_keywords = [
            'verify', 'account', 'update', 'confirm', 'login', 'signin',
            'banking', 'secure', 'suspended', 'locked', 'unusual-activity',
            'alert', 'notification', 'paypal', 'amazon', 'microsoft',
            'apple', 'google', 'facebook', 'netflix', 'ebay'
        ]
        
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'-{2,}',  # Multiple hyphens
            r'[0-9]+[a-z]+[0-9]+',  # Mixed numbers and letters (like paypa1)
            r'^\d+',  # Starts with number
        ]
        
        keyword_count = sum(1 for keyword in phishing_keywords if keyword in domain)
        pattern_matches = sum(1 for pattern in suspicious_patterns if re.search(pattern, domain))
        
        # Calculate suspicion score
        suspicion_score = keyword_count * 2 + pattern_matches * 3
        
        return {
            'is_suspicious': suspicion_score >= 3,
            'score': suspicion_score,
            'has_phishing_keywords': keyword_count > 0,
            'has_suspicious_patterns': pattern_matches > 0
        }
    except Exception as e:
        print(f"Reputation check failed: {e}")
        return {'is_suspicious': False, 'score': 0, 'has_phishing_keywords': False, 'has_suspicious_patterns': False}

def is_common_legitimate_domain(domain: str) -> bool:
    """Check if domain is a well-known legitimate site"""
    legitimate_domains = [
        # Global tech/social
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'netflix.com',
        'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com', 'medium.com',
        'paypal.com', 'ebay.com', 'cnn.com', 'bbc.com', 'yahoo.com', 'bing.com',
        # Pakistani universities and institutions
        'giki.edu.pk', 'nust.edu.pk', 'lums.edu.pk', 'fast.edu.pk', 'comsats.edu.pk',
        'pieas.edu.pk', 'itu.edu.pk', 'uet.edu.pk', 'pu.edu.pk', 'hec.gov.pk',
        # Other major universities
        'mit.edu', 'stanford.edu', 'harvard.edu', 'cambridge.ac.uk', 'oxford.ac.uk'
    ]
    
    # Remove www. and port for comparison
    clean_domain = domain.replace('www.', '').split(':')[0]
    
    # Check exact match
    if clean_domain in legitimate_domains:
        return True
    
    # Check if it's a subdomain of a legitimate domain
    for legit_domain in legitimate_domains:
        if clean_domain.endswith('.' + legit_domain):
            return True
    
    return False

def extract_features(url: str) -> dict:
    """Extracts the 30 features from the given URL and returns as dictionary."""
    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove port from domain if present
        if ':' in domain:
            domain = domain.split(':')[0]

        # Validate domain structure
        if not domain or domain == 'localhost':
            raise ValueError("Invalid domain")
        
        # Check URL reputation
        reputation = check_url_reputation(url)
        
        # Check if it's a known legitimate domain
        is_known_legitimate = is_common_legitimate_domain(domain)

        # 1. having_ip_address (-1 if IP, 1 otherwise)
        ip_feature = -1 if is_ip_address(domain) else 1

        # 2. url_length (-1 if > 75, 0 if 54-75, 1 if <= 53)
        length = len(url)
        if length > 75:
            url_length = -1
        elif length >= 54:
            url_length = 0
        else:
            url_length = 1

        # 3. shortening_service (-1 if URL shortener detected, 1 otherwise)
        shortening_services = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd', 'cli.gs',
            'ow.ly', 't.co', 'buff.ly', 'adf.ly', 'shorte.st'
        ]
        shortening_service = -1 if any(s in domain for s in shortening_services) else 1

        # 4. having_at_symbol (-1 if @ present, 1 otherwise)
        having_at_symbol = -1 if '@' in url else 1

        # 5. double_slash_redirecting (-1 if // found after position 7, 1 otherwise)
        double_slash_redirecting = -1 if url.rfind("//") > 7 else 1

        # 6. prefix_suffix (-1 if '-' in domain, 1 otherwise)
        prefix_suffix = -1 if '-' in domain else 1

        # 7. having_sub_domain (1 if 0-1 subdomains, 0 if 2 subdomains, -1 if 3+)
        subdomain_count = count_subdomains(domain)
        if subdomain_count <= 1:
            having_sub_domain = 1
        elif subdomain_count == 2:
            having_sub_domain = 0
        else:
            having_sub_domain = -1

        # 8. ssl_final_state (1 if HTTPS, -1 otherwise)
        ssl_state = 1 if parsed_url.scheme == 'https' else -1
        
        # 9. domain_registration_length
        # Check if domain has valid TLD - if not, mark as suspicious
        domain_registration_length = 1 if is_valid_domain(domain) else -1

        # 10. favicon (check if domain is legitimate-looking)
        favicon = 1 if is_valid_domain(domain) else -1

        # 11. port (-1 if non-standard port, 1 if standard or no port)
        port_num = parsed_url.port
        if port_num and port_num not in [80, 443]:
            port = -1
        else:
            port = 1

        # 12. https_token (-1 if 'https' in domain name, 1 otherwise)
        https_token = -1 if 'https' in domain.replace('https://', '') else 1

        # 13. request_url - suspicious if invalid domain
        request_url = 1 if is_valid_domain(domain) else -1

        # 14. url_of_anchor - suspicious if invalid domain
        url_of_anchor = 1 if is_valid_domain(domain) else -1

        # 15. links_in_tags - suspicious if invalid domain
        links_in_tags = 1 if is_valid_domain(domain) else -1

        # 16. sfh - suspicious if invalid domain
        sfh = 1 if is_valid_domain(domain) else -1

        # 17. submitting_to_email
        submitting_to_email = -1 if 'mailto:' in url.lower() else 1

        # 18. abnormal_url - check if domain is valid
        abnormal_url = 1 if is_valid_domain(domain) else -1

        # 19. redirect - assume suspicious for invalid domains
        redirect = 1 if is_valid_domain(domain) else 0

        # 20. on_mouseover
        on_mouseover = 1 if is_valid_domain(domain) else 0

        # 21. rightclick
        rightclick = 1 if is_valid_domain(domain) else 0

        # 22. popupwindow
        popupwindow = 1 if is_valid_domain(domain) else 0

        # 23. iframe
        iframe = 1 if is_valid_domain(domain) else -1

        # 24. age_of_domain - assume new/suspicious if invalid TLD
        age_of_domain = 1 if is_valid_domain(domain) else -1

        # 25. dnsrecord - check if DNS resolves
        dns_exists = has_valid_dns(domain)
        dnsrecord = 1 if dns_exists else -1

        # 26. web_traffic - assume low for invalid/unknown domains
        web_traffic = 0 if is_valid_domain(domain) else -1

        # 27. page_rank - assume low for invalid domains
        page_rank = -1 if not is_valid_domain(domain) else 0

        # 28. google_index - assume not indexed if invalid
        google_index = 1 if is_valid_domain(domain) else -1

        # 29. links_pointing_to_page
        links_pointing_to_page = 0 if is_valid_domain(domain) else -1

        # 30. statistical_report - flag invalid domains
        statistical_report = 1 if is_valid_domain(domain) else -1

        # Assemble the final feature vector (30 elements) as dictionary
        features = {
            'having_ip_address': ip_feature,
            'url_length': url_length,
            'shortining_service': shortening_service,
            'having_at_symbol': having_at_symbol,
            'double_slash_redirecting': double_slash_redirecting,
            'prefix_suffix': prefix_suffix,
            'having_sub_domain': having_sub_domain,
            'sslfinal_state': ssl_state,
            'domain_registration_length': domain_registration_length,
            'favicon': favicon,
            'port': port,
            'https_token': https_token,
            'request_url': request_url,
            'url_of_anchor': url_of_anchor,
            'links_in_tags': links_in_tags,
            'sfh': sfh,
            'submitting_to_email': submitting_to_email,
            'abnormal_url': abnormal_url,
            'redirect': redirect,
            'on_mouseover': on_mouseover,
            'rightclick': rightclick,
            'popupwindow': popupwindow,
            'iframe': iframe,
            'age_of_domain': age_of_domain,
            'dnsrecord': dnsrecord,
            'web_traffic': web_traffic,
            'page_rank': page_rank,
            'google_index': google_index,
            'links_pointing_to_page': links_pointing_to_page,
            'statistical_report': statistical_report
        }
        
        return features
        
    except Exception as e:
        print(f"Feature extraction failed: {e}")
        # Return suspicious values if extraction fails
        feature_names = [
            'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
            'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state',
            'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
            'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
            'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain',
            'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
            'statistical_report'
        ]
        return {name: -1 for name in feature_names}  # Default to suspicious


# --- 4. API Endpoints ---

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "message": "Phishing URL Scanner API is running",
        "model_loaded": model is not None
    }

@app.post("/api/scan", response_model=ScanResult)
async def scan_url(request: UrlRequest):
    """
    Receives a URL, extracts features, and returns a phishing prediction.
    """
    url_to_scan = request.link.strip()

    if not url_to_scan:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Basic URL validation
    if not re.match(r'^https?://', url_to_scan):
        # Try to add http:// if missing
        url_to_scan = 'http://' + url_to_scan

    # 1. Extract features
    try:
        feature_dict = extract_features(url_to_scan)
        # Convert dictionary to DataFrame to preserve feature names
        input_data = pd.DataFrame([feature_dict])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {str(e)}")

    # 2. Make Prediction
    if model is None:
        # Mock result if model failed to load
        result = 0  # Suspicious
        confidence = 0.50
    else:
        try:
            # Use the loaded model for prediction
            prediction = model.predict(input_data)[0]
            probabilities = model.predict_proba(input_data)[0]
            
            # Map prediction to confidence
            class_labels = model.classes_
            pred_index = np.where(class_labels == prediction)[0][0]
            confidence = probabilities[pred_index]
            result = int(prediction)
            
            # OVERRIDE: Unknown domains should be treated as suspicious by default
            # Model outputs: -1 (phishing), 0 (suspicious), 1 (legitimate)
            parsed_url = urlparse(url_to_scan)
            domain = parsed_url.netloc.lower().replace('www.', '')
            
            if result == 1:  # Model thinks it's legitimate (safe)
                if is_common_legitimate_domain(domain):
                    # Whitelist: Known legitimate domains stay safe
                    pass
                else:
                    # ALL unknown domains are at least suspicious
                    reputation = check_url_reputation(url_to_scan)
                    
                    # Check multiple risk factors
                    risk_factors = 0
                    
                    # Risk factor 1: Not a known legitimate domain
                    risk_factors += 1
                    
                    # Risk factor 2: Has suspicious patterns or keywords
                    if reputation['is_suspicious'] or reputation['score'] > 0:
                        risk_factors += 2
                    
                    # Risk factor 3: No HTTPS
                    if parsed_url.scheme != 'https':
                        risk_factors += 1
                    
                    # Risk factor 4: DNS issues
                    if not has_valid_dns(domain):
                        risk_factors += 3
                    
                    # Apply risk-based downgrade
                    if risk_factors >= 4:
                        result = -1  # Phishing/Dangerous
                        confidence = 0.85
                    elif risk_factors >= 1:
                        result = 0  # Suspicious (any unknown domain)
                        confidence = min(confidence, 0.65)  # Cap confidence low
                    
        except Exception as e:
            print(f"Prediction error: {e}")
            result = 0
            confidence = 0.50

    # 3. Format Response with confidence thresholds
    # Apply stricter thresholds - low confidence should be treated as suspicious
    if result == 1 and confidence >= 0.75:
        status_text = "safe"
        message = "✅ URL appears to be Legitimate"
        details = [
            "No major phishing indicators detected in URL structure",
            "Domain has valid TLD and DNS record" if feature_dict.get('dnsrecord') == 1 else "Domain structure appears normal",
            "Uses HTTPS encryption" if feature_dict.get('sslfinal_state') == 1 else "Uses HTTP (not encrypted)",
            f"Model confidence: {confidence*100:.1f}%",
            "⚠️ Note: This analysis is based on limited features. Always verify sender identity and be cautious with sensitive information."
        ]
    elif result == 1 and confidence < 0.75:
        # Low confidence "safe" should be treated as suspicious
        status_text = "suspicious"
        message = "⚠️ URL is Suspicious - Low Confidence Detection"
        details = [
            f"Model marked as safe but with only {confidence*100:.1f}% confidence",
            "Domain structure may contain subtle phishing indicators",
            "Verify the legitimacy before entering any personal information",
            "Check for typos in the domain name and unusual patterns",
            "When in doubt, navigate to the site directly rather than clicking links"
        ]
    elif result == 0:
        status_text = "suspicious"
        message = "⚠️ URL is Suspicious - Proceed with Caution"
        details = [
            "The model detected some suspicious characteristics",
            "Domain may be invalid or newly registered" if feature_dict.get('domain_registration_length') == -1 else "Some unusual URL patterns detected",
            f"Model confidence: {confidence*100:.1f}%",
            "Verify the legitimacy before entering any personal information",
            "Check for typos in the domain name",
            "When in doubt, navigate to the site directly rather than clicking links"
        ]
    else:  # result == -1
        status_text = "dangerous"
        message = "🚨 DANGER: URL Likely Phishing Attempt"
        details = [
            "Multiple strong indicators of a phishing attempt detected",
            "Invalid domain structure or missing DNS record" if feature_dict.get('dnsrecord') == -1 else "Highly suspicious URL pattern",
            f"Model confidence: {confidence*100:.1f}%",
            "DO NOT enter credentials, payment info, or personal data",
            "Close this page immediately",
            "Report this URL to your IT department or relevant authorities"
        ]

    return ScanResult(
        status=status_text,
        message=message,
        details=details,
        prediction_score=float(confidence)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)