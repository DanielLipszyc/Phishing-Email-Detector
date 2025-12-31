import requests
import re
import tldextract
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone


class URLAnalyzer:
    """Analyze URLs for phishing indicators and threat intelligence."""
    
    def __init__(self, virustotal_api_key=None):
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        
        # Known legitimate domains (allowlist)
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'dropbox.com', 'paypal.com', 'chase.com', 'bankofamerica.com'
        }
    
    def analyze_url(self, url):
        """Comprehensive URL analysis returning risk indicators."""
        
        results = {
            'url': url,
            'risk_score': 0,
            'risk_factors': [],
            'domain_info': {},
            'vt_results': None
        }
        
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Check for IP-based URL
            if self._is_ip_address(parsed.netloc.split(':')[0]):
                results['risk_score'] += 30
                results['risk_factors'].append("URL uses IP address instead of domain")
            
            # Check for suspicious TLD
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw']
            if extracted.suffix in suspicious_tlds:
                results['risk_score'] += 20
                results['risk_factors'].append(f"Suspicious TLD: .{extracted.suffix}")
            
            # Check for URL obfuscation techniques
            if '@' in url:
                results['risk_score'] += 25
                results['risk_factors'].append("URL contains @ symbol (possible obfuscation)")
            
            if url.count('//') > 1:
                results['risk_score'] += 15
                results['risk_factors'].append("URL contains multiple // (possible redirect)")
            
            if '%' in parsed.netloc:
                results['risk_score'] += 20
                results['risk_factors'].append("URL-encoded characters in domain")
            
            # Check for lookalike domains (typosquatting)
            typosquat_target = self._check_typosquatting(domain)
            if typosquat_target:
                results['risk_score'] += 35
                results['risk_factors'].append(f"Possible typosquatting of {typosquat_target}")
            
            # Check URL length (phishing URLs tend to be longer)
            if len(url) > 75:
                results['risk_score'] += 10
                results['risk_factors'].append("Unusually long URL")
            
            # Check subdomain count
            if extracted.subdomain:
                subdomain_count = extracted.subdomain.count('.') + 1
                if subdomain_count > 2:
                    results['risk_score'] += 15
                    results['risk_factors'].append(f"Multiple subdomains ({subdomain_count})")
            
            # WHOIS lookup for domain age
            domain_info = self._get_domain_info(domain)
            results['domain_info'] = domain_info
            
            if domain_info.get('age_days') is not None:
                if domain_info['age_days'] < 30:
                    results['risk_score'] += 25
                    results['risk_factors'].append(f"Very new domain ({domain_info['age_days']} days old)")
                elif domain_info['age_days'] < 90:
                    results['risk_score'] += 10
                    results['risk_factors'].append(f"New domain ({domain_info['age_days']} days old)")
            
            # VirusTotal check (if API key provided)
            if self.vt_api_key:
                vt_results = self._check_virustotal(url)
                results['vt_results'] = vt_results
                
                if vt_results and vt_results.get('malicious', 0) > 0:
                    results['risk_score'] += min(vt_results['malicious'] * 10, 40)
                    results['risk_factors'].append(
                        f"VirusTotal: {vt_results['malicious']} vendors flagged as malicious"
                    )
            
            # Check if domain is in trusted list
            if domain in self.trusted_domains:
                results['risk_score'] = max(0, results['risk_score'] - 30)
                results['risk_factors'].append("Domain is in trusted list")
            
        except Exception as e:
            results['error'] = str(e)
            results['risk_score'] += 10
            results['risk_factors'].append(f"Error analyzing URL: {str(e)}")
        
        # Normalize score to 0-100
        results['risk_score'] = min(100, results['risk_score'])
        results['risk_level'] = self._get_risk_level(results['risk_score'])
        
        return results
    
    def _is_ip_address(self, host):
        """Check if host is an IP address."""
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ipv4_pattern, host))
    
    def _check_typosquatting(self, domain):
        """Check if domain might be typosquatting a known brand."""
        
        # Brand patterns to check
        brands = {
            'paypal': ['paypa1', 'paypall', 'paypaI', 'paypal-', 'pay-pal', 'paypai'],
            'microsoft': ['microsofl', 'micros0ft', 'micosoft', 'microsft'],
            'google': ['googIe', 'g00gle', 'gooogle', 'goggle'],
            'amazon': ['amaz0n', 'arnazon', 'amazn', 'amazonn'],
            'apple': ['appIe', 'app1e', 'aplle'],
            'netflix': ['netfIix', 'netf1ix', 'neftlix'],
            'facebook': ['faceb00k', 'facebok', 'faceboook'],
            'chase': ['chasse', 'chas3', 'chase-'],
            'wellsfargo': ['wells-fargo', 'wellsfarg0', 'weilsfargo'],
        }
        
        domain_lower = domain.lower()
        
        for brand, typos in brands.items():
            # Check exact typos
            for typo in typos:
                if typo in domain_lower:
                    return brand
            
            # Check if brand appears with suspicious additions
            if brand in domain_lower and domain_lower != f"{brand}.com":
                if any(x in domain_lower for x in ['-secure', '-login', '-verify', '-update', '-account']):
                    return brand
        
        return None
    
    def _get_domain_info(self, domain):
        """Get WHOIS information for domain."""
        info = {'domain': domain}
        
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                
                if creation:
                    now = datetime.now()
                    if creation.tzinfo:
                        now = datetime.now(timezone.utc)
                    age = now - creation.replace(tzinfo=now.tzinfo if creation.tzinfo else None)
                    info['age_days'] = age.days
                    info['creation_date'] = str(creation)
            
            info['registrar'] = w.registrar
            
        except Exception as e:
            info['whois_error'] = str(e)
        
        return info
    
    def _check_virustotal(self, url):
        """Check URL against VirusTotal."""
        
        if not self.vt_api_key:
            return None
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(
                f"{self.vt_base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                return {'not_found': True}
                
        except Exception as e:
            return {'error': str(e)}
        
        return None
    
    def _get_risk_level(self, score):
        """Convert numeric score to risk level."""
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"