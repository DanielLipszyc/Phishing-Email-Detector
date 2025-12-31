import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
import numpy as np

STOPWORDS = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
             'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
             'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
             'ought', 'used', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by',
             'from', 'as', 'into', 'through', 'during', 'before', 'after',
             'above', 'below', 'between', 'under', 'again', 'further', 'then',
             'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all',
             'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor',
             'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'just',
             'and', 'but', 'if', 'or', 'because', 'until', 'while', 'this', 'that',
             'these', 'those', 'i', 'me', 'my', 'myself', 'we', 'our', 'ours',
             'you', 'your', 'yours', 'he', 'him', 'his', 'she', 'her', 'hers',
             'it', 'its', 'they', 'them', 'their', 'what', 'which', 'who', 'whom'}


class FeatureExtractor:
    """Extract features from email content for phishing detection."""
    
    URGENCY_WORDS = [
        'urgent', 'immediate', 'action required', 'suspended', 'verify',
        'confirm', 'update', 'expire', 'locked', 'unauthorized', 'alert',
        'warning', 'important', 'attention', 'act now', 'limited time'
    ]
    
    FINANCIAL_WORDS = [
        'bank', 'account', 'credit', 'debit', 'paypal', 'payment',
        'transaction', 'wire', 'transfer', 'ssn', 'social security',
        'tax', 'refund', 'prize', 'winner', 'lottery', 'inheritance'
    ]
    
    CREDENTIAL_WORDS = [
        'password', 'login', 'username', 'credential', 'sign in',
        'log in', 'click here', 'verify your', 'confirm your'
    ]
    
    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'cc',
        'su', 'buzz', 'link', 'click', 'download'
    ]

    def __init__(self):
        self.stopwords = STOPWORDS
    
    def extract_all_features(self, email_text, subject=""):
        """Extract all features from an email and return as dict."""

        text = self._strip_html(email_text)
        text_lower = text.lower()
        

        urls = self._extract_urls(email_text)
        
        features = {}
        

        features['length'] = len(text)
        features['word_count'] = len(text.split())
        

        features['urgency_word_count'] = self._count_keywords(text_lower, self.URGENCY_WORDS)
        features['financial_word_count'] = self._count_keywords(text_lower, self.FINANCIAL_WORDS)
        features['credential_word_count'] = self._count_keywords(text_lower, self.CREDENTIAL_WORDS)
        
        #Structural features
        features['url_count'] = len(urls)
        features['unique_domain_count'] = len(set(urlparse(u).netloc for u in urls))
        features['has_ip_url'] = int(any(self._url_has_ip(u) for u in urls))
        features['suspicious_tld_count'] = self._count_suspicious_tlds(urls)
        features['avg_url_length'] = np.mean([len(u) for u in urls]) if urls else 0
        features['max_url_length'] = max([len(u) for u in urls]) if urls else 0
        

        features['urls_with_at_symbol'] = sum(1 for u in urls if '@' in u)
        features['urls_with_hex'] = sum(1 for u in urls if '%' in u)
        features['urls_with_double_slash'] = sum(1 for u in urls if '//' in u[8:])
        
        #Formatting features
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['capital_ratio'] = self._capital_ratio(text)
        features['special_char_ratio'] = self._special_char_ratio(text)
        
        # HTML indicators 
        features['has_html'] = int('<html' in email_text.lower() or '<body' in email_text.lower())
        features['has_form'] = int('<form' in email_text.lower())
        features['has_script'] = int('<script' in email_text.lower())
        features['hidden_element_count'] = email_text.lower().count('display:none') + email_text.lower().count('visibility:hidden')
        
        # Subject line features 
        if subject:
            subject_lower = subject.lower()
            features['subject_urgency'] = self._count_keywords(subject_lower, self.URGENCY_WORDS)
            features['subject_has_re_fwd'] = int(subject_lower.startswith('re:') or subject_lower.startswith('fwd:'))
            features['subject_all_caps'] = int(subject.isupper() and len(subject) > 3)
        else:
            features['subject_urgency'] = 0
            features['subject_has_re_fwd'] = 0
            features['subject_all_caps'] = 0
        
        # Linguistic features
        features['avg_word_length'] = self._avg_word_length(text)
        features['stopword_ratio'] = self._stopword_ratio(text)
        
        # Grammar/spelling indicators
        features['double_space_count'] = text.count('  ')
        features['missing_space_after_period'] = len(re.findall(r'\.[A-Za-z]', text))
        
        return features
    
    def _strip_html(self, text):
        """Remove HTML tags from text."""
        soup = BeautifulSoup(text, 'html.parser')
        return soup.get_text(separator=' ')
    
    def _extract_urls(self, text):
        """Extract all URLs from text."""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def _count_keywords(self, text, keywords):
        """Count occurrences of keywords in text."""
        count = 0
        for keyword in keywords:
            count += text.count(keyword)
        return count
    
    def _url_has_ip(self, url):
        """Check if URL uses IP address instead of domain."""
        try:
            netloc = urlparse(url).netloc
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            return bool(re.match(ip_pattern, netloc.split(':')[0]))
        except:
            return False
    
    def _count_suspicious_tlds(self, urls):
        """Count URLs with suspicious TLDs."""
        count = 0
        for url in urls:
            extracted = tldextract.extract(url)
            if extracted.suffix.lower() in self.SUSPICIOUS_TLDS:
                count += 1
        return count
    
    def _capital_ratio(self, text):
        """Calculate ratio of capital letters."""
        if not text:
            return 0
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0
        capitals = [c for c in letters if c.isupper()]
        return len(capitals) / len(letters)
    
    def _special_char_ratio(self, text):
        """Calculate ratio of special characters."""
        if not text:
            return 0
        special = [c for c in text if not c.isalnum() and not c.isspace()]
        return len(special) / len(text)
    
    def _avg_word_length(self, text):
        """Calculate average word length."""
        words = [w for w in text.split() if w.isalpha()]
        if not words:
            return 0
        return np.mean([len(w) for w in words])
    
    def _stopword_ratio(self, text):
        """Calculate ratio of stopwords."""
        words = [w.lower() for w in text.split() if w.isalpha()]
        if not words:
            return 0
        stopword_count = sum(1 for w in words if w in self.stopwords)
        return stopword_count / len(words)
    
    def get_feature_names(self):
        """Return list of feature names in order."""
        return [
            'length', 'word_count', 'urgency_word_count', 'financial_word_count',
            'credential_word_count', 'url_count', 'unique_domain_count', 
            'has_ip_url', 'suspicious_tld_count', 'avg_url_length', 'max_url_length',
            'urls_with_at_symbol', 'urls_with_hex', 'urls_with_double_slash',
            'exclamation_count', 'question_count', 'capital_ratio', 'special_char_ratio',
            'has_html', 'has_form', 'has_script', 'hidden_element_count',
            'subject_urgency', 'subject_has_re_fwd', 'subject_all_caps',
            'avg_word_length', 'stopword_ratio', 'double_space_count',
            'missing_space_after_period'
        ]