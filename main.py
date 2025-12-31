import argparse
import joblib
import os
from src.feature_extractor import FeatureExtractor
from src.url_analyzer import URLAnalyzer


class PhishingDetector:
    """Main phishing detection application."""
    
    def __init__(self, model_dir='models', vt_api_key=None):
        self.extractor = FeatureExtractor()
        self.url_analyzer = URLAnalyzer(virustotal_api_key=vt_api_key)
        
        # Load trained model
        self.model = joblib.load(f'{model_dir}/phishing_model.joblib')
        self.scaler = joblib.load(f'{model_dir}/scaler.joblib')
        self.feature_names = joblib.load(f'{model_dir}/feature_names.joblib')
        
        print("Phishing detector initialized")
    
    def analyze_email(self, email_text, subject="", verbose=True):
        """Analyze an email and return phishing assessment."""
        
        results = {
            'classification': None,
            'confidence': None,
            'risk_factors': [],
            'url_analysis': [],
            'feature_highlights': {}
        }
        
        # Extract features
        features = self.extractor.extract_all_features(email_text, subject)
        
        # Prepare feature vector
        feature_vector = [features[name] for name in self.feature_names]
        feature_vector_scaled = self.scaler.transform([feature_vector])
        
        # Get prediction
        prediction = self.model.predict(feature_vector_scaled)[0]
        probability = self.model.predict_proba(feature_vector_scaled)[0]
        
        phishing_prob = probability[1]
        
        results['classification'] = 'PHISHING' if prediction == 1 else 'LEGITIMATE'
        results['confidence'] = float(max(probability))
        results['phishing_probability'] = float(phishing_prob)
        
        # Identify risk factors from features
        if features['urgency_word_count'] > 2:
            results['risk_factors'].append(f"Contains {features['urgency_word_count']} urgency-related words")
        
        if features['credential_word_count'] > 1:
            results['risk_factors'].append(f"Contains {features['credential_word_count']} credential-related words")
        
        if features['has_ip_url']:
            results['risk_factors'].append("Contains URL with IP address")
        
        if features['suspicious_tld_count'] > 0:
            results['risk_factors'].append(f"{features['suspicious_tld_count']} URLs with suspicious TLDs")
        
        if features['urls_with_at_symbol'] > 0:
            results['risk_factors'].append("URL contains @ symbol (obfuscation technique)")
        
        if features['has_form']:
            results['risk_factors'].append("Email contains HTML form")
        
        if features['capital_ratio'] > 0.3:
            results['risk_factors'].append("Excessive use of capital letters")
        
        # Analyze extracted URLs
        urls = self._extract_urls(email_text)
        for url in urls[:5]:
            url_result = self.url_analyzer.analyze_url(url)
            results['url_analysis'].append(url_result)
            
            if url_result['risk_level'] in ['HIGH', 'MEDIUM']:
                for factor in url_result['risk_factors'][:2]:
                    results['risk_factors'].append(f"URL: {factor}")
        
        # Feature highlights
        results['feature_highlights'] = {
            'url_count': features['url_count'],
            'urgency_words': features['urgency_word_count'],
            'financial_words': features['financial_word_count'],
            'credential_words': features['credential_word_count']
        }
        
        if verbose:
            self._print_results(results)
        
        return results
    
    def _extract_urls(self, text):
        """Extract URLs from text."""
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def _print_results(self, results):
        """Print formatted results."""
        
        print("\n" + "="*60)
        print("PHISHING ANALYSIS RESULTS")
        print("="*60)
        
        if results['classification'] == 'PHISHING':
            print(f"\n⚠️  CLASSIFICATION: {results['classification']}")
            print(f"   Confidence: {results['confidence']*100:.1f}%")
            print(f"   Phishing Probability: {results['phishing_probability']*100:.1f}%")
        else:
            print(f"\n✓  CLASSIFICATION: {results['classification']}")
            print(f"   Confidence: {results['confidence']*100:.1f}%")
            print(f"   Phishing Probability: {results['phishing_probability']*100:.1f}%")
        
        if results['risk_factors']:
            print(f"\n📋 RISK FACTORS ({len(results['risk_factors'])}):")
            for factor in results['risk_factors']:
                print(f"   • {factor}")
        
        if results['url_analysis']:
            print(f"\n🔗 URL ANALYSIS ({len(results['url_analysis'])} URLs):")
            for url_result in results['url_analysis']:
                url_short = url_result['url'][:50] + "..." if len(url_result['url']) > 50 else url_result['url']
                print(f"   • {url_short}")
                print(f"     Risk: {url_result['risk_level']} ({url_result['risk_score']}/100)")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(description='Phishing Email Detector')
    parser.add_argument('--email', type=str, help='Path to email file or email text')
    parser.add_argument('--subject', type=str, default='', help='Email subject line')
    parser.add_argument('--vt-key', type=str, help='VirusTotal API key')
    parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = PhishingDetector(
        vt_api_key=args.vt_key or os.environ.get('VIRUSTOTAL_API_KEY')
    )
    
    if args.interactive:
        print("\nPhishing Detector - Interactive Mode")
        print("Enter 'quit' to exit\n")
        
        while True:
            print("\nPaste email content (end with empty line):")
            lines = []
            while True:
                line = input()
                if line == '':
                    break
                if line.lower() == 'quit':
                    return
                lines.append(line)
            
            email_text = '\n'.join(lines)
            if email_text:
                detector.analyze_email(email_text)
    
    elif args.email:
        if os.path.exists(args.email):
            with open(args.email, 'r', encoding='utf-8', errors='ignore') as f:
                email_text = f.read()
        else:
            email_text = args.email
        
        detector.analyze_email(email_text, args.subject)
    
    else:
        # Demo with sample phishing email
        sample_phishing = """
        From: security@paypa1-secure.com
        Subject: URGENT: Your Account Has Been Limited!
        
        Dear Valued Customer,
        
        We have noticed unusual activity on your PayPal account. Your account 
        has been temporarily limited until you verify your information.
        
        Please click the link below immediately to restore your account access:
        
        http://192.168.1.100/paypal-verify/login.php?id=28374&verify=true
        
        If you do not verify within 24 hours, your account will be permanently 
        suspended and all funds will be frozen.
        
        Click Here to Verify: http://paypa1-secure.tk/verify
        
        Thank You,
        PayPal Security Team
        """
        
        print("\n📧 Analyzing sample phishing email...")
        detector.analyze_email(sample_phishing, "URGENT: Your Account Has Been Limited!")


if __name__ == "__main__":
    main()