from datetime import datetime
import requests
import json
import re
import os
from bs4 import BeautifulSoup


# ========================================
# CONFIGURATION
# ========================================
BASE_URL = "https://bookshop.multilit.com"
EMAIL = "islamraisul796@gmail.com"
PASSWORD = "rai@12345!Roy"
CARD_COUNTRY = "BD"


# ========================================
# PAYMENT METHOD ADDER CLASS
# ========================================
class PaymentMethodAdder:
    """Handles the complete flow of adding payment methods to WooCommerce for EPTES"""
    
    def __init__(self, base_url, email, password, cookies_file='cookies/cookies11.txt'):
        self.base_url = base_url.rstrip('/')
        self.email = email
        self.password = password
        self.session = requests.Session()
        self.logged_in_cookies = {}
        self.stripe_key = None
        self.cookies_file = cookies_file
    
    def save_cookies(self):
        """Save cookies to file for reuse"""
        os.makedirs('cookies', exist_ok=True)
        cookies_dict = self.session.cookies.get_dict()
        with open(self.cookies_file, 'w') as f:
            json.dump(cookies_dict, f, indent=2)
        print(f"✅ Cookies saved to {self.cookies_file}")
    
    def load_cookies(self):
        """Load cookies from file"""
        if os.path.exists(self.cookies_file):
            try:
                with open(self.cookies_file, 'r') as f:
                    cookies_dict = json.load(f)
                    for key, value in cookies_dict.items():
                        self.session.cookies.set(key, value)
                print(f"✅ Loaded cookies from {self.cookies_file}")
                return True
            except Exception as e:
                print(f"⚠️ Could not load cookies: {e}")
                return False
        return False
    
    def check_if_logged_in(self):
        """Check if already logged in using saved cookies"""
        if not self.load_cookies():
            return False
        
        try:
            headers = {
                        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                        'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
                        'dnt': '1',
                        'priority': 'u=0, i',
                        'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'document',
                        'sec-fetch-mode': 'navigate',
                        'sec-fetch-site': 'none',
                        'sec-fetch-user': '?1',
                        'upgrade-insecure-requests': '1',
                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                # Check if we're actually on the add-payment-method page (not redirected to login)
                if 'woocommerce-form-login' in response.text or 'woocommerce-login-nonce' in response.text:
                    print("⚠️ Cookies expired - page shows login form. Will login fresh.")
                    self.session.cookies.clear()
                    return False
                
                # Check if the page has Stripe payment elements
                if 'wc_stripe_upe_params' in response.text or 'pk_live_' in response.text or 'pk_test_' in response.text:
                    print("✅ Already logged in! Using saved cookies.")
                    return True
                
                # If we're here, we might be on the my-account page but not the add-payment-method page
                print("⚠️ Cookies may be invalid - no Stripe elements found. Will login fresh.")
                self.session.cookies.clear()
                return False
            
            print("⚠️ Cookies expired or invalid. Will login fresh.")
            self.session.cookies.clear()
            return False
                
        except Exception as e:
            print(f"⚠️ Error checking login status: {e}")
            self.session.cookies.clear()
            return False
    
    def get_initial_cookies_and_login_nonce(self):
        """Visit the login page to get initial cookies and extract login nonce"""
        print("🔄 Getting initial cookies and login nonce...")
        
        try:
            headers = {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
                    'cache-control': 'max-age=0',
                    'dnt': '1',
                    'priority': 'u=0, i',
                    'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'none',
                    'sec-fetch-user': '?1',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/', headers=headers)
            
            if response.status_code == 200:
                print(f"✅ Page loaded successfully, cookies saved automatically")
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                nonce_input = soup.find('input', {'id': 'woocommerce-login-nonce'})
                if nonce_input and hasattr(nonce_input, 'get'):
                    login_nonce = nonce_input.get('value')
                    if login_nonce:
                        print(f"✅ Login nonce extracted: {login_nonce}")
                        return login_nonce
                
                nonce_input = soup.find('input', {'name': 'woocommerce-login-nonce'})
                if nonce_input and hasattr(nonce_input, 'get'):
                    login_nonce = nonce_input.get('value')
                    if login_nonce:
                        print(f"✅ Login nonce extracted: {login_nonce}")
                        return login_nonce
                
                nonce_patterns = [
                    r'id="woocommerce-login-nonce"[^>]+value="([^"]+)"',
                    r'name="woocommerce-login-nonce"\s+value="([^"]+)"',
                    r'"woocommerce-login-nonce"\s*:\s*"([^"]+)"',
                    r'woocommerce-login-nonce.*?value="([^"]+)"'
                ]
                
                for pattern in nonce_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        login_nonce = match.group(1)
                        print(f"✅ Login nonce extracted via regex: {login_nonce}")
                        return login_nonce
                
                print("❌ Could not extract login nonce from page")
                print("🔍 Searching for 'nonce' in page content...")
                nonce_debug = re.findall(r'nonce["\']?\s*[=:]\s*["\']([a-zA-Z0-9]+)["\']', response.text, re.IGNORECASE)
                if nonce_debug:
                    print(f"   Found possible nonces: {nonce_debug[:5]}")
                return None
            else:
                print(f"❌ Failed to load login page: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting initial cookies: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def login(self, nonce):
        """Login to the account"""
        print(f"🔄 Logging in as {self.email}...")
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': self.base_url,
            'referer': f'{self.base_url}/my-account/',
            'priority': 'u=0, i',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        
        data = {
                'username': self.email,
                'password': self.password,
                'woocommerce-login-nonce': nonce,
                '_wp_http_referer': '/my-account/',
                'login': 'Log in',
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/my-account/',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                self.logged_in_cookies = self.session.cookies.get_dict()
                self.save_cookies()
                print(f"✅ Login successful and cookies saved!")
                return True
            else:
                print(f"❌ Login failed with status code: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error during login: {e}")
            return False
    
    def extract_stripe_key_and_ajax_nonce(self):
        """Extract Stripe key and AJAX nonce from payment pages"""
        ajax_nonce = None
        
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
                'cache-control': 'max-age=0',
                'dnt': '1',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/my-account/',
                'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                stripe_patterns = [
                    r'"key"\s*:\s*"(pk_live_[a-zA-Z0-9]+)"',
                    r'"key"\s*:\s*"(pk_test_[a-zA-Z0-9]+)"',
                ]
                
                for pattern in stripe_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        self.stripe_key = match.group(1)
                        print(f"✅ Stripe key extracted: {self.stripe_key[:20]}...")
                        break
                
                ajax_patterns = [
                    r'"createAndConfirmSetupIntentNonce"\s*:\s*"([^"]+)"',
                ]
                
                for pattern in ajax_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        ajax_nonce = match.group(1)
                        print(f"✅ AJAX nonce extracted: {ajax_nonce}")
                        break
                
                if not self.stripe_key:
                    print("❌ Could not find Stripe key in page")
                    
                if not ajax_nonce:
                    print("❌ Could not find AJAX nonce in page")
                
                return self.stripe_key, ajax_nonce
            else:
                print(f"❌ Failed to load payment method page: {response.status_code}")
                return None, None
                
        except Exception as e:
            print(f"❌ Error extracting data: {e}")
            return None, None
    
    def create_stripe_payment_method(self, card_data):
        """Create a payment method using Stripe API"""
        print("🔄 Creating Stripe payment method...")
        
        if not self.stripe_key:
            print("❌ No Stripe key available")
            return None
        
        headers = {
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        
        card_number = card_data.get('number', '').replace(' ', '+')
        
        data = f"type=card&card[number]={card_number}&card[cvc]={card_data.get('cvc', '')}&card[exp_year]={card_data.get('exp_year', '')}&card[exp_month]={card_data.get('exp_month', '')}&allow_redisplay=unspecified&billing_details[address][country]={card_data.get('country', 'BD')}&pasted_fields=number&payment_user_agent=stripe.js%2F851131afa1%3B+stripe-js-v3%2F851131afa1%3B+payment-element%3B+deferred-intent&referrer={self.base_url}&time_on_page=23545&key={self.stripe_key}&_stripe_version=2024-06-20"
        
        try:
            response = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                payment_method = response.json()
                payment_method_id = payment_method.get('id')
                print(f"✅ Stripe payment method created: {payment_method_id}")
                return payment_method_id
            else:
                print(f"❌ Failed to create Stripe payment method: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error creating Stripe payment method: {e}")
            return None
    
    def add_payment_method_to_account(self, payment_method_id, ajax_nonce):
        """Add the payment method to WooCommerce account"""
        print(f"🔄 Adding payment method to account...")
        
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'dnt': '1',
            'origin': self.base_url,
            'priority': 'u=1, i',
            'referer': f'{self.base_url}/my-account/add-payment-method/',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        
        data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce,
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/wp-admin/admin-ajax.php',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    setup_intent_id = result.get('data', {}).get('id')
                    print(f"✅ Payment method added successfully!")
                    print(f"   Status: {result.get('data', {}).get('status')}")
                    print(f"   Setup Intent ID: {setup_intent_id}")
                    return True, setup_intent_id
                else:
                    print(f"❌ Failed to add payment method: {result}")
                    return False, None
            else:
                print(f"❌ Error adding payment method: Status {response.status_code}")
                return False, None
                
        except Exception as e:
            print(f"❌ Error adding payment method: {e}")
            return False, None
    
    def run(self, card_data):
        """Main execution flow"""
        print("=" * 60)
        print("🚀 Starting Payment Method Addition Process")
        print("=" * 60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Target: {self.base_url}")
        print(f"Email: {self.email}")
        print(f"Card: {card_data.get('number', 'N/A')}")
        print("=" * 60)
        
        if not self.check_if_logged_in():
            login_nonce = self.get_initial_cookies_and_login_nonce()
            if not login_nonce:
                print("\n💥 Failed to get login nonce!")
                return None, None, False
            
            if not self.login(login_nonce):
                print("\n💥 Failed to login!")
                return None, None, False
        
        stripe_key, ajax_nonce = self.extract_stripe_key_and_ajax_nonce()
        
        if not self.stripe_key:
            print("\n💥 Failed to extract Stripe key!")
            return None, None, False
        
        if not ajax_nonce:
            print("\n💥 Failed to extract AJAX nonce!")
            return None, None, False
        
        payment_method_id = self.create_stripe_payment_method(card_data)
        if not payment_method_id:
            print("\n💥 Failed to create payment method!")
            return None, None, False
        
        success, setup_intent_id = self.add_payment_method_to_account(payment_method_id, ajax_nonce)
        
        if not success:
            print("\n💥 Failed to add payment method to account!")
            return payment_method_id, None, False
        
        print("\n" + "=" * 60)
        print("🎉 Payment Method Addition Completed Successfully!")
        print("=" * 60)
        return payment_method_id, setup_intent_id, True


# ========================================
# HELPER FUNCTIONS
# ========================================

def advanced_luhn_checksum(card_number):
    """Luhn algorithm for card number validation"""
    def digits_of(n):
        return [int(d) for d in str(n)]

    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10


def is_valid_card(card_number):
    """Check if card number passes Luhn validation"""
    card_number = str(card_number).replace(' ', '').replace('-', '')
    if not card_number.isdigit():
        return False
    return advanced_luhn_checksum(card_number) == 0


def get_bin_info(card_number):
    """Get BIN information for a card"""
    bin_number = str(card_number)[:6]
    
    try:
        print(f"🔍 Fetching BIN info for: {bin_number}")
        response = requests.get(f'https://bin-db.vercel.app/api/bin?bin={bin_number}', timeout=5)
        
        if response.status_code == 200:
            bin_data = response.json()
            if bin_data.get('status') == 'SUCCESS' and bin_data.get('data'):
                print(f"✅ BIN info found: {bin_data['data'][0].get('brand', 'N/A')}")
                return bin_data['data'][0]
        
        print("❌ BIN info not found")
        return None
    except Exception as e:
        print(f"⚠️ Could not fetch BIN info: {e}")
        return None


def parse_card_details(auth_string):
    """Parse card details from auth string format: CARD|MM|YYYY|CVC"""
    try:
        parts = auth_string.split('|')
        if len(parts) != 4:
            return None
        
        card_number = parts[0].strip().replace(' ', '')
        exp_month = parts[1].strip().zfill(2)
        exp_year = parts[2].strip()
        cvc = parts[3].strip()
        
        if len(exp_year) == 2:
            exp_year = exp_year
        elif len(exp_year) == 4:
            exp_year = exp_year[-2:]
        else:
            return None
        
        return {
            'number': card_number,
            'exp_month': exp_month,
            'exp_year': exp_year,
            'cvc': cvc,
            'country': CARD_COUNTRY
        }
    except Exception as e:
        print(f"❌ Error parsing card details: {e}")
        return None


# ========================================
# ENDPOINT HANDLER
# ========================================
def handle_endpoint(auth, hcaptcha_token=''):
    """
    Main endpoint handler for EPTES payment validation
    Returns: (response_dict, status_code)
    """
    if not auth:
        return {
            'success': False,
            'error': 'Missing auth parameter',
            'message': 'Please provide card details in format: CARD_NUMBER|EXP_MONTH|EXP_YEAR|CVC'
        }, 400
    
    card_data = parse_card_details(auth)
    
    if not card_data:
        return {
            'success': False,
            'error': 'Invalid card details format',
            'message': 'Format: CARD_NUMBER|EXP_MONTH|EXP_YEAR|CVC (year can be 2 or 4 digits)',
            'example': '5444228403258437|11|2028|327'
        }, 400
    
    try:
        print(f"🔐 Validating card: {card_data['number'][:6]}******{card_data['number'][-4:]}")
        
        bin_info = get_bin_info(card_data['number'])
        
        if not is_valid_card(card_data['number']):
            error_result = {}
            
            if bin_info:
                error_result['bin_info'] = {
                    'bank': bin_info.get('issuer', 'N/A'),
                    'brand': bin_info.get('brand', 'N/A'),
                    'country': bin_info.get('Country', {}).get('Name', 'N/A') if isinstance(bin_info.get('Country'), dict) else 'N/A',
                    'level': bin_info.get('level', 'N/A'),
                    'type': bin_info.get('type', 'N/A')
                }
            
            error_result['card'] = f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year'] if len(card_data['exp_year']) == 4 else '20' + card_data['exp_year']}|{card_data['cvc']}"
            error_result['message'] = 'Invalid card number (Failed Luhn validation)'
            error_result['status'] = 'error'
            
            return error_result, 400
        
        print("✅ Card passed Luhn validation")
        
        email = os.getenv('EPTES_EMAIL', EMAIL)
        password = os.getenv('EPTES_PASSWORD', PASSWORD)
        
        adder = PaymentMethodAdder(
            base_url=BASE_URL,
            email=email,
            password=password,
            cookies_file='cookies/cookies11.txt'
        )
        
        payment_method_id, setup_intent_id, success = adder.run(card_data=card_data)
        
        result = {}
        
        if bin_info:
            result['bin_info'] = {
                'bank': bin_info.get('issuer', 'N/A'),
                'brand': bin_info.get('brand', 'N/A'),
                'country': bin_info.get('Country', {}).get('Name', 'N/A') if isinstance(bin_info.get('Country'), dict) else 'N/A',
                'level': bin_info.get('level', 'N/A'),
                'type': bin_info.get('type', 'N/A')
            }
        
        result['card'] = f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year'] if len(card_data['exp_year']) == 4 else '20' + card_data['exp_year']}|{card_data['cvc']}"
        result['gateway'] = 'Stripe'
        result['message'] = 'Payment method added successfully' if success else 'Payment declined'
        result['payment_method_id'] = payment_method_id
        result['setup_intent_id'] = setup_intent_id
        result['status'] = 'success' if success else 'declined'
        
        return result, 200
            
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'An error occurred while processing the request',
            'type': type(e).__name__
        }, 500
