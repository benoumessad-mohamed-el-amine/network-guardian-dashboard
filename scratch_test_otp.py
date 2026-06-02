import os
import sys
import django
# Setup Django environment
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'back')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'demo.settings')
django.setup()

from rest_framework.test import APIRequestFactory
from django.contrib.auth.models import User
from myapp.views import api_user, api_forgot_password, api_reset_password, otp_store

def run_test():
    print("=== STARTING OTP FLOW TESTING ===")
    
    # 1. Get or create test user
    username = "test_otp_user"
    email = "test_otp_user@soficlef.local"
    password = "old_password_123"
    
    user, created = User.objects.get_or_create(username=username)
    user.set_password(password)
    user.email = email
    user.save()
    print(f"Test user: '{username}' with email: '{email}' initialized.")

    factory = APIRequestFactory()

    # 2. Trigger forgot-password (generate and send OTP)
    print("\n--- Requesting OTP ---")
    request = factory.post('/api/auth/forgot-password/', {'identity': username}, format='json')
    response = api_forgot_password(request)
    print(f"Status Code: {response.status_code}")
    print(f"Response Data: {response.data}")

    # Inspect in-memory otp_store
    record = otp_store.get(username)
    if not record:
        print("ERROR: OTP was not stored in otp_store!")
        return False
        
    otp_code = record['otp']
    print(f"Generated OTP from memory: {otp_code}")

    # 3. Trigger reset-password with correct OTP
    print("\n--- Resetting Password with Valid OTP ---")
    new_password = "new_password_456"
    request = factory.post('/api/auth/reset-password/', {
        'identity': username,
        'otp': otp_code,
        'new_password': new_password
    }, format='json')
    response = api_reset_password(request)
    print(f"Status Code: {response.status_code}")
    print(f"Response Data: {response.data}")

    # 4. Verify password change
    user.refresh_from_db()
    if user.check_password(new_password):
        print("\nSUCCESS: Password updated and verified successfully in the database!")
    else:
        print("\nERROR: Password check failed after reset!")
        return False
        
    # Clean up test user
    user.delete()
    print("Test user cleaned up.")
    print("=== TEST PASSED ===")
    return True

if __name__ == '__main__':
    run_test()
