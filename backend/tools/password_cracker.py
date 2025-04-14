"""
Password Cracker Module
Provides functions to crack password hashes using dictionary attacks
"""

import hashlib
import logging
import time
import os
from Crypto.Hash import MD5, SHA1, SHA256

logger = logging.getLogger(__name__)

# Default wordlists
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common_passwords.txt")

# Ensure the wordlists directory exists
os.makedirs(os.path.join(os.path.dirname(__file__), "wordlists"), exist_ok=True)

# Create a default wordlist if it doesn't exist
if not os.path.exists(DEFAULT_WORDLIST):
    with open(DEFAULT_WORDLIST, "w") as f:
        f.write("\n".join(["password", "123456", "qwerty", "admin", "welcome", 
                           "password123", "abc123", "letmein", "monkey", "1234567890"]))

def hash_password(password, hash_type):
    """
    Hash a password with the specified algorithm
    
    Args:
        password (str): Password to hash
        hash_type (str): Hash algorithm (md5, sha1, sha256, etc.)
    
    Returns:
        str: Hashed password
    """
    encoded = password.encode('utf-8')
    
    if hash_type.lower() == 'md5':
        return MD5.new(encoded).hexdigest()
    elif hash_type.lower() == 'sha1':
        return SHA1.new(encoded).hexdigest()
    elif hash_type.lower() == 'sha256':
        return SHA256.new(encoded).hexdigest()
    elif hash_type.lower() == 'sha512':
        return hashlib.sha512(encoded).hexdigest()
    else:
        # Default to sha256
        return hashlib.sha256(encoded).hexdigest()

def crack_password(hash_value, hash_type='sha256', wordlist_path=None):
    """
    Attempt to crack a password hash using a dictionary attack
    
    Args:
        hash_value (str): The hash to crack
        hash_type (str): Hash algorithm (md5, sha1, sha256, etc.)
        wordlist_path (str): Path to wordlist file (one password per line)
    
    Returns:
        dict: Results of the cracking attempt
    """
    try:
        # Use default wordlist if none specified
        if not wordlist_path:
            wordlist_path = DEFAULT_WORDLIST
        
        logger.info(f"Starting password cracking for {hash_type} hash using wordlist: {wordlist_path}")
        
        start_time = time.time()
        result = {
            'hash': hash_value,
            'hash_type': hash_type,
            'found': False,
            'password': None,
            'attempts': 0,
            'duration': 0,
            'wordlist': wordlist_path
        }
        
        # Normalize hash value (lowercase)
        hash_value = hash_value.lower()
        
        # Open wordlist and try each password
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
            for password in wordlist:
                password = password.strip()
                if not password:
                    continue
                
                # Hash the current password
                current_hash = hash_password(password, hash_type)
                result['attempts'] += 1
                
                # Compare with target hash
                if current_hash.lower() == hash_value:
                    result['found'] = True
                    result['password'] = password
                    break
                
                # Check for timeout (optional)
                if result['attempts'] % 1000 == 0 and time.time() - start_time > 60:
                    logger.warning("Password cracking timed out after 60 seconds")
                    break
        
        # Calculate duration
        result['duration'] = round(time.time() - start_time, 2)
        
        return result
        
    except Exception as e:
        logger.error(f"Error during password cracking: {str(e)}")
        raise Exception(f"Password cracking failed: {str(e)}")

if __name__ == "__main__":
    # Test the password cracker
    test_password = "password123"
    test_hash = hash_password(test_password, "sha256")
    print(f"Test hash (SHA256) for '{test_password}': {test_hash}")
    
    result = crack_password(test_hash, "sha256")
    print(f"Cracking result: {result}") 