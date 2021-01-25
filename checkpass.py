# Start that project

import requests
import hashlib
import sys


# Request data from API
# This API accepts as input first five chars of SHA1 hashed string "query_char"
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the API and try again")
    return res

# Arranges data recived from API and compares it with user input
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0    

# Prepares user input for API request and API responce        
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

# Loops through command arguments 
def main(args):
    if len(sys.argv) == 1:
        print("Please give some input.")
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was leaked {count} times. You should use another password.")
        else:
            print(f"{password} was NOT found. Carry on.")
    return 'Done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))