# Start that project

import requests



def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the API and try again")
    return res
def pwned_api_check(password):
    # Check password if it exist in API response
    pass

request_api_data('123')
