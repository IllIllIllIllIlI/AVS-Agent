import requests
from bs4 import BeautifulSoup

"""
This is a logger. It logs in the targeted page, checks for the response status and returns the cookie's id.
"""
def at_login_required(target, redirect_page):    
    session = requests.Session()
    
    r1 = session.get(target)
    soup = BeautifulSoup(r1.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        print(f'No login form found at {target}, skipping this step...')
        return None
        
    token = token_input['value']
    
    r2 = session.post(target, data={   # default credentials make list if need be.
        'username': 'admin', 
        'password':'password',
        'user_token': token,
        'Login': 'Login'
        }) 
    
    base_url = target.rsplit('/', 1)[0]
    test_url = f"{base_url}/{redirect_page}"
    r3 = session.get(test_url)

    # print("returned status code = ", r3)
    # print("=== URL finale r3 ===", r3.url)
    # print("=== r3 text extrait ===", r3.text[500:1000])
    if 'Logout' in r3.text:
        return session.cookies['PHPSESSID']
    else:    
        print('login failed, status code: ', r3)
        return None