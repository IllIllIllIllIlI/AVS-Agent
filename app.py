from model.model_config import cyber_exp_model
from utils.nmap_scanner import nmap_scan
from utils.zap_scanner import zap_scan
from utils.auth import at_login_required
import zapv2

zap = zapv2.ZAPv2(proxies={'http': 'http://172.17.0.1:8080', 'https': 'http://172.17.0.1:8080'})

SCAN_OPTIONS = ['spider', 
               'ajaxSpider', 
               'ascan', 
               'pscan']

WEB_PORTS = ['80', 
             '443',
             '8443']

def autonomous_vunerability_scanner_agent(target, zap_target):
    nmap_input = nmap_scan(target)
    
    prompt = f"""Based on this Nmap scan result: {nmap_input} 
    Available ZAP scans: 
    - spider (traditional web crawl) 
    - ajaxSpider (The Ajax Spider allows you to crawl web applications written in Ajax in far more depth than the traditional Spider)
    - ascan (active vulnerability scan) 
    - pscan (passive scan) 
    Which ZAP scan(s) should be performed? Respond ONLY with the scan name(s), comma-separated.
    """
    
    agent_answer = cyber_exp_model(prompt)
    print(agent_answer)
    
    scans = agent_answer.split(',')
    
    scan_type = []
    for scan in scans:
        scan = scan.strip()
        
        if scan in SCAN_OPTIONS :
            scan_type.append(scan)
            
        else:
            cyber_exp_model("Do you confirm there are no scans to perform? If this not the case please regenerate an answer respecting the zap scan nomenclature thank you.")
    
    web_ports_found = []
    for p in nmap_input:
        port = str(p['port_number'])
        
        if port in WEB_PORTS:
            web_ports_found.append(port)
    
    # page_input = input("Please type the login page's name needed with your test (ie: login.php): ")
    
    # redirect_input = input("Please enter the page to be redirected after login (ie: index.php): ")
    
    all_alerts = []
    for port_num in web_ports_found:
        if port_num == '80':
            #login_url = f"http://{target}/{page_input}"
            login_url = f"http://{target}/login.php"
        else:    
            #login_url = f"http://{target}:{port_num}/{page_input}"
            login_url = f"http://{target}:{port_num}/login.php"
        # print("==================== LOGIN URL =====================")
        # print(login_url)
        # print("==================== EoL 1 =========================")
        
        cookie_val = at_login_required(login_url, redirect_page="index.php")
        # print("============== cookie_val ==========================")
        # print(cookie_val)
        # print("============== EoL 2 ===============================")
        if cookie_val:
            # all_cookies = f"PHPSESSID={cookie_val}; security=low"
            # # print("============== all_cookies =====================")
            # # print(all_cookies)
            # # print("============== EoL 3 ===========================")
            
            # try:
            #     zap.replacer.remove_rule(description=f'Auth port {port_num}')
            # except:
            #     pass
            
            # # This sets up the context in which the zap api will authenticate itself and scan the target.
            # context_id = zap.context.new_context(contextname="myContext")
            # zap.context.include_in_context(contextname="myContext", regex="http://127.0.0.1/.*")
            
            # # The authentication method the api will use and how it knows it is authenticated.
            # zap.authentication.set_authentication_method(contextid=context_id, authmethodname="formBasedAuthentication", authmethodconfigparams=f"loginUrl=http://{target}/login.php&loginRequestData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D%26user_token%3D%7B%25user_token%25%7D%26Login%3DLogin")
            # zap.authentication.set_logged_in_indicator(contextid=context_id, loggedinindicatorregex="Logout")
            
            # # This is the user setup the api will use to navigate, with its creation, credentials setup and enableing.
            # user_id = zap.users.new_user(contextid=context_id, name="myUser")
            # zap.users.set_authentication_credentials(contextid=context_id, userid=user_id, authcredentialsconfigparams="username=admin&password=password")
            # zap.users.set_user_enabled(contextid=context_id, userid=user_id, enabled=True)
            
            # zap.replacer.add_rule(
            #     description=f'Auth port {port_num}',
            #     enabled=True,
            #     matchtype="REQ_HEADER",
            #     matchstring="Cookie",
            #     matchregex=False,
            #     replacement=f"{all_cookies}"
            # )
            
            zap.httpsessions.create_empty_session(site=f"http://{zap_target}", session="mysession")
            zap.httpsessions.set_session_token_value(site=f"http://{zap_target}", session="mysession", sessiontoken="PHPSESSID", tokenvalue=cookie_val)
            zap.httpsessions.set_active_session(site=f"http://{zap_target}", session="mysession")
            
            # context_id = zap.context.new_context(contextname="myContext")
            # zap.context.include_in_context(contextname="myContext", regex=f"http://{target}/.*")
            
            print("=== SESSIONS ===")
            print(zap.httpsessions.sessions(site=f"http://{zap_target}"))
            print("=== ACTIVE SESSION ===")
            print(zap.httpsessions.active_session(site=f"http://{zap_target}"))
            print("=== EoL SESSIONS ===")
            
        for t in scan_type: 
            target_url = f"http://{zap_target}/"
            print(f'Targetting -> {target_url} at port {port_num}')
            
            alerts = zap_scan(target_url, t)
            
            all_alerts.append(alerts)
            print("============== all_alerts[0] ====================")
            print(all_alerts[0]) 
            print("============== EoL 4 ============================")
    return all_alerts
    
if __name__ == "__main__":
    target = "127.0.0.1" #input("Please enter the targeted addresses: \n")
    zap_target = "172.17.0.1"
    autonomous_vunerability_scanner_agent(target, zap_target)