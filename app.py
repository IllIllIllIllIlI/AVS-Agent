import model.model_config
from utils.nmap_scanner import nmap_scan
from utils.zap_scanner import zap_scan
from utils.auth import at_login_required
from utils.report import report_parser, vulnerability_ranker
import zapv2
import gc


"""
Main pipeline and agent orchestration.

Takes a target IP, performs an Nmap port scan,
feeds the results to the LLM agent which decides which ZAP scans to run,
then executes those scans and returns the discovered vulnerabilities.
"""

zap = zapv2.ZAPv2(proxies={'http': 'http://172.17.0.1:8080', 'https': 'http://172.17.0.1:8080'})

# List of basic scans from ZAP api.
SCAN_OPTIONS = ['spider', 
               'ajaxSpider', 
               'ascan', 
               'pscan']

# Ports to be scanned (8080 is removed because it belongs to ZAP).
WEB_PORTS = ['80', 
             '443',
             '8443']

def autonomous_vunerability_scanner_agent(target, zap_target):
    
    # Nmap scan.
    nmap_input = nmap_scan(target)
    
    # Cyber agent's prompt.
    prompt = f"""Based on this Nmap scan result: {nmap_input} 
    Available ZAP scans: 
    - spider (traditional web crawl) 
    - ajaxSpider (The Ajax Spider allows you to crawl web applications written in Ajax in far more depth than the traditional Spider)
    - ascan (active vulnerability scan) 
    - pscan (passive scan) 
    Which ZAP scan(s) should be performed? Respond ONLY with the scan name(s), comma-separated.
    """
    
    # Injection of the prompt in the agent.
    agent_answer = model.model_config.cyber_exp_model(prompt)
    print(agent_answer)
    
    scans = agent_answer.split(',')
    
    scan_type = []
    for scan in scans:
        scan = scan.strip()
        
        if scan in SCAN_OPTIONS :
            scan_type.append(scan)
            
        else:
            # Ask confirmation to the agent.
            model.model_config.cyber_exp_model("Do you confirm there are no scans to perform? If this not the case please regenerate an answer respecting the zap scan nomenclature thank you.")
    
    # Freeing of RAM and VRAM
    del model.model_config
    free_malloc = gc.collect()
    
    if free_malloc is True:
        print("memory freed; model unloaded")
    else:
        print("failure to free memory; model still loaded")
        
    # Mapping of the ports for the login URL.
    web_ports_found = []
    for p in nmap_input:
        port = str(p['port_number'])
        
        if port in WEB_PORTS:
            web_ports_found.append(port)
    
    # page_input = input("Please type the login page's name needed with your test (ie: login.php): ") # For personalized use cases
    
    # redirect_input = input("Please enter the page to be redirected after login (ie: index.php): ") # For personalized use cases
    
    all_alerts = []
    for port_num in web_ports_found:
        if port_num == '80':
            #login_url = f"http://{target}/{page_input}" # For personalized use cases
            login_url = f"http://{target}/login.php"
        else:    
            #login_url = f"http://{target}:{port_num}/{page_input}" # For personalized use cases
            login_url = f"http://{target}:{port_num}/login.php"
        
        cookie_val = at_login_required(login_url, redirect_page="index.php")

        if cookie_val:
            
            # Initialize an empty ZAP session, inject the cookie obtained from the programmatic login, and set it as active.
            zap.httpsessions.create_empty_session(site=f"http://{zap_target}", session="mysession")
            zap.httpsessions.set_session_token_value(site=f"http://{zap_target}", session="mysession", sessiontoken="PHPSESSID", tokenvalue=cookie_val)
            zap.httpsessions.set_active_session(site=f"http://{zap_target}", session="mysession")
            
            # Debug prints.
            # print("=== SESSIONS ===")
            # print(zap.httpsessions.sessions(site=f"http://{zap_target}"))
            # print("=== ACTIVE SESSION ===")
            # print(zap.httpsessions.active_session(site=f"http://{zap_target}"))
            # print("=== EoL SESSIONS ===")
            
        for t in scan_type: 
            
            target_url = f"http://{zap_target}/"
            print(f'Targetting -> {target_url} at port {port_num}')
            
            # The ZAP scans chosen by the cyber agent are applied to the target url.
            alerts = zap_scan(target_url, t)
            all_alerts.append(alerts)
            
            # Debug prints.
            # print("============== all_alerts[0] ====================")
            # print(all_alerts[0]) 
            # print("============== EoL 4 ============================")
            
    return all_alerts
    
if __name__ == "__main__":
    target = "127.0.0.1" #input("Please enter the targeted addresses: \n") # For personalized use cases
    zap_target = "172.17.0.1"
    all_alerts = autonomous_vunerability_scanner_agent(target, zap_target)
    parsed = report_parser(all_alerts)
    report = vulnerability_ranker(parsed)