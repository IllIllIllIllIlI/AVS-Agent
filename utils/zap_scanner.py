import zapv2
import time

zap = zapv2.ZAPv2(proxies={'http': 'http://172.17.0.1:8080', 'https': 'http://172.17.0.1:8080'})

def zap_scan(target_url, scan_type):
    
    if scan_type == 'spider':
        
        print(f"Starting tradidional Spider scan at {target_url}...")
        spider = zap.spider.scan(url=target_url)
        
        while int(zap.spider.status(spider)) < 100: 
            
            print('Spider progress %: {}'.format(zap.spider.status(spider)))
            time.sleep(2)
            
        print("Spider finished crawling, waiting for ZAP to process...")
        time.sleep(5)
        
        print("=== URLS FOUND ===")
        print("zap.spider.results(spider): ",zap.spider.results(spider))
        print("=== EoL URLS ===")
        
        return zap.alert.alerts()
    
    elif scan_type == 'ajaxSpider':
        
        print(f"Starting ajaxSpider scan at {target_url}...")
        ajaxSpider = zap.ajaxSpider.scan(target_url)
        
        timeout = time.time() + 60*2 
        while zap.ajaxSpider.status() == 'running':
            
            if time.time() > timeout:
                break
            
            print('Ajax Spider status' + zap.ajaxSpider.status())
            time.sleep(7)
        
        print("ajaxSpider finished crawling, waiting for ZAP to process...")
        time.sleep(5)
        
        return zap.alert.alerts()
    
    elif scan_type == 'ascan':
        print(f"Starting ascan scan at {target_url}...")
        ascan = zap.ascan.scan(url=target_url, recurse=True, inscopeonly=False)
        while True:    
            status = zap.ascan.status(ascan)
            print(f"Ascan scan at {status}%")
            if isinstance(status, int) or status.isdigit():
                if int(status) >= 100:
                    
                    return zap.alert.alerts()
                
            else:
                print("Scan finished or does not exist.")
                return zap.alert.alerts()

            time.sleep(7)
    
    elif scan_type == 'pscan':
        
        print(f"Starting pscan scan at {target_url}...")
        pscan = zap.pscan.enable_all_scanners()
        
        while int(zap.pscan.status(pscan)) < 100:
            print(f"Pscan scan at {zap.pscan.status(pscan)}%")
            time.sleep(7)
        
        print("pscan finished passive scanning, waiting for ZAP to process...")
        time.sleep(5)
            
        return zap.alert.alerts()
    
    else:
        
        return "Scan not in list please try again"