import nmap

def nmap_parser(results):
    target_ip = list(results['scan'].keys())
    
    ports_info = []
    
    for ip in target_ip:
        
        for port, port_items in results['scan'][ip]['tcp'].items():
            
            ports_info.append({
                'port_number': port,
                'service_name': port_items['name'],
                'service_product': port_items['product']
            })    
    
    return ports_info

def nmap_scan(target):
    print(f"Scanning {target}...")
    
    nm = nmap.PortScanner()
    
    is_open = nm.scan(hosts=target, arguments='-p- -sV')
    
    parser = nmap_parser(is_open)
    
    print(f"Scan done: {parser}")
    
    return parser