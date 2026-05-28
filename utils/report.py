import zapv2
import json

zap = zapv2.ZAPv2(proxies={'http': 'http://172.17.0.1:8080', 'https': 'http://172.17.0.1:8080'})

def alert_scorer(alert):
    
    risk_mapping = {
        'high': 3,
        'medium': 2,
        'low': 1,
        'informational': 0
    }
    
    confidence_mapping = {
        'high': 3,
        'medium': 2,
        'low': 1
    }
    
    risk_score = risk_mapping[alert['risk'].lower()]
    confidence_score = confidence_mapping[alert['confidence'].lower()]
    
    if risk_score > 0:
        
        result_score = (risk_score * 3) + confidence_score - 3
    
    else:
        
        result_score = 0.0
    
    return result_score

def report_parser(all_alerts):
    
    alert_list = []

    for alerts in all_alerts:
        
        for alert in alerts:
            
            alert_mapping = {
                'alert': alert['alert'],
                'cweid': alert['cweid'],
                'pluginId': alert['pluginId'],
                'risk': alert['risk'],
                'confidence': alert['confidence'],
                'url': alert['url'],
                'param': alert['param'],
                'method': alert['method'],
                'evidence': alert['evidence'],
                'attack': alert['attack'],
                'solution': alert['solution'],
                'description': alert['description'],
                'reference': alert['reference']
            }
            
            alert_mapping['score'] = alert_scorer(alert_mapping)
            
            alert_list.append(alert_mapping)
        
    return alert_list

def vulnerability_ranker(alert_list):
    
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    informational_count = 0
    
    alerts_sorted = sorted(alert_list, key=lambda x: x['score'], reverse=True)
    
    for alert in alerts_sorted:
        
        if alert['risk'].lower() == 'high':
            
            high_risk_count += 1
        
        elif alert['risk'].lower() == 'medium':
            
            medium_risk_count += 1
        
        elif alert['risk'].lower() == 'low':
            
            low_risk_count += 1
        
        elif alert['risk'].lower() == 'informational':
            
            informational_count += 1
    
    total_risk_count = high_risk_count + medium_risk_count + low_risk_count

    report = {
        'summary': {
            'total risks': total_risk_count,
            'high': high_risk_count,
            'medium': medium_risk_count,
            'low': low_risk_count,
            'informational': informational_count
        },
        'vulnerabilities': alerts_sorted
    }
    
    with open("custom-vulnerability-report.json", "w") as file:
        
        json.dump(report, file, indent=4)
        
    return report