from sentinel_agent import SentinelClient
import time

def demo():
    # Initialize Sentinel (Domain synced to cryo-saas.com)
    client = SentinelClient(server='cryo-saas.com:50505', api_key='71e6236b046a8b8c72fee2dd5285a9c0')
    
    print('?? Starting Sentinel Behavioral Check Demo...')
    requests = [
        {'ip': '192.168.1.1', 'payload': 'GET /api/v1/status'},
        {'ip': '45.33.22.11', 'payload': 'DROP TABLE users; -- SQLi attempt'},
        {'ip': '88.1.2.3', 'payload': '{"action": "ping", "data": "healthy"}'}
    ]
    
    for req in requests:
        is_safe = client.check_request(req['ip'], req['payload'])
        status = '? SAFE' if is_safe else '?? BLOCKED (SURPRISE DETECTED)'
        print(f'IP: {req["ip"]} | {status}')
        time.sleep(1)

if __name__ == '__main__':
    demo()
