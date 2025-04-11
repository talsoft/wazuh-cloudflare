# 🛡️ Wazuh XDR + Cloudflare Integration for Active Response

## 📌 Notes

- Make sure Wazuh has outbound internet access to reach the Cloudflare API.
- Use logging inside the bash script for debugging (e.g., `logger` or `echo` to a log file).
- You can customize the rule to respond to different threat types or log sources.

---

## 🧪 Testing

You can test your active response script manually using the following command:

```bash
echo '{ 
  "version": 1, 
  "origin": { "name": "node01", "module": "wazuh-execd" }, 
  "command": "add", 
  "parameters": { 
    "action": "add", 
    "extra_args": [], 
    "alert": { 
      "timestamp": "2025-04-09T14:50:00.123-0300", 
      "rule": { 
        "level": 10, 
        "description": "SSHD brute force trying different users.", 
        "id": "5712", 
        "firedtimes": 50, 
        "groups": ["sshd", "authentication_failed"] 
      }, 
      "agent": { 
        "id": "001", 
        "name": "webserver-01", 
        "ip": "192.168.1.10" 
      }, 
      "manager": { "name": "wazuh-manager" }, 
      "id": "1712685000.12345", 
      "data": { 
        "srcip": "198.51.100.123", 
        "srcport": "54321", 
        "dstuser": "invaliduser" 
      }, 
      "location": "sshd" 
    }, 
    "program": "/var/ossec/active-response/bin/cloudflare-block-ip.py" 
  } 
}' | python3 ./cloudflare-block-ip.py add some_user 198.51.100.123 1712685000.12345 5712 agent_name agent_ip
