# wazuh-cloudflare

# 🛡️ Wazuh XDR + Cloudflare Integration for Active Response

This project combines the power of **Wazuh XDR** and **Cloudflare** to deliver automated threat detection and mitigation at scale.

## 🚀 Overview

- **Wazuh XDR** for threat detection and incident response  
- 🔹 **Cloudflare** for edge-level traffic filtering and IP blocking  

## 🔒 Key Benefits

- ✅ Real-time detection of malicious activity using Wazuh's correlation engine  
- ✅ Automatic blocking of suspicious IPs via Cloudflare’s firewall API   
- ✅ Scalable and automated protection — no manual intervention needed  
- ✅ Faster incident response with proactive threat mitigation  

---

## ⚙️ How It Works

1. Wazuh analyzes logs, detects threats, and raises alerts  
2. Malicious IPs are sent to **Cloudflare** for immediate blocking  
3. All activity is monitored and logged for full auditability  

---

## 🧩 Configuration

### 1. Cloudflare Setup

#### Create an IP List

1. Go to your Cloudflare account.  
2. Navigate to **Manage Account → Configurations → Lists**.  
3. Click **Create new list**.  
4. Name it (e.g., `wazuh_blocked_ips`), select `IP Address` as content type, and click **Create**.  
5. Copy the **List ID** (`CLOUDFLARE_IP_LIST_ID`).  

#### Get Your Account ID

- Found on your domain’s main page under the API section. Save it as `CLOUDFLARE_ACCOUNT_ID`.

#### Create an API Token

1. Go to **My Profile → API Tokens → Create Token**.  
2. Use the **Edit Cloudflare IP Lists** template or define custom permissions:
   - **Account → Account Settings → Read**  
   - **Account → Cloudflare IP Lists → Edit (or Write)**  
3. Assign the token to your account and **copy it immediately**. Save as `CLOUDFLARE_API_TOKEN`.

#### Create a Firewall Rule

1. Go to **Security → WAF → Firewall Rules**.  
2. Click **Create Firewall Rule**.  
3. Name it (e.g., `Block Wazuh IPs`), and configure:
   - **Field**: `IP Source Address`
   - **Operator**: `is in list`
   - **Value**: your IP list (`wazuh_blocked_ips`)
   - **Action**: `Block`, `Managed Challenge`, or `JS Challenge`  
4. Click **Deploy**.

---

### 2. Wazuh Configuration

#### Create Active Response Script

1. Copy the active response script to  `/var/ossec/active-response/bin/cloudflare-block-ip.py`:
2. Install the python modules requeriments: apt install python-requests
3. Make it executable:
   ```bash
   chmod +x /var/ossec/active-response/bin/cloudflare-block-ip.py
   ```

#### Configure Active Response in Wazuh

1. In `/var/ossec/etc/ossec.conf`, add:
   ```xml
 <ossec_config>
  <command>
    <name>cloudflare-block</name>
    <executable>cloudflare-block-ip.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>cloudflare-block</command>
    <location>server</location> 
    <rules_id>5712,5720</rules_id>
    <timeout>60</timeout>
  </active-response>
</ossec_config>
   ```

3. Restart Wazuh:
   ```bash
   systemctl restart wazuh-manager
   ```

---

## 📌 Notes

- Make sure Wazuh has outbound internet access to reach the Cloudflare API.
- You can customize the rule to respond to different threat types or log sources.

---

## 📁 Optional

You can create a `docs/` folder with:
- Sample logs that trigger the response
- Extended JSON example from GCP
- Testing instructions 

---

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a pull request.
