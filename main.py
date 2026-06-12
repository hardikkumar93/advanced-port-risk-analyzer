# Socket library network connections aur port scanning ke liye
import socket

#For scanning time
import time

# PDF report generate karne ke liye ReportLab library
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Common port numbers aur unki services ka mapping
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session", 
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
    27017: "MongoDB"
}
# Har service ke liye risk level define kiya gaya hai

risk_levels = {
    21: "Medium Risk",      # FTP
    22: "Low Risk",         # SSH
    23: "High Risk",        # Telnet
    25: "Medium Risk",      # SMTP
    53: "Low Risk",         # DNS
    67: "Low Risk",         # DHCP Server
    68: "Low Risk",         # DHCP Client
    69: "High Risk",        # TFTP
    80: "Low Risk",         # HTTP
    110: "Medium Risk",     # POP3
    123: "Low Risk",        # NTP
    135: "Medium Risk",     # MS RPC
    137: "Medium Risk",     # NetBIOS Name
    138: "Medium Risk",     # NetBIOS Datagram
    139: "High Risk",       # NetBIOS Session
    143: "Medium Risk",     # IMAP
    161: "Medium Risk",     # SNMP
    162: "Medium Risk",     # SNMP Trap
    179: "Low Risk",        # BGP
    389: "Medium Risk",     # LDAP
    443: "Low Risk",        # HTTPS
    445: "High Risk",       # SMB
    465: "Low Risk",        # SMTPS
    514: "Low Risk",        # Syslog
    587: "Low Risk",        # SMTP Submission
    636: "Low Risk",        # LDAPS
    993: "Low Risk",        # IMAPS
    995: "Low Risk",        # POP3S
    1433: "High Risk",      # MSSQL
    1521: "High Risk",      # Oracle
    2049: "Medium Risk",    # NFS
    3306: "Medium Risk",    # MySQL
    3389: "High Risk",      # RDP
    5432: "Medium Risk",    # PostgreSQL
    5900: "High Risk",      # VNC
    6379: "High Risk",      # Redis
    8080: "Medium Risk",    # HTTP Alternate
    8443: "Low Risk",       # HTTPS Alternate
    9200: "High Risk",      # Elasticsearch
    27017: "Medium Risk"    # MongoDB
}

# Risk level ka reason batane ke liye dictionary
risk_reasons = {
    21: "FTP does not encrypt data, so usernames and passwords can be seen by attackers.",
    22: "SSH uses encryption and is generally safe to use.", 
    23: "Telnet does not encrypt data, making it easy for attackers to read information.",
    25: "SMTP can be misused for sending spam emails if not secured properly.",
    53: "DNS is important for websites, but a badly configured DNS server can be misused.",
    67: "A fake DHCP server can give wrong network settings to users.",
    68: "DHCP clients usually have low risk but can be affected by fake DHCP servers.",
    69: "TFTP has no password protection or encryption.",
    80: "HTTP does not encrypt website traffic.",
    110: "POP3 sends email information without encryption.",
    123: "NTP is generally safe but can sometimes be misused in network attacks.",
    135: "This service may expose Windows systems to network attacks.",
    137: "This service may reveal information about devices on the network.",
    138: "This service may expose network information to attackers.",
    139: "This service has been used in many network attacks in the past.",
    143: "IMAP without encryption can expose email data.",
    161: "SNMP can reveal information about network devices.",
    162: "SNMP Trap messages may reveal network activity.",
    179: "BGP is important for internet routing but should only be used by trusted systems.",
    389: "LDAP sends directory information without encryption.",
    443: "HTTPS encrypts website traffic and is considered secure.",
    445: "SMB is often targeted by malware and ransomware.",
    465: "SMTPS encrypts email communication and is generally secure.",
    514: "Syslog may expose system logs if not protected.",
    587: "SMTP Submission supports secure email sending.",
    636: "LDAPS encrypts directory service communication.",
    993: "IMAPS encrypts email access.",
    995: "POP3S encrypts email retrieval.",
    1433: "An exposed SQL Server may allow attackers to access database data.",
    1521: "An exposed Oracle Database may reveal sensitive information.",
    2049: "Improperly configured NFS shares can expose files.",
    3306: "An exposed MySQL server may allow unauthorized access.",
    3389: "RDP is often targeted by password guessing attacks.",
    5432: "An exposed PostgreSQL database may leak important data.",
    5900: "Weakly protected VNC servers may allow remote access.",
    6379: "Redis without security settings can be easily accessed by attackers.",
    8080: "Applications running on this port may not use encryption.",
    8443: "This port usually provides secure encrypted web access.",
    9200: "Elasticsearch may expose sensitive information if left open.",
    27017: "MongoDB may leak data if it is publicly accessible."
}

# Security improve karne ke recommendations
recommendations = {
    21: "Use SFTP instead of FTP whenever possible.",
    22: "Use strong passwords and disable root login.",
    23: "Replace Telnet with SSH.",
    25: "Enable SMTP authentication and spam protection.",
    53: "Allow DNS access only from trusted sources.",
    67: "Allow DHCP services only on trusted networks.",
    68: "Use trusted DHCP servers only.",
    69: "Avoid TFTP for sensitive file transfers.",
    80: "Redirect users to HTTPS.",
    110: "Use encrypted email protocols.",
    123: "Restrict NTP access to trusted systems.",
    135: "Limit RPC access using firewall rules.",
    137: "Disable NetBIOS if not required.",
    138: "Disable NetBIOS if not required.",
    139: "Restrict NetBIOS access to trusted networks.",
    143: "Use IMAPS instead of IMAP.",
    161: "Use strong SNMP community strings and restrict access.",
    162: "Allow SNMP Trap traffic only from trusted devices.",
    179: "Allow BGP connections only from trusted peers.",
    389: "Use LDAPS instead of LDAP.",
    443: "Keep SSL/TLS certificates updated.",
    445: "Restrict SMB access using firewall rules.",
    465: "Keep email encryption settings updated.",
    514: "Protect and monitor Syslog servers.",
    587: "Use authentication for email submission.",
    636: "Keep directory services secured and updated.",
    993: "Use strong email account passwords.",
    995: "Use strong email account passwords.",
    1433: "Do not expose SQL Server directly to the internet.",
    1521: "Restrict Oracle Database access to trusted hosts.",
    2049: "Limit NFS access to authorized systems only.",
    3306: "Do not expose MySQL directly to the internet.",
    3389: "Use VPN and Multi-Factor Authentication.",
    5432: "Restrict PostgreSQL access to trusted hosts.",
    5900: "Secure VNC with strong authentication.",
    6379: "Enable Redis authentication and restrict access.",
    8080: "Use HTTPS if sensitive data is transmitted.",
    8443: "Maintain secure SSL/TLS configurations.",
    9200: "Do not expose Elasticsearch to the public internet.",
    27017: "Enable MongoDB authentication and restrict access."
}

# Better aur secure alternatives
recommended_services = {
    21: "SFTP",
    22: "SSH",
    23: "SSH",
    25: "SMTP with Authentication",
    53: "Secure DNS Configuration",
    67: "Secure DHCP Configuration",
    68: "Trusted DHCP Server",
    69: "SFTP",
    80: "HTTPS",
    110: "POP3S",
    123: "Secure NTP Configuration",
    135: "Restricted RPC Access",
    137: "Disable NetBIOS",
    138: "Disable NetBIOS",
    139: "Disable NetBIOS or Restrict Access",
    143: "IMAPS",
    161: "Secure SNMP",
    162: "Secure SNMP Trap",
    179: "Trusted BGP Peers",
    389: "LDAPS",
    443: "HTTPS",
    445: "Restricted SMB Access",
    465: "SMTPS",
    514: "Secure Syslog",
    587: "Authenticated SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Secured SQL Server",
    1521: "Secured Oracle Database",
    2049: "Restricted NFS Access",
    3306: "Secured MySQL",
    3389: "RDP with VPN and MFA",
    5432: "Secured PostgreSQL",
    5900: "Secured VNC",
    6379: "Authenticated Redis",
    8080: "HTTPS",
    8443: "HTTPS",
    9200: "Restricted Elasticsearch",
    27017: "Authenticated MongoDB"
}

# Recommended service better kyu hai uska explanation
why_alternative = {
    21: "SFTP encrypts file transfers and protects usernames and passwords.",
    22: "Strong passwords and restricted root access improve SSH security.",
    23: "SSH encrypts communication and protects login credentials.",
    25: "SMTP authentication helps prevent spam and unauthorized email use.",
    53: "Secure DNS settings help prevent misuse and unauthorized access.",
    67: "Trusted DHCP services reduce the risk of incorrect network settings.",
    68: "Using trusted DHCP servers helps ensure safe network configuration.",
    69: "Secure file transfer methods provide encryption and authentication.",
    80: "HTTPS encrypts website traffic and protects sensitive information.",
    110: "Encrypted email protocols protect messages and login credentials.",
    123: "Restricting NTP access helps prevent abuse of time services.",
    135: "Firewall protection reduces exposure to network attacks.",
    137: "Disabling unnecessary services reduces information leakage.",
    138: "Disabling unused services improves overall network security.",
    139: "Restricting NetBIOS access reduces unauthorized connections.",
    143: "IMAPS encrypts email communication and protects user data.",
    161: "Secure SNMP settings help prevent unauthorized monitoring.",
    162: "Trusted devices improve the security of network monitoring.",
    179: "Trusted BGP peers reduce routing security risks.",
    389: "LDAPS encrypts directory information and protects user data.",
    443: "Updated certificates help maintain secure encrypted communication.",
    445: "Firewall restrictions reduce SMB-related attacks.",
    465: "Encrypted email communication improves message security.",
    514: "Protected log servers help secure system information.",
    587: "Authenticated email submission reduces email abuse.",
    636: "Encrypted directory communication improves security.",
    993: "Encrypted email access protects account information.",
    995: "Encrypted email retrieval improves privacy and security.",
    1433: "Restricting database access helps protect sensitive data.",
    1521: "Trusted host access reduces database security risks.",
    2049: "Limiting NFS access protects shared files from unauthorized users.",
    3306: "Restricted database access improves MySQL security.",
    3389: "VPN and MFA greatly improve remote desktop security.",
    5432: "Trusted host access helps protect PostgreSQL databases.",
    5900: "Strong authentication improves VNC security.",
    6379: "Redis authentication prevents unauthorized access.",
    8080: "HTTPS provides encryption for web applications.",
    8443: "Strong SSL/TLS settings maintain secure communication.",
    9200: "Restricting Elasticsearch access helps prevent data exposure.",
    27017: "MongoDB authentication protects sensitive database information."
}

# User se target website aur port range lena
target = input("Enter Website/IP: ")

start_port = int(input("Start Port: "))
end_port = int(input("End Port: "))

#website and port validation
has_error = False

# Website Validation First
try:
    ip = socket.gethostbyname(target)

except socket.gaierror:
    print("\nERROR: Invalid Website/IP Address")
    has_error = True

# Port Validation  after that
if start_port < 1 or start_port > 65535:
    print("ERROR: Invalid Start Port Number")
    has_error = True

if end_port < 1 or end_port > 65535:
    print("ERROR: Invalid End Port Number")
    has_error = True

if start_port > end_port:
    print("ERROR: Start Port Cannot Be Greater Than End Port")
    has_error = True
if has_error:
    exit()
# Scan result ko future report ke liye store karna
report_data = []

#scanning time batayegaa
start_time = time.time()

# Target IP display karna
print("\nScanning Target:", ip)
print("-" * 40)

# User ke diye gaye port range ko scan karna
for port in range(start_port, end_port + 1):

# TCP socket create karna
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connection attempt ke liye maximum wait time
    s.settimeout(0.3)

# Check karna ki port open hai ya nahi
    result = s.connect_ex((ip, port))

    if result == 0:

# Open port ki service identify karna
        service = services.get(port, "Unknown Service")
        # Risk level aur uska reason nikalna
        risk = risk_levels.get(
        port,
        "Needs Manual Review")

        risk_reason = risk_reasons.get(port, "No reason available.")
        # Security recommendation aur secure alternative
        recommendation = recommendations.get(port, "No recommendation available.")
        recommended_service = recommended_services.get(
            port,
            "No recommended service available."
        )
        why = why_alternative.get(port, "No explanation available.")

        print(f"\nPort {port} -> OPEN ({service}) | {risk}")

        print(f"\nWhy {risk}?")
        print(risk_reason)

# Check karna service secure hai ya upgrade required
        if service == recommended_service:
            status = "Service Appears Secure"
        else:
            status = "Upgrade Recommended"

        print("\nStatus:")
        print(status)

        print("\nRecommended Service:")
        print(recommended_service)

        print("\nRecommendation:")
        print(recommendation)

        print(f"\nWhy {recommended_service}?")
        print(why)

        print("-" * 50)

# Report ke liye result ko text format me store karna
        report_entry = f"""
Port {port} -> OPEN ({service}) | {risk}

Why {risk}?
{risk_reason}

Status:
{status}

Recommended Service:
{recommended_service}

Recommendation:
{recommendation}

Why {recommended_service}?
{why}

--------------------------------------------------
"""
# Report list me entry add karna
        report_data.append(report_entry)

# Resource free karne ke liye socket close karna
    s.close()
 
print(
    f"\nTotal Open Ports Found: {len(report_data)}"
)

end_time = time.time()

scan_time = end_time - start_time

print(f"\nScan Completed In: {scan_time:.2f} Seconds")

# User se poochna ki text report save karni hai ya nahi
save = input("\nSave Report? (y/n): ")

if save.lower() == "y":
# Report ko text file me save karna
    with open(
    f"{target}_report.txt",
    "w"
) as file:

     for line in report_data:
        file.write(line)
    print("Report Saved Successfully!")

# User se poochna PDF report generate karni hai ya nahi
save = input("\nGenerate PDF Report? (y/n): ")

if save.lower() == "y":

# PDF document object create karna
    pdf = SimpleDocTemplate(f"{target}_report.pdf")

# PDF ke styles load karna
    styles = getSampleStyleSheet()

    content = []

# PDF report ka heading create karna
    title = Paragraph(
        f"Advanced Port Scanner Report - {target}",
        styles['Title']
    )

    content.append(title)
    content.append(Spacer(1, 12))

    content.append(
    Paragraph(
        f"Target IP Address: {ip}",
        styles['Heading2']
    )
)

    content.append(Spacer(1, 10))

    content.append(
    Paragraph(
        f"Total Open Ports Found: {len(report_data)}",
        styles['Heading2']
    )
  )

content.append(Spacer(1, 12))

# Har report entry ko PDF me add karna
for entry in report_data:

        para = Paragraph(
            entry.replace("\n", "<br/>"),
            styles['BodyText']
        )

        content.append(para)
        content.append(Spacer(1, 10))

# Final PDF generate karna
        pdf.build(content)

print("PDF Report Generated Successfully!")

print("\nScan Complete")