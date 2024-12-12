import re
import json
import csv
from collections import defaultdict

# Log faylını oxuma
log_file = 'server_logs.txt'

# Pattern
log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) /login HTTP/1.1" (\d+) (\d+)'

# Uğursuz giriş cəhdlərini saxlamaq üçün dictionary
failed_logins = defaultdict(int)

# IP ünvanlarını və onların müvafiq məlumatlarını saxlamaq üçün listlər
log_data = []

# Log faylını oxuyub analiz edirik
with open(log_file, 'r') as f:
    for line in f:
        match = re.search(log_pattern, line)
        if match:
            ip = match.group(1)
            date = match.group(2)
            method = match.group(3)
            status = match.group(4)
            size = match.group(5)

            # IP ünvanları və HTTP metodları
            log_data.append({'IP': ip, 'Date': date, 'Method': method, 'Status': status})

            # Uğursuz giriş cəhdlərinin sayını artırırıq
            if status == '401':  # 401 status kodu uğursuz girişdir
                failed_logins[ip] += 1

# 5-dən çox uğursuz giriş cəhdi olan IP-ləri tapırıq
failed_logins_ip = {ip: count for ip, count in failed_logins.items() if count > 5}

# JSON fayllarını yazmaq
with open('failed_logins.json', 'w') as f:
    json.dump(failed_logins_ip, f, indent=4)

# Təhdid kəşfiyyatı IP-ləri (məsələn, təhdid IP-lərini hardcoded olaraq təyin edə bilərik)
threat_ips = ['192.168.1.11',]  # Bu siyahıya təhdid IP-lərini əlavə edin

# Təhdid IP-lərini tapmaq
threat_ip_data = [entry for entry in log_data if entry['IP'] in threat_ips]

with open('threat_ips.json', 'w') as f:
    json.dump([entry['IP'] for entry in threat_ip_data], f, indent=4)

# Birləşdirilmiş təhlükəsizlik məlumatları (failed_logins və threat_ips birləşməsi)
combined_security_data = {
    'failed_logins': failed_logins_ip,
    'threat_ips': [entry['IP'] for entry in threat_ip_data]
}

with open('combined_security_data.json', 'w') as f:
    json.dump(combined_security_data, f, indent=4)

# Mətn faylını yazmaq: IP-lər və onların uğursuz giriş cəhdləri
with open('log_analysis.txt', 'w') as f:
    for ip, count in failed_logins_ip.items():
        f.write(f"{ip} failed {count} login attempts\n")

# CSV faylını yaratmaq
with open('log_analysis.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP', 'Date', 'Method', 'Status']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for entry in log_data:
        writer.writerow(entry)

print("Log configuration is done")
