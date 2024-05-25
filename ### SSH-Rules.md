### Suricata Rules

Suricata, ağ trafiğini izlemek ve anormal veya zararlı etkinlikleri tespit etmek için kullanılan bir açık kaynaklı tehdit algılama motorudur. İşte port 22 (SSH) ile ilgili brute force saldırılarını tespit etmek için bazı Suricata kuralları:

1. **SSH Login Attempt Detection:** SSH bağlantı girişimlerini tespit eder.
   ```suricata
   alert tcp any any -> any 22 (msg:"SSH login attempt"; flow:to_server,established; content:"SSH-2.0-"; nocase; sid:1000001; rev:1;)
   ```

2. **SSH Brute Force Detection (Multiple Failed Logins):** Belirli bir süre içinde (örneğin 60 saniye) belirli sayıda (örneğin 5) başarısız SSH girişimi tespit edildiğinde uyarı verir.
   ```suricata
   alert tcp any any -> any 22 (msg:"Potential SSH Brute Force Attack"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; content:"Failed password"; nocase; sid:1000002; rev:1;)
   ```

3. **SSH Successful Login:** Başarılı SSH girişimlerini tespit eder.

   ```suricata
   alert tcp any any -> any 22 (msg:"Successful SSH Login"; flow:to_server,established; content:"Accepted password"; nocase; sid:1000003; rev:1;)
   ```

### Splunk Queries

Splunk, büyük veri analizi ve güvenlik bilgisi ile olay yönetimi (SIEM) için kullanılan güçlü bir platformdur. İşte SSH brute force saldırılarını tespit etmek için bazı Splunk sorguları:

1. **SSH Login Attempts:** SSH hizmetine başarısız girişim denemelerini sayar ve kaynak IP adresi ve kullanıcı adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "sshd" "Failed password" | stats count by src_ip user
   ```

2. **Multiple Failed SSH Logins (Brute Force Detection):** Belirli bir süre içinde (örneğin 5 dakika) belirli sayıda (örneğin 5) başarısız SSH girişimi tespit edildiğinde, kaynak IP adresi ve kullanıcı adına göre gruplar.

   ```splunk
   index=your_index sourcetype=your_sourcetype "sshd" "Failed password" | stats count by src_ip user | where count > 5
   ```

3. **Successful SSH Logins:** Başarılı SSH girişimlerini sayar ve kaynak IP adresi ve kullanıcı adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "sshd" "Accepted password" | stats count by src_ip user
   ```
   Bu kurallar ve sorgular, SSH trafiğini izleyerek brute force saldırılarını tespit etmek için kullanılabilir.