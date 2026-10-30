# Send Mikrokat alerts to Wazuh

This is optional. Mikrokat works without Wazuh.

1. On the Data tab of Mikrokat Settings, turn on Write an alert file.
2. Install a Wazuh agent on the Mikrokat host and add this to its `ossec.conf`:

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/opt/mikrokat/data/logs/alerts.json</location>
   </localfile>
   ```

3. Restart the agent.

Wazuh's Suricata rules read these alerts at a low level. To get notified, add [local_rules.xml](local_rules.xml) to `/var/ossec/etc/rules/local_rules.xml` on the manager and restart it. It raises Mikrokat alerts to level 7, and to level 12 for high severity alerts and real blocks. Wazuh emails from level 12 by default.
