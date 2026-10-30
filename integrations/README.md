# Sending Mikrokat alerts to a SIEM

Everything here is optional. Turn on the method you want on the Data tab of Settings.

Every alert is one JSON object in Suricata's EVE format, so most tools can read it as Suricata data. Mikrokat adds:

```json
"mikrokat": {"action": "Would block", "target": "203.0.113.5", "direction": "inbound", "country": "NL"}
```

| Tool | Method | Setup |
|---|---|---|
| Splunk | File through a Universal Forwarder | See below |
| Splunk | HTTP Event Collector | Webhook, format Splunk HEC, token in Secret, URL ending in `/services/collector/event` |
| Elastic | File through Filebeat or Elastic Agent | Read `alerts.json` with JSON parsing, or use the Suricata integration |
| Wazuh | File through an agent | [wazuh](wazuh/README.md) |
| Graylog and others | Syslog | Add a Syslog input and parse the message body as JSON |

## Splunk Universal Forwarder

`inputs.conf`:

```ini
[monitor:///opt/mikrokat/data/logs/alerts.json]
sourcetype = suricata
index = main
```

Use a `props.conf` with `KV_MODE = json` if you have no Suricata add-on.
