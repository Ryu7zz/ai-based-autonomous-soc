from pathlib import Path

ossec_path = Path('/var/ossec/etc/ossec.conf')
rules_path = Path('/var/ossec/etc/rules/local_rules.xml')

ossec = ossec_path.read_text(encoding='utf-8')
network_localfile = """
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/automaticsoc-network.json</location>
  </localfile>
"""

if '/var/log/automaticsoc-network.json' not in ossec:
    marker = """  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>
"""
    if marker in ossec:
        ossec = ossec.replace(marker, marker + "\n" + network_localfile)
    else:
        last = ossec.rfind('</ossec_config>')
        if last == -1:
            raise SystemExit('ossec.conf malformed: missing </ossec_config>')
        ossec = ossec[:last] + network_localfile + "\n" + ossec[last:]

rules = rules_path.read_text(encoding='utf-8')
network_rules = """
<group name="local,network,traffic,">
  <rule id="100700" level="8">
    <decoded_as>json</decoded_as>
    <field name="event_type">network_traffic</field>
    <description>AutomaticSOC network traffic event detected</description>
    <group>network,traffic,</group>
  </rule>

  <rule id="100701" level="12">
    <if_sid>100700</if_sid>
    <field name="attack_class">brute_force|port_scan|ddos|malware</field>
    <description>AutomaticSOC simulated network attack event</description>
    <group>attack,network,</group>
  </rule>
</group>
"""

if 'id="100700"' not in rules:
    rules = rules.strip() + "\n\n" + network_rules + "\n"

ossec_path.write_text(ossec, encoding='utf-8')
rules_path.write_text(rules, encoding='utf-8')
print('updated')
