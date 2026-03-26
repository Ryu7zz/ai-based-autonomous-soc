from pathlib import Path

ossec_path = Path('/var/ossec/etc/ossec.conf')
rules_path = Path('/var/ossec/etc/rules/local_rules.xml')

ossec = ossec_path.read_text(encoding='utf-8')
rules = rules_path.read_text(encoding='utf-8')

rule_block = """
<group name=\"local,attack,authentication_failed,\">
  <rule id=\"100501\" level=\"12\">
    <if_group>authentication_failed</if_group>
    <description>Custom brute-force threshold exceeded</description>
    <frequency>6</frequency>
    <timeframe>60</timeframe>
    <same_source_ip />
  </rule>
</group>
"""

active_response_block = """
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100501,5710,5712,5763</rules_id>
    <timeout>600</timeout>
  </active-response>
"""

extra_localfiles = """
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>
"""

changed = False

if "rule id=\"100501\"" not in rules:
    rules = rules.rstrip() + "\n\n" + rule_block + "\n"
    rules_path.write_text(rules, encoding='utf-8')
    changed = True

if "<rules_id>100501,5710,5712,5763</rules_id>" not in ossec:
    first_close = ossec.find("</ossec_config>")
    if first_close != -1:
        ossec = ossec[:first_close] + "\n" + active_response_block + "\n" + ossec[first_close:]
        changed = True

if "/var/log/auth.log" not in ossec:
    second_open = ossec.find("<ossec_config>", ossec.find("</ossec_config>") + 1)
    if second_open != -1:
        second_close = ossec.find("</ossec_config>", second_open)
        if second_close != -1:
            section = ossec[second_open:second_close]
            section += "\n" + extra_localfiles + "\n"
            ossec = ossec[:second_open] + section + ossec[second_close:]
            changed = True

if changed:
    ossec_path.write_text(ossec, encoding='utf-8')
    print("updated")
else:
    print("already-configured")
