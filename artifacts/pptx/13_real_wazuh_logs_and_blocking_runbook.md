Real Wazuh Logs + Real Blocking Runbook

Goal
- Show real attack/security logs in Wazuh Dashboard.
- Show real active-response blocking (iptables/firewalld) with proof.

Why you only see system logs now
- Usually only manager/internal service logs are indexed.
- Agents are not forwarding security log sources (auth, sysmon, web, IDS, firewall).
- No rules are firing for your test attack pattern.
- Active response is not enabled on manager/agents.

Step 1: Ensure at least one monitored endpoint agent is connected
- In Wazuh Dashboard -> Agents, status must be Active.
- If no active agents, install/register agent first.

Linux agent quick check
- On endpoint: sudo systemctl status wazuh-agent
- On manager: sudo /var/ossec/bin/agent_control -l

Step 2: Collect real security logs on Linux agent
Edit /var/ossec/etc/ossec.conf on the Linux agent and include these localfile blocks inside <ossec_config>:

<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/secure</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/nginx/access.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/nginx/error.log</location>
  <log_format>syslog</log_format>
</localfile>

Then restart agent:
- sudo systemctl restart wazuh-agent

Step 3: Add a guaranteed test detection rule on manager
Edit /var/ossec/etc/rules/local_rules.xml on Wazuh manager and add:

<group name="local,attack,authentication_failed,">
  <rule id="100501" level="12">
    <if_group>authentication_failed</if_group>
    <description>Custom brute-force threshold exceeded</description>
    <frequency>6</frequency>
    <timeframe>60</timeframe>
    <same_source_ip />
  </rule>
</group>

Restart manager:
- sudo systemctl restart wazuh-manager

Step 4: Enable active response blocking
Edit /var/ossec/etc/ossec.conf on manager and ensure these entries exist:

<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100501,5710,5712,5763</rules_id>
  <timeout>600</timeout>
</active-response>

Restart manager:
- sudo systemctl restart wazuh-manager

Notes
- For endpoint-side blocking instead of manager-side, set location to all or defined-agent depending on architecture.
- On systems using nftables/firewalld, verify the drop command backend used by Wazuh package.

Step 5: Generate real attack-like logs (safe test)
From another host, run repeated failed SSH logins against your test Linux target (lab only).
- Example behavior: 8-12 wrong password attempts within 1 minute.

Or local simulation on target to force auth-failed lines:
- sudo logger "Failed password for invalid user test from 185.44.9.10 port 53322 ssh2"
Repeat several times quickly.

Step 6: Verify in dashboard (this is what you screenshot)
Open Wazuh Dashboard -> Security events and query:
- rule.level >= 10
- rule.id: 100501 OR rule.groups: authentication_failed
- data.srcip: 185.44.9.10 (or your test source IP)

Step 7: Verify real blocking happened
On blocking node (manager or endpoint depending on location):
- sudo iptables -L -n | grep 185.44.9.10
or
- sudo firewall-cmd --list-rich-rules | grep 185.44.9.10

Also verify active-response log:
- sudo tail -n 200 /var/ossec/logs/active-responses.log

Step 8: Connect to your app for project demo
Use your app webhook endpoint to ingest same alerts:
- POST /api/webhook/wazuh
Then show in your app:
- /api/webhook/events
- /api/webhook/events/{ingestion_id}

PPT screenshots to prove real logs + real blocking
1) Wazuh Agents page showing Active agent(s).
2) Wazuh Security events showing auth_failed/high-level alerts (rule 100501 or similar).
3) Event details panel showing real srcip, rule.id, and firedtimes.
4) Terminal with iptables/firewalld rule containing attacker IP.
5) Terminal tail of active-responses.log showing firewall-drop execution.
6) Your app webhook history showing same alert ingested.

Common reasons blocking does not happen
- active-response block missing in ossec.conf.
- Rule ID not included in active-response rules_id list.
- Manager restarted but agent not restarted after config changes.
- Alert rule fired at low level below your dashboard filter.
- Wrong blocking location (manager vs endpoint).

Verified live status on this host (already done)
- Wazuh manager is healthy: `systemctl is-active wazuh-manager` returned `active`.
- Real custom detection fired: rule `100501` events are present for failed SSH passwords from `185.44.9.10`.
- Real active response fired: rule `651` (`Host Blocked by firewall-drop Active Response`) is present and references rule `100501`.
- Real firewall block exists now:
  - `iptables -L -n` shows `DROP ... 185.44.9.10`.
  - `iptables -S` shows `-A INPUT -s 185.44.9.10/32 -j DROP` and `-A FORWARD -s 185.44.9.10/32 -j DROP`.
  - `nft list ruleset` also contains drop rules for `185.44.9.10`.

Fast screenshot sequence (no extra reconfiguration)
1) Dashboard Security events filter:
  - `rule.id:100501 OR rule.id:651`
2) Open one `100501` event details and capture:
  - `full_log` with `Failed password ... from 185.44.9.10`
  - `data.srcip = 185.44.9.10`
3) Open one `651` event details and capture:
  - description `Host Blocked by firewall-drop Active Response`
4) Terminal capture:
  - `sudo iptables -L -n | grep 185.44.9.10`
  - `sudo tail -n 50 /var/ossec/logs/active-responses.log`
