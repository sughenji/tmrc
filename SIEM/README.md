# Elasticsearch

Search for event ID 4625 (failed login)

```
data.win.system.eventID: 4625
```

![](Pasted%20image%2020231228121015.png)

or: `*4625*`


Free text search: `"doco1"`

![](Pasted%20image%2020231228121300.png)


Login failed for disabled account (substatus = 0xC0000072)

```
data.win.system.eventID: 4625 and data.win.eventdata.subStatus: 0xc0000072
```

With time range

![](Pasted%20image%2020231229195445.png)

Specific user:

```
data.win.system.eventID: 4625 and data.win.eventdata.targetUserName: a.rofl
```

Specific time:

```
data.win.system.eventID: 4624 and data.win.eventdata.targetUserName: sugo and data.win.system.systemTime:     "2023-12-29T20:11:00.629985900Z"
```

Get a list of indexes:

```bash
root@videodrome:~# curl -k "https://192.168.81.4:9200/_cat/indices" -u admin:XXXXXXXXXXX
green open wazuh-alerts-4.x-2023.05.25            s-BOcZL9T6Kh4N_1o7KfrQ 3 0 6376242 0    3.5gb    3.5gb
green open wazuh-alerts-4.x-2023.05.26            LBIx5hfKSsy7L36Dv7qcow 3 0 5120565 0    2.3gb    2.3gb
green open wazuh-alerts-4.x-2023.05.27            GDRdGRHpQd-m3uvx5T_d2w 3 0 4538891 0    1.6gb    1.6gb
green open wazuh-alerts-4.x-2023.05.28            8a6N0XbpT2Gf-6eNmoEBHg 3 0 4667609 0    1.6gb    1.6gb
green open wazuh-alerts-4.x-2023.11.28            H4uLmyeqRA2B3xy7IGwqYQ 3 0 1356142 0  931.9mb  931.9mb
green open wazuh-alerts-4.x-2023.05.29            vpLbbvLzRfOnfgjRZoxZqg 3 0 4466111 0    1.7gb    1.7gb
green open wazuh-alerts-4.x-2023.11.29            BxyXHwprQje_EYhf2s1XZA 3 0  791692 0  666.4mb  666.4mb
green open wazuh-alerts-4.x-2023.05.20            D1JX-iaVSkubQJUh1PzDYQ 3 0 6620682 0    3.4gb    3.4gb
green open wazuh-alerts-4.x-2023.05.21            DPSevUUZSZC7WkJ02D9Vtg 3 0 6770025 0    3.3gb    3.3gb
..
..
..
```

Get latest 2 alerts (`size=2`) from a specific index (`wazuh-alerts-4.x-2023.11.28`)

```bash
root@videodrome:~# curl -k "https://192.168.81.4:9200/wazuh-alerts-4.x-2023.11.28/_search?pretty=true&size=2" -u admin:XXXXXX
{
  "took" : 1,
  "timed_out" : false,
  "_shards" : {
    "total" : 3,
    "successful" : 3,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 10000,
      "relation" : "gte"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "wazuh-alerts-4.x-2023.11.28",
        "_id" : "bk07E4wBl0sn2DHsE_qA",
        "_score" : 1.0,
        "_source" : {
          "agent" : {
            "ip" : "192.168.89.114",
            "name" : "ROFLOR-PC",
            "id" : "141"
          },
          "manager" : {
            "name" : "dune"
          },
          "data" : {
            "win" : {
              "eventdata" : {
                "param1" : "\\\\Device\\\\HarddiskVolume5\\\\ProgramData\\\\Cynet\\\\Amsi\\\\5.0.1.14\\\\x64\\\\AmsiProvider.dll"
              },
              "system" : {
                "eventID" : "5038",
..
..
```

Get a detail of a specific agent

```json
root@dune:~# curl -s -k 'https://localhost:55000/agents/?q=id=001' -H "Authorization: Bearer $TOKEN" | jq
{
  "data": {
    "affected_items": [
      {
        "os": {
          "build": "22621",
          "major": "10",
          "minor": "0",
          "name": "Microsoft Windows 11 Pro",
          "platform": "windows",
          "uname": "Microsoft Windows 11 Pro",
          "version": "10.0.22621.2861"
        },
        "mergedSum": "0ad90ffd0c6b8564a6ae04fe1ea6ccab",
        "ip": "FE80:0000:0000:0000:5D56:6F88:E932:DA0D",
        "manager": "dune",
        "version": "Wazuh v4.4.4",
        "registerIP": "any",
        "name": "ROLF-PC",
        "node_name": "node01",
        "group_config_status": "synced",
        "group": [
          "company",
          "company_workstation"
        ],
        "id": "001",
        "lastKeepAlive": "2023-12-29T19:29:00+00:00",
        "configSum": "dae1a43c7abb3a6ff80ea27383c78d09",
        "dateAdd": "2023-04-12T13:39:49+00:00",
        "status": "active"
      }
    ],
    "total_affected_items": 1,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All selected agents information was returned",
  "error": 0
}
```

Get a list of ALL agents

```bash
root@dune:~# curl -k 'https://localhost:55000/agents/?q=id!=000' -H "Authorization: Bearer $TOKEN" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 85733  100 85733    0     0  1272k      0 --:--:-- --:--:-- --:--:-- 1268k
{
  "data": {
    "affected_items": [
      {
        "os": {
          "build": "22621",
          "major": "10",
          "minor": "0",
          "name": "Microsoft Windows 11 Pro",
          "platform": "windows",
          "uname": "Microsoft Windows 11 Pro",
          "version": "10.0.22621.2861"
        },
        "mergedSum": "0ad90ffd0c6b8564a6ae04fe1ea6ccab",
        "ip": "FE80:0000:0000:0000:5D56:6F88:E932:DA0D",
        "manager": "dune",
        "version": "Wazuh v4.4.4",
        "registerIP": "any",
        "name": "ROFL-PC",
        "node_name": "node01",
        "group_config_status": "synced",
        "group": [
          "micso",
          "micso_workstation"
        ],
        "id": "001",
        "lastKeepAlive": "2023-12-29T19:24:00+00:00",
        "configSum": "dae1a43c7abb3a6ff80ea27383c78d09",
        "dateAdd": "2023-04-12T13:39:49+00:00",
        "status": "active"
..
..
..
```

Get a list of agent name (from JSON)

```bash
root@dune:/home/sugo# curl -s -k 'https://localhost:55000/agents/?q=id!=000' -H "Authorization: Bearer $TOKEN" | jq ' .data.affected_items[].name'
"ASD-PC"
"NB-LOL"
"dc1"
"NORMIS-NEWPC"
"EXCHANGE"
..
..
```

Return a list of multiple fields (eg. `name`, `group_config_status`)

```bash
root@dune:/home/sugo# curl -s -k 'https://localhost:55000/agents/?q=id!=000' -H "Authorization: Bearer $TOKEN" | jq ' .data.affected_items[] | "\(.name), \(.group_config_status)"'
"ROFL-PC, synced"
"NB-CATHY, synced"
"dc1, synced"
"MAURYS-NEWPC, not synced"
..
..
```

KQL (Kibana Query Language) query to exclude computer accounts (`HOSTNAME$`):

```shell-session
NOT user.name: *$ AND winlog.channel.keyword: Security
```



