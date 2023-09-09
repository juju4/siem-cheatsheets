# SIEM/Logging query cheatsheet
Last updated: 2023/06/03

## Essential tables/partitions/index

|Platform | Howto |
|---------|-------|
|Azure KQL| `* | summarize count() by $table`|
|Elastic| `curl http://localhost:9200/_cat/indices?v`|
|Graylog|``|
|Splunk| `| tstats count where index=* by index`, `| tstats count WHERE index=* OR index=_* BY index,host`, `| eventcount summarize=false index=* | dedup index | fields index` |
|Sumologic| `* | count by _index`, `* | count by _sourceCategory`|

## Classical operators

* or/and

|Platform | Howto |
|---------|-------|
|Azure KQL|or/and (case-sensitive)|
|Graylog|or/and (case-insensitive)|
|Kibana|or/and (case-insensitive)|
|Splunk| OR/AND (case-sensitive)|
|Sumologic| or/and (case-insensitive)|

* not

|Platform | Howto |
|---------|-------|
|Azure KQL|`E | where a == "b"`|
|Graylog|`not`|
|Kibana| `not` (case-insensitive)|
|Splunk|`field!=value`|
|Sumologic|`!E`, `E | where a != b`|

* where

|Platform | Howto |
|---------|-------|
|Azure KQL|`E | where a == "b"`|
|Elastic| |
|Graylog|``|
|Splunk|`E | where a = b`|
|Sumologic|`E | where a = "b"`|

* count

|Platform | Howto |
|---------|-------|
|Azure KQL|`E | summarize count() by field`|
|Elastic| |
|Graylog|aggregation through views panel only|
|Splunk|`E | stats count BY field`|
|Sumologic|`E | count by field`|

* distinct count

|Platform | Howto |
|---------|-------|
|Azure KQL|`E | summarize dcount(field)`|
|Elastic| |
|Graylog|``|
|Splunk|``|
|Sumologic|`E | count_distinct(field)`|


* contains

|Platform | Howto |
|---------|-------|
|Azure KQL|`T | where field contains "word"`, has, startswith, endswith|
|Elastic| |
|Graylog|`field:/.*word.*/` `"word"`|
|Kibana|`field:*word*`|
|Splunk|`field=*word*` `"word"`|
|Sumologic|`field=*word*` `"word"`|

* limit

|Platform | Howto |
|---------|-------|
|Azure KQL|limit, take, top|
|Elastic||
|Graylog||
|Splunk|head, top|
|Sumologic|limit|

* wildcard extract, regex extract

|Platform | Howto |
|---------|-------|
|Azure KQL|`T | extend _ProcessName=extract('"process name": "(.*"', 1, ExtendedProperties)`, `T | extend _ProcessName=extract("$.process name", ExtendedProperties)`, parse_json|
|Elastic|[JSON processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/json-processor.html)|
|Graylog||
|Splunk|`source="some.log" Fatal | rex "(?i) msg=(?P[^,]+)"`, `source="some.log" | regex _raw=".*Fatal.*"`, [spath](https://docs.splunk.com/Documentation/Splunk/9.0.4/SearchReference/Spath), [JSON Functions](https://docs.splunk.com/Documentation/SCS/current/SearchReference/JSONFunctions)|
|Sumologic|parse, parse regex, parse json|

* time slicing

|Platform | Howto |
|---------|-------|
|Azure KQL|`T | summarize count() by bin(TimeGenerated, 1h), field`|
|Elastic| |
|Graylog||
|Splunk|`E | bin span=1hr _time | stats count by _time`, `E | timechart count span=1hr`|
|Sumologic|`E | timeslice 1h | count _timeslice,field`, `E | timeslice 1h | count _timeslice,field | transpose row _timeslice column field`|

* rename field

|Platform | Howto |
|---------|-------|
|Azure KQL|`T | project-rename new_column_name = column_name`|
|Elastic| |
|Graylog||
|Splunk|`E | rename field1 as field2`|
|Sumologic|`E | field1 as field2`|

* search by IP address
https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/ipv4-is-matchfunction
https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/ConditionalFunctions#cidrmatch.28.22X.22.2CY.29
https://help.sumologic.com/05Search/Search-Query-Language/Search-Operators/CIDR

* lookup csv, ASN, geolocation
https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/lookupoperator
https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/ipv4-lookup-plugin
https://github.com/rod-trent/SentinelKQL/blob/master/GEOIPLocation.txt
https://docs.splunk.com/Documentation/SplunkCloud/8.2.2202/SearchReference/Iplocation
https://help.sumologic.com/05Search/Search-Query-Language/Search-Operators/lookup
https://help.sumologic.com/05Search/Search-Query-Language/Search-Operators/ASN_Lookup
https://help.sumologic.com/05Search/Search-Query-Language/Search-Operators/Geo-Lookup

* case-sensitivity

|Platform | Howto |
|---------|-------|
|Azure KQL|`=~` (case insensitive), `==` (case sensitive)|
|Elastic| |
|Graylog||
|Splunk||
|Sumologic|first line case insensitive, case sensitive after pipe|

## Parsing

* Azure KQL: normalizing
https://docs.microsoft.com/en-us/azure/sentinel/normalization
* Elastic Common Schema
https://www.elastic.co/guide/en/ecs/current/index.html
* Splunk Common Information Model
https://docs.splunk.com/Documentation/CIM/5.1.1/User/Overview
* Sumologic: Core fields definition up to administrator (Field Extraction Rule aka FER), CSE normalized
https://help.sumologic.com/Cloud_SIEM_Enterprise/CSE_Schema/CSE_Normalized_Classification


## Metadata fields

Depending on platform, those may exist all the time or not.

|Platform | Howto |
|---------|-------|
|Azure KQL|$table, _ResourceId, SubscriptionId, Computer, * (full message), _TimeReceived, TimeGenerated, _IsBillable|
|Graylog||
|Kibana|@timestamp, _time, _index, _id|
|Splunk|index, source, _raw, _indextime, _time|
|Sumologic|_sourceCategory, _sourceHost, _index, _sourceName, _raw, _receipttime, _messagetime|

* https://docs.microsoft.com/en-us/azure/azure-monitor/logs/log-standard-columns
* https://docs.splunk.com/Documentation/Splunk/latest/Data/Aboutdefaultfields
* https://help.sumologic.com/05Search/Get-Started-with-Search/Search-Basics/Built-in-Metadata

## Field match

Before pipe
* Sumologic if Field Extraction Rule (FER): "key=value"
* Elastic, Graylog: "key:value"

After pipe
* Azure KQL: `where key == value`
* Sumologic: `where key = value`

Notes:
* field name case sensitive: Azure KQL
* field name case insensitive: Sumologic


## Full text search

* Before pipe

|Platform | Howto |
|---------|-------|
|Azure KQL|`search "word1" or "word2"`, `search in (T) "word"`|
|Graylog|`"word1" or "word2"`|
|Splunk|`"word1" OR "word2"`|
|Sumologic|`"word1" or "word2"`|

## Volume, eps
|Platform | Howto |
|---------|-------|
|Azure KQL|See Data collection health monitoring workbook|
|Graylog||
|Splunk|`index=_internal source=*metrics.log group=per_index_thruput | eval GB=kb/1024/1024 | timechart span=1d sum(GB) as GB | eval GB=round(GB,2)`, `| tstats count where index=* by  _time span=1s`|
|Sumologic|`_index=sumologic_volume`, `* | timeslice 1s | count _timeslice | min(_count), pct(_count,25), pct(_count,50), pct(_count,75), max(_count)`|
https://help.sumologic.com/Manage/Ingestion-and-Volume/Data_Volume_Index
https://help.sumologic.com/Manage/Ingestion-and-Volume/Data_Volume_Index/Log_and_Tracing_Data_Volume_Index

## Last seen
|Platform | Howto |
|---------|-------|
|Azure KQL|See Data collection health monitoring workbook, `T | summarize max(TimeGenerated)`|
|Graylog||
|Splunk|`| tstats latest(_time) as latest where (index=* earliest=-1mon@mon  latest=-0h@h) by index host source sourcetype | convert ctime(latest)`|
|Sumologic|`E | first(_messagetime) as last_seen1 | formatDate(fromMillis(last_seen1),"yyyy-MM-dd'T'HH:mm:ss.SSSZ") as last_seen`|

## Logs Audit
|Platform | Howto |
|---------|-------|
|Azure KQL|`LAQueryLogs` https://learn.microsoft.com/en-us/azure/sentinel/audit-sentinel-data|
|Elastic|<clustername>_audit.json file: https://www.elastic.co/guide/en/elasticsearch/reference/current/enable-audit-logging.html, https://www.elastic.co/guide/en/elasticsearch/reference/current/auditing-search-queries.html|
|Graylog||
|Splunk|`index=_audit` https://docs.splunk.com/Documentation/Splunk/9.0.4/Security/AuditSplunkactivity|
|Sumologic|`_view=sumologic_search_usage_per_query`, `index=sumologic_audit` https://help.sumologic.com/docs/manage/security/audit-index/|

## Sharing

Most of the time you can copy/paste the search query, but you may miss some settings like timeperiod.
Some tools allow to share query as shortcut code or url:

* Kibana: [url](https://www.elastic.co/guide/en/kibana/master/reporting-getting-started.html#share-a-direct-link)
* Sentinel: [url, query or email](https://azurecloudai.blog/2021/05/26/how-to-easily-share-your-azure-sentinel-queries-with-the-community/)
* Sumologic: [_code or url](https://help.sumologic.com/docs/search/get-started-with-search/search-basics/share-link-to-search/)

## Logs file import

Sometimes, you have raw text logs files to analyze and ideally in the same tools than live logs.
Most of the time it is possible to import text files aka csv or json. Some platform may even allow to load standalone evt/evtx files.
Depending on target tool, you may be able to send data to any index/table or not.

* Cribl
  * https://docs.cribl.io/stream/usecase-replay-s3
  * https://cribl.io/blog/replay-logstream-game-changer/
* Elasticsearch
  * https://www.elastic.co/blog/importing-csv-and-log-data-into-elasticsearch-with-file-data-visualizer
  * https://discuss.elastic.co/t/import-log-file-in-elasticsearch-and-kibana/156181/2
  * https://github.com/jadonn/elasticsearch-file-importer
  * https://github.com/janstarke/python-evtxtools
  * https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/
  * https://github.com/dgunter/evtxtoelk
  * https://github.com/sumeshi/evtx2es
* Sentinel: to a CustomLogs table only
  * https://learn.microsoft.com/en-us/azure/azure-monitor/agents/data-sources-custom-logs
  * https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/azure-sentinel-to-go-part1-a-lab-w-prerecorded-data-amp-a-custom/ba-p/1260191
  * https://github.com/Cyb3rWard0g/azure-loganalytics-api-clients/blob/master/python/ala-python-data-producer.py
* Splunk
  * https://docs.splunk.com/Documentation/Splunk/9.0.4/Data/Extractfieldsfromfileswithstructureddata
  * https://hurricanelabs.com/splunk-tutorials/ingesting-a-csv-file-into-splunk/
  * https://community.splunk.com/t5/Getting-Data-In/Why-is-my-sourcetype-not-parsing-as-CSV-and-am-getting-two/td-p/244469
  * https://michael-gale.medium.com/upload-files-into-splunk-through-the-api-6aa9ca912545
  * https://docs.splunk.com/Documentation/Splunk/9.0.4/Data/MonitorWindowseventlogdata#Index_exported_event_log_files
  * https://community.splunk.com/t5/Getting-Data-In/Windows-Event-Log-evtx-file-import-Foriegn-AD-Domain/m-p/557628
* Sumologic
  * https://help.sumologic.com/docs/send-data/installed-collectors/sources/local-file-source/
  * https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/logs-metrics/upload-logs/


## Data purging

If dev or testing environment, you may want to clear data fully or partially.
In production, that should never happens or nearly as else we may at risk of losing audit trail. At least, not without losing logs immutability/Write Once Read Many (WORM)/tampering protection. If possible, you still want to ensure proper backup and audit trail.

* Elasticsearch: `curl -XDELETE 0:9200/indexname-\*`, `curl -XDELETE 'http://localhost:9200/_all'`, `sudo so-elasticsearch-query 'so-elasticsearch-2023.01.01' -XDELETE`
  * https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-delete-index.html
  * https://discuss.elastic.co/t/delete-all-data-from-index-without-deleting-index/87661/8
  * https://docs.securityonion.net/en/2.3/so-elasticsearch-query.html#examples (not supporting wildcards)
* Sentinel
  * https://learn.microsoft.com/en-us/rest/api/loganalytics/workspace-purge/purge?tabs=HTTP
  * https://learn.microsoft.com/en-us/azure/azure-monitor/logs/personal-data-mgmt#how-to-export-and-delete-private-data
  * https://learn.microsoft.com/en-us/azure/sentinel/offboard
  * https://smsagent.blog/2022/01/06/purging-table-data-from-a-log-analytics-workspace/
* Splunk: `source="/fflanda/incoming/cheese.log" | delete`, `splunk clean eventdata -index <index_name>`
  * https://docs.splunk.com/Documentation/Splunk/9.0.4/Indexer/RemovedatafromSplunk
  * https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Howindexingworks
* Sumologic
  * https://support.sumologic.com/hc/en-us/articles/360034976954-Different-ways-to-purge-or-hide-sensitive-data-from-Sumo-Logic

## Quota and volume management

* Sentinel
  * [Set daily cap on Log Analytics workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/daily-cap), `_LogOperation | where Category =~ "Ingestion" | where Detail contains "OverQuota"`
* Sumologic
  * [Ingest Budgets](https://help.sumologic.com/docs/manage/ingestion-volume/ingest-budgets/), `_index=sumologic_audit _sourceName=VOLUME_QUOTA _sourceCategory=account_management "Budget"`

## References

* Azure KQL
  * https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference
  * https://techcommunity.microsoft.com/t5/azure-data-explorer/azure-data-explorer-kql-cheat-sheets/ba-p/1057404
  * https://techcommunity.microsoft.com/t5/azure-data-explorer/kql-cheat-sheets-quick-reference-official-page/ba-p/1203181
  * [Azure Data Explorer KQL cheat sheets, Dec 2019](https://techcommunity.microsoft.com/t5/azure-data-explorer-blog/azure-data-explorer-kql-cheat-sheets/ba-p/1057404), https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet.pdf
  * https://kloudspro.com/kusto-query-language-kql-cheatsheet/
  * https://github.com/MicrosoftDocs/dataexplorer-docs/blob/master/data-explorer/kusto/query/splunk-cheat-sheet.md
  * https://github.com/microsoft/Kusto-Query-Language
  * https://github.com/reprise99/awesome-kql-sentinel
  * https://github.com/rod-trent/MustLearnKQL
  * [Kusto Detective Agency](https://detective.kusto.io)
  * Examples: https://github.com/Azure/Azure-Sentinel, https://github.com/reprise99/Sentinel-Queries

* Elastic
  * [Kibana Query Language (KQL)](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
  * [Event Query Language (EQL) syntax reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html)
  * [Example: Detect threats with EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-ex-threat-detection.html)

* Graylog [Writing Search Queries](https://go2docs.graylog.org/5-1/making_sense_of_your_log_data/writing_search_queries.html
  * no standardize "schema"/_sourceCategory: application_name under linux vs @metadata_beat/win, source=hostname, event_provider=win event channels
  * `gl2_source_input:"608843ff98bb330cce5a5ea5" AND winlog_event_data_CommandLine:/powershell/`
  * `timestamp:["2020-08-01 00:00:00.000" TO "2020-09-01 00:00:00.000"]`
  * `source:"ACC\-05" && event_task_desc:"File created (rule: FileCreate)"`
  * `source:"ACC\-05" && event_id:11 && DEFCATZ`
  * `source:"ACC\-05" && log_source_name:Microsoft-Windows-Sysmon`
  * `event_type:zeek AND 31.7.109.216`

* Splunk [Welcome to the Search Reference](https://docs.splunk.com/Documentation/SplunkCloud/9.0.2303/SearchReference/WhatsInThisManual)
  * `index=*-win EventCode=1`
  * `index=attack  | top limit=200 "Test Name"`
  * `index=*-win EventCode=1 process_name!=splunk*.exe CommandLine=*Audio*`
  * `index=* sourcetype=bro* sourcetype="bro:x509:json" "CN=win-dc-748.attackrange.local" | stats count by certificate.subject, certificate.serialindex=* sourcetype=bro* sourcetype="bro:x509:json" "CN=win-dc-748.attackrange.local"`
  * https://gist.github.com/domanchi/12daa99ee023c4e9644ab56f14d21fd7
  * https://docs.google.com/spreadsheets/d/1RTcZsRbDsjxwmKpe3FIvSKUjBk5pR2Dlzj71QTnxAK0/edit#gid=0 Crowdstrike Splunk Threat Hunting Searches
  * https://github.com/pe3zx/crowdstrike-falcon-queries
  * https://www.splunk.com/en_us/blog/tips-and-tricks/how-to-determine-when-a-host-stops-sending-logs-to-splunk-expeditiously.html

* Sumologic
  * https://help.sumologic.com/05Search/Search-Cheat-Sheets/General-Search-Examples-Cheat-Sheet
  * https://help.sumologic.com/05Search/Search-Cheat-Sheets/Log-Operators-Cheat-Sheet
  * https://help.sumologic.com/05Search/Search-Cheat-Sheets/grep-to-Searching-with-Sumo-Cheat-Sheet
  * https://cheatography.com/tme520/cheat-sheets/sumo-logic/

## Glossary

* T: Table
* E: Expression
