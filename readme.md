# Splunk Searches to MITRE ATT&CK Navigation Layer
This script was created to assist in parsing out a CSV list of Splunk rules and the associated MITRE techniques into a MITRE ATT&CK navigation layer. Using a REST query, you can export a list of Splunk rules and their annotations (if using ES).

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| where match('action.correlationsearch.enabled', "1|[Tt]|[Tt][Rr][Uu][Ee]") 
| where disabled=0 
| eval actions=split(actions, ",") 
| table title mitre_technique action.correlationsearch.annotations
```

You'll then need to clean up the results so the exported CSV looks like
```
Title,MITRE Mapping,
Default Account Activity,"[""T1078"", ""T1078.001""]"
```
