# Splunk Searches to MITRE ATT&CK Navigation Layer
This script was created to assist in parsing a CSV list of Splunk rules and the associated MITRE techniques into a MITRE ATT&CK navigation layer. Using a REST query, you can export a list of Splunk rules and their annotations with the below search.

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| where match('action.correlationsearch.enabled', "1|[Tt]|[Tt][Rr][Uu][Ee]") 
| where disabled=0 
| rex field=action.correlationsearch.annotations max_match=0 "(?<temp_technique>T\d{4})(?!\.)" 
| rex field=action.correlationsearch.annotations max_match=0 "(?<temp_subtechnique>T\d{4}\.\d{3})"
| eval 
    techniques=coalesce(mvjoin(temp_technique, ","), ""),
    subtechniques=coalesce(mvjoin(temp_subtechnique, ","), "")
| fillnull value=""
| table title techniques subtechniques
```

This file can be passed to the script with the `-f` flag.
```
python Splunk-CSV-MITRE.py -f Splunk-Rules.csv 
```

The script will output a JSON file that can be imported into the MITRE ATT&CK Navigator. 
