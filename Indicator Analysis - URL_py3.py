"""
This playbook processes URLs not in bogon_list and creates a task note for every indicator for review by the analyst
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block




# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_urls' block
    check_urls(container=container)

    return

def check_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_urls() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
            ["artifact:*.cef.url", "!=", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        url_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def url_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.url", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="url_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['vt'], callback=url_reputation_format, name="url_reputation")

    return

def url_reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_format() called')
    
    template = """%%
### VirusTotal Summary of `{0}`: *{1}, {2}*

*VTI link: {3}*

Scan Date: *{4}*

** Scan Results **

| Scanner | Detected | Result |
| ---- | ---- | ---- |
| Kaspersky | {5} | {6} |
| BitDefender | {7} | {8} | 
| Google Safe Browsing: | {9} | {10} |
| AlienVault | {11} | {12} |
Sophos | {13} | {14} |
| Forcepoint ThreatSeeker: | {15} | {16} |
| ESET |  {17} | {18} |
| MalwareDomainList | {19} | {20} |
| Fortinet | {21} | {22} |

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation:action_result.parameter.url",
        "url_reputation:action_result.message",
        "url_reputation:action_result.data.*.verbose_msg",
        "url_reputation:action_result.data.*.permalink",
        "url_reputation:action_result.data.*.scan_date",
        "url_reputation:action_result.data.*.scans.Kaspersky.detected",
        "url_reputation:action_result.data.*.scans.Kaspersky.result",
        "url_reputation:action_result.data.*.scans.BitDefender.detected",
        "url_reputation:action_result.data.*.scans.BitDefender.result",
        "url_reputation:action_result.data.*.scans.Google Safebrowsing.detected",
        "url_reputation:action_result.data.*.scans.Google Safebrowsing.result",
        "url_reputation:action_result.data.*.scans.AlienVault.detected",
        "url_reputation:action_result.data.*.scans.AlienVault.result",
        "url_reputation:action_result.data.*.scans.Sophos.detected",
        "url_reputation:action_result.data.*.scans.Sophos.result",
        "url_reputation:action_result.data.*.scans.Forcepoint ThreatSeeker.detected",
        "url_reputation:action_result.data.*.scans.Forcepoint ThreatSeeker.result",
        "url_reputation:action_result.data.*.scans.ESET.detected",
        "url_reputation:action_result.data.*.scans.ESET.result",
        "url_reputation:action_result.data.*.scans.MalwareDomainList.detected",
        "url_reputation:action_result.data.*.scans.MalwareDomainList.result",
        "url_reputation:action_result.data.*.scans.Fortinet.detected",
        "url_reputation:action_result.data.*.scans.Fortinet.result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="url_reputation_format", separator=", ")

    join_format_14(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator analysis - URL playbook.  Check logic and playbook parameters")

    container = phantom.get_container(container.get('id', None))

    return

def hunt_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_url' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_url' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
            })

    phantom.act(action="hunt url", parameters=parameters, assets=['ha'], callback=url_hunt_format, name="hunt_url")

    return

def url_hunt_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_hunt_format() called')
    
    template = """%%
### Falcon Sandbox Summary of `{0}`: *{1}, {2} - {3}*
*Hybrid Analysis Link: https://hybrid-analysis.com/sample/{10}*

| Data| Result |
| --- | --- |
| VX family | {4} |
| Scan date | {5} |
| Name(s) | {6} |
| Environment | {7} |
| Type | {8} |
| sha1 | {9} |
| sha256 | {10} |
| Compromised Hosts | {11} |
| Domains | {12} |

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_url:action_result.parameter.url",
        "hunt_url:action_result.message",
        "hunt_url:action_result.data.*.verdict",
        "hunt_url:action_result.data.*.threat_score_verbose",
        "hunt_url:action_result.data.*.vx_family",
        "hunt_url:action_result.data.*.analysis_start_time",
        "hunt_url:action_result.data.*.submit_name",
        "hunt_url:action_result.data.*.environment",
        "hunt_url:action_result.data.*.type",
        "hunt_url:action_result.data.*.sha1",
        "hunt_url:action_result.data.*.sha256",
        "hunt_url:action_result.data.*.compromised_hosts",
        "hunt_url:action_result.data.*.domains",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="url_hunt_format", separator=", ")

    join_format_14(container=container)

    return

def merge_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_list() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:url_filter:condition_1:artifact:*.cef.requestURL'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/drafts/list_merge_dedup_py3", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/drafts/list_merge_dedup_py3', parameters=parameters, name='merge_list', callback=merge_list_callback)

    return

def merge_list_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('merge_list_callback() called')
    
    url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    hunt_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_14() called')
    
    template = """{0}  
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_format:formatted_data",
        "url_hunt_format:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_14", separator=", ")

    add_note_5(container=container)

    return

def join_format_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_14() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['url_reputation', 'hunt_url']):
        
        # call connected block "format_14"
        format_14(container=container, handle=handle)
    
    return

def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_14')

    note_title = "URL Reputation Results"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return