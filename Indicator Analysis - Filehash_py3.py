"""
This playbook processes filehashes not in bogon_list and creates a task note for every indicator for review by the analyst
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
    
    # call 'check_fileHash' block
    check_fileHash(container=container)

    return

def check_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_fileHash() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
            ["artifact:*.cef.fileHashMd5", "!=", ""],
            ["artifact:*.cef.fileHashSha1", "!=", ""],
            ["artifact:*.cef.fileHashSha256", "!=", ""],
            ["artifact:*.cef.fileHashSha512", "!=", ""],
            ["artifact:*.cef.hash", "!=", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        fileHash_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def fileHash_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fileHash_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.fileHashMd5", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.fileHashSha1", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.fileHashSha256", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.fileHashSha512", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.hash", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="fileHash_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'hash': custom_function_results_item_1[0],
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['vt'], callback=reputation_format, name="file_reputation")

    return

def reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reputation_format() called')
    
    template = """%%
### VirusTotal Summary of {0}: *{1}, {2}*

*VTI link: {3}*

Scan Date: {4}
- sha1: {5}
- sha256: {6}

| Scanner | Detected | Result |
| ---- | ---- | ---- |
| CrowdStrike | {7} | {8} |
| Cylance | {9} | {10} |
| ESET | {11} | {12} |
| FireEye | {13} | {14} |
| MalwareBytes | {15} | {16} |
| McAfee | {17} | {18} | 
| McAfee Gateway | {19} | {20} |
| Microsoft | {21} | {22} |
| Symantec | {23} | {24} | 
| Sophos | {25} | {26}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation:action_result.parameter.hash",
        "file_reputation:action_result.message",
        "file_reputation:action_result.data.*.verbose_msg",
        "file_reputation:action_result.data.*.permalink",
        "file_reputation:action_result.data.*.scan_date",
        "file_reputation:action_result.data.*.sha1",
        "file_reputation:action_result.data.*.sha256",
        "file_reputation:action_result.data.*.scans.CrowdStrike.detected",
        "file_reputation:action_result.data.*.scans.CrowdStrike.result",
        "file_reputation:action_result.data.*.scans.Cylance.detected",
        "file_reputation:action_result.data.*.scans.Cylance.result",
        "file_reputation:action_result.data.*.scans.ESET-NOD32.detected",
        "file_reputation:action_result.data.*.scans.ESET-NOD32.result",
        "file_reputation:action_result.data.*.scans.FireEye.detected",
        "file_reputation:action_result.data.*.scans.FireEye.result",
        "file_reputation:action_result.data.*.scans.Malwarebytes.detected",
        "file_reputation:action_result.data.*.scans.Malwarebytes.result",
        "file_reputation:action_result.data.*.scans.McAfee.detected",
        "file_reputation:action_result.data.*.scans.McAfee.result",
        "file_reputation:action_result.data.*.scans.McAfee-GW-Edition.detected",
        "file_reputation:action_result.data.*.scans.McAfee-GW-Edition.result",
        "file_reputation:action_result.data.*.scans.Microsoft.detected",
        "file_reputation:action_result.data.*.scans.Microsoft.result",
        "file_reputation:action_result.data.*.scans.Symantec.detected",
        "file_reputation:action_result.data.*.scans.Symantec.result",
        "file_reputation:action_result.data.*.scans.Sophos.detected",
        "file_reputation:action_result.data.*.scans.Sophos.result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reputation_format", separator=", ")

    join_format_13(container=container)

    return

def hunt_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_hash' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_hash' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'hash': custom_function_results_item_1[0],
            })

    phantom.act(action="hunt hash", parameters=parameters, assets=['ha'], callback=hunt_hash_format, name="hunt_hash")

    return

def hunt_hash_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_hash_format() called')
    
    template = """%%
### Falcon Sandbox Summary of {0}: *{1}, {2} - {3}*

*Hybrid Analysis Link: https://hybrid-analysis.com/sample/{10}*

| Data| Result |
| --- | --- |
| VX family | {4} |
| Scan date |  {5} |
| Name(s) | {6} |
| Environment | {7} |
| Type | {8} | 
| sha1 | {9} | 
| sha256 | {10} | 
| imphash | {11} |
| ssdeep | {12} |

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_hash:action_result.parameter.hash",
        "hunt_hash:action_result.message",
        "hunt_hash:action_result.data.*.verdict",
        "hunt_hash:action_result.data.*.threat_score_verbose",
        "hunt_hash:action_result.data.*.vx_family",
        "hunt_hash:action_result.data.*.analysis_start_time",
        "hunt_hash:action_result.data.*.submit_name",
        "hunt_hash:action_result.data.*.environment",
        "hunt_hash:action_result.data.*.type",
        "hunt_hash:action_result.data.*.sha1",
        "hunt_hash:action_result.data.*.sha256",
        "hunt_hash:action_result.data.*.imphash",
        "hunt_hash:action_result.data.*.ssdeep",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="hunt_hash_format", separator=", ")

    join_format_13(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator Analysis - Filehash playbook.  Check logic and playbook parameters")

    container = phantom.get_container(container.get('id', None))

    return

"""
You may need to remove some hashes for the applications you are trying to use.  Like Anomali only use MD5/SHA1 for example.
"""
def merge_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_list() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:fileHash_filter:condition_1:artifact:*.cef.fileHash'])

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
    
    file_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    hunt_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_13() called')
    
    template = """{0}  
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "reputation_format:formatted_data",
        "hunt_hash_format:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_13", separator=", ")

    add_note_5(container=container)

    return

def join_format_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_13() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['file_reputation', 'hunt_hash']):
        
        # call connected block "format_13"
        format_13(container=container, handle=handle)
    
    return

def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_13')

    note_title = "File Reputation Results"
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