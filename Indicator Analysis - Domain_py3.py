"""
This playbook processes domains not in bogon_list and creates a task note for every indicator for review by the analyst
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
    
    # call 'check_domain' block
    check_domain(container=container)

    return

def check_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_domain() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.deviceDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dntdom", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sntdom", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceDnsDomain", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        domain_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def domain_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.deviceDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dntdom", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sntdom", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceDnsDomain", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="domain_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['vt'], callback=domain_reputation_format, name="domain_reputation")

    return

def domain_whois_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_whois_format() called')
    
    template = """%%
### Whois Registration of {0} : *Updated Date: {1}*

- Registrar: {2}
- Expiration: {3}
- Creation: {4}

----
%%"""

    # parameter list for template variable replacement
    parameters = [
        "whois_domain:action_result.parameter.domain",
        "whois_domain:action_result.data.*.updated_date",
        "whois_domain:action_result.data.*.registrar",
        "whois_domain:action_result.data.*.expiration_date",
        "whois_domain:action_result.data.*.creation_date",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_whois_format", separator=", ")

    join_format_16(container=container)

    return

def whois_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_domain' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_domain' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['whois'], callback=domain_whois_format, name="whois_domain")

    return

def domain_reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_format() called')
    
    template = """%%
### VirusTotal Summary of {0}: * {1}, {2}*

*VTI link: https://www.virustotal.com/gui/domain/{0}* 

| Category | Context |
| --- | --- | 
| Category |  {3} | 
| Alexa domain info | {4} |
| Alexa rank | {5} |
| TrendMicro category | {6} |
| BitDefender category | {7} |
| Forcepoint ThreatSeeker category | {8} | 
| Websense ThreatSeeker category | {9} | 
| Opera domain info | {10} |

** WHOIS: **

{11}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation:action_result.parameter.domain",
        "domain_reputation:action_result.message",
        "domain_reputation:action_result.data.*.verbose_msg",
        "domain_reputation:action_result.data.*.categories",
        "domain_reputation:action_result.data.*.Alexa domain info",
        "domain_reputation:action_result.data.*.Alexa rank",
        "domain_reputation:action_result.data.*.TrendMicro category",
        "domain_reputation:action_result.data.*.BitDefender category",
        "domain_reputation:action_result.data.*.Forcepoint ThreatSeeker category",
        "domain_reputation:action_result.data.*.Websense ThreatSeeker category",
        "domain_reputation:action_result.data.*.Opera domain info",
        "domain_reputation:action_result.data.*.whois",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_reputation_format", separator=", ")

    join_format_16(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator Analysis - Domain playbook.  Check logic and playbook parameters")

    container = phantom.get_container(container.get('id', None))

    return

def hunt_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_domain' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_domain' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="hunt domain", parameters=parameters, assets=['ha'], callback=domain_hunt_format, name="hunt_domain")

    return

def domain_hunt_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_hunt_format() called')
    
    template = """%%
### Falcon Sandbox Summary of {0}: *{1}*

*Hybrid Analysis Link: https://www.hybrid-analysis.com/search?query={0}*
- Malicious: {2}
- Suspicious: {3}
- Unknown: {4}
- No Verdict: {5}
- No Specific Threat: {6}
- Allow listed: {7}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_domain:action_result.parameter.domain",
        "hunt_domain:action_result.message",
        "hunt_domain:action_result.summary.found_by_verdict_name.malicious",
        "hunt_domain:action_result.summary.found_by_verdict_name.suspicious",
        "hunt_domain:action_result.summary.found_by_verdict_name.unknown",
        "hunt_domain:action_result.summary.found_by_verdict_name.no_verdict",
        "hunt_domain:action_result.summary.found_by_verdict_name.no_specific_threat",
        "hunt_domain:action_result.summary.found_by_verdict_name.whitelisted",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_hunt_format", separator=", ")

    join_format_16(container=container)

    return

def merge_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_list() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:domain_filter:condition_1:artifact:*.cef.sourceDnsDomain', 'filtered-data:domain_filter:condition_1:artifact:*.cef.destinationDnsDomain'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
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
    
    whois_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    domain_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    hunt_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_16() called')
    
    template = """{0}  
{1}  
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "domain_whois_format:formatted_data",
        "domain_reputation_format:formatted_data",
        "domain_hunt_format:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_16", separator=", ")

    add_note_7(container=container)

    return

def join_format_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_16() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['whois_domain', 'domain_reputation', 'hunt_domain']):
        
        # call connected block "format_16"
        format_16(container=container, handle=handle)
    
    return

def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_7() called')

    formatted_data_1 = phantom.get_format_data(name='format_16')

    note_title = "Domain Reputation Results"
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