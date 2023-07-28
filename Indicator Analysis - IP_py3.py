"""
This playbook processes IP addresses not in bogon_list and creates a task note for every indicator for review by the analyst
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
    
    # call 'check_ip_address' block
    check_ip_address(container=container)

    return

def check_ip_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_ip_address() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_ip", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_ip", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        ip_address_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
TODO:
add sourceAddress to destinationAddress and remove RFC 1918 addresses also
"""
def ip_address_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_address_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_ip", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_ip", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="ip_address_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_dedup_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_dedup_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['vt'], callback=reputation_format, name="ip_reputation")

    return

def whois_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_dedup_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_ip' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=whois_format, name="whois_ip")

    return

def whois_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_format() called')
    
    template = """%%
### Whois Registration of {0} : *Registered Date: {1}*

{2}

***Latest Registered:***
- Name: {3}
- City: {4}, State: {5}, Country: {6}
- Description: {7}
- Email: {8}
- Updated: {9}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "whois_ip:action_result.parameter.ip",
        "whois_ip:action_result.data.*.asn_date",
        "whois_ip:action_result.message",
        "whois_ip:action_result.data.*.nets.0.name",
        "whois_ip:action_result.data.*.nets.0.city",
        "whois_ip:action_result.data.*.nets.0.state",
        "whois_ip:action_result.data.*.nets.0.country",
        "whois_ip:action_result.data.*.nets.0.description",
        "whois_ip:action_result.data.*.nets.0.emails",
        "whois_ip:action_result.data.*.nets.0.updated",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="whois_format", separator=", ")

    join_format_13(container=container)

    return

def reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reputation_format() called')
    
    template = """%%
### VirusTotal Summary of {0}: *{1}, {2}*

*VTI link: https://www.virustotal.com/gui/ip-address/{0}*

Network: {3} - Owner: {4}, ASN: {5} 

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation:action_result.parameter.ip",
        "ip_reputation:action_result.message",
        "ip_reputation:action_result.data.*.verbose_msg",
        "ip_reputation:action_result.data.*.network",
        "ip_reputation:action_result.data.*.as_owner",
        "ip_reputation:action_result.data.*.asn",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reputation_format", separator=", ")

    join_format_13(container=container)

    return

def geolocation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_dedup_list:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=geolocate_format, name="geolocation")

    return

def geolocate_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_format() called')
    
    template = """%%
### Maxmind Geolocation of {0}: *{1}*, *{2}* 
Latitude: {3} Longitude: {4}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "geolocation:action_result.parameter.ip",
        "geolocation:action_result.data.*.continent_name",
        "geolocation:action_result.data.*.country_name",
        "geolocation:action_result.data.*.latitude",
        "geolocation:action_result.data.*.longitude",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="geolocate_format", separator=", ")

    join_format_13(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator Analysis - IP playbook.  Check logic and playbook parameters")

    container = phantom.get_container(container.get('id', None))

    return

def merge_dedup_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_dedup_list() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:ip_address_filter:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:ip_address_filter:condition_1:artifact:*.cef.sourceAddress'])

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
    phantom.custom_function(custom_function='local/drafts/list_merge_dedup_py3', parameters=parameters, name='merge_dedup_list', callback=merge_dedup_list_callback)

    return

def merge_dedup_list_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('merge_dedup_list_callback() called')
    
    geolocation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    whois_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    ip_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_13() called')
    
    template = """{0}  
{1}  
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_format:formatted_data",
        "whois_format:formatted_data",
        "reputation_format:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_13", separator=", ")

    add_note_5(container=container)

    return

def join_format_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_13() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['geolocation', 'whois_ip', 'ip_reputation']):
        
        # call connected block "format_13"
        format_13(container=container, handle=handle)
    
    return

def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_13')

    note_title = "IP Reputation Results"
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