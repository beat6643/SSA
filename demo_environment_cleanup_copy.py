"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_containers' block
    get_containers(container=container)

    return

def get_containers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_containers() called')
    
    input_parameter_0 = ""

    get_containers__delete_containers = None
    get_containers__delete_notables = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    url = phantom.build_phantom_rest_url('artifact') + '?_filter_name="Notable Artifact"&page_size=0'
    response = phantom.requests.get(url, verify=False).json()
    notable_dict = {}
    delete_container_list = []
    delete_notable_list = []
    get_containers__delete_containers = []
    get_containers__delete_notables = []
    
    if response['count'] > 0:
        for artifact in response['data']:
            risk_object = artifact['cef']['risk_object']
            orig_source = artifact['cef']['source']
            if (risk_object, orig_source) not in notable_dict.keys():
                notable_dict[(risk_object, orig_source)] =  {'create_time': artifact['create_time'], 
                                                             'container': artifact['container'], 
                                                             'event_id': artifact['cef']['event_id'], 
                                                             'source': artifact['cef']['source']}
            
            elif (risk_object, orig_source) in notable_dict.keys():
                if artifact['create_time'] > notable_dict[(risk_object, orig_source)]['create_time']:
                    delete_container_list.append(notable_dict[(risk_object, orig_source)]['container'])
                    delete_notable_list.append(notable_dict[(risk_object, orig_source)]['event_id'])
                    notable_dict[(risk_object, orig_source)] = {'create_time': artifact['create_time'], 
                                                     'container': artifact['container'], 
                                                     'event_id': artifact['cef']['event_id'], 
                                                     'source': artifact['cef']['source']}
                    
                elif artifact['create_time'] < notable_dict[(risk_object, orig_source)]['create_time']:
                    delete_container_list.append(artifact['container'])
                    delete_notable_list.append(artifact['cef']['event_id'])
                    
    for del_container, del_notable in zip(delete_container_list, delete_notable_list):
        url = phantom.build_phantom_rest_url('container', del_container)
        response = phantom.requests.get(url, verify=False).json()
        if response['status'] != 'closed' or response['status'] != 'open' or response['container_type'] != 'case' or response['owner'] != None:
            get_containers__delete_containers.append(del_container)
            get_containers__delete_notables.append(del_notable)

    phantom.debug(get_containers__delete_containers)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_containers:delete_containers', value=json.dumps(get_containers__delete_containers))
    phantom.save_run_data(key='get_containers:delete_notables', value=json.dumps(get_containers__delete_notables))
    delete_containers_decision(container=container)

    return

def delete_splunk_notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_splunk_notables() called')

    # collect data for 'delete_splunk_notables' call
    formatted_data_1 = phantom.get_format_data(name='format_notable_delete')

    parameters = []
    
    # build parameters list for 'delete_splunk_notables' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_set_status_1, name="delete_splunk_notables")

    return

def format_notable_delete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_notable_delete() called')
    
    template = """index=notable  | eval `get_event_id_meval`,rule_id=event_id 
| search event_id IN (
%%
\"{0}\" 
%%
)
| delete"""

    # parameter list for template variable replacement
    parameters = [
        "get_containers:custom_function:delete_notables",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_notable_delete", separator=", ")

    delete_splunk_notables(container=container)

    return

def delete_containers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_containers() called')
    
    get_containers__delete_containers = json.loads(phantom.get_run_data(key='get_containers:delete_containers'))

    ################################################################################
    ## Custom Code Start
    ################################################################################
    url = phantom.build_phantom_rest_url('container')
    for del_container in get_containers__delete_containers:
        url = phantom.build_phantom_rest_url('container', del_container)
        response = phantom.requests.delete(url, verify=False)
        phantom.debug(response.text)

    ################################################################################
    ## Custom Code End
    ################################################################################
    format_notable_delete(container=container)

    return

def delete_containers_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_containers_decision() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["get_containers:custom_function:delete_containers", "!=", []],
            ["get_containers:custom_function:delete_notables", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        delete_containers(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_set_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="Closed")

    return

def join_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_status_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['delete_splunk_notables']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_set_status_1_called', value='set_status_1')
        
        # call connected block "set_status_1"
        set_status_1(container=container, handle=handle)
    
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