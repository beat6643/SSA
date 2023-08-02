"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'unquarantine_device_1' block
    unquarantine_device_1(container=container)

    return

@phantom.playbook_block()
def unquarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("unquarantine_device_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_host = phantom.collect2(container=container, datapath=["playbook_input:host"])

    parameters = []

    # build parameters list for 'unquarantine_device_1' call
    for playbook_input_host_item in playbook_input_host:
        if playbook_input_host_item[0] is not None:
            parameters.append({
                "ip_hostname": playbook_input_host_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("unquarantine device", parameters=parameters, name="unquarantine_device_1", assets=["carbon black"], callback=success_filter)

    return


@phantom.playbook_block()
def mark_evidence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_evidence_1() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container": id_value,
        "content_type": "action_run_id",
        "input_object": filtered_results,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_1", callback=indicator_remove_tag_2)

    return


@phantom.playbook_block()
def indicator_remove_tag_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_remove_tag_2() called")

    filtered_result_0_data_success_filter = phantom.collect2(container=container, datapath=["filtered-data:success_filter:condition_1:unquarantine_device_1:action_result.parameter.ip_hostname"])

    parameters = []

    # build parameters list for 'indicator_remove_tag_2' call
    for filtered_result_0_item_success_filter in filtered_result_0_data_success_filter:
        parameters.append({
            "tags": "contained",
            "indicator": filtered_result_0_item_success_filter[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/indicator_remove_tag", parameters=parameters, name="indicator_remove_tag_2")

    return


@phantom.playbook_block()
def success_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("success_filter() called")

    ################################################################################
    # Filter on succesful unquarantine actions
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["unquarantine_device_1:action_result.status", "==", "success"]
        ],
        name="success_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        mark_evidence_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return