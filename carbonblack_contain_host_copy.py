"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'quarantine_device_1' block
    quarantine_device_1(container=container)

    return

@phantom.playbook_block()
def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("quarantine_device_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_host = phantom.collect2(container=container, datapath=["playbook_input:host"])

    parameters = []

    # build parameters list for 'quarantine_device_1' call
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

    phantom.act("quarantine device", parameters=parameters, name="quarantine_device_1", assets=["carbon black"], callback=success_filteer)

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

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_1", callback=tag_contained)

    return


@phantom.playbook_block()
def success_filteer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("success_filteer() called")

    ################################################################################
    # Filter on succesful quarantine actions
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["quarantine_device_1:action_result.status", "==", "success"]
        ],
        name="success_filteer:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        mark_evidence_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def tag_contained(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_contained() called")

    filtered_result_0_data_success_filteer = phantom.collect2(container=container, datapath=["filtered-data:success_filteer:condition_1:quarantine_device_1:action_result.parameter.ip_hostname"])

    parameters = []

    # build parameters list for 'tag_contained' call
    for filtered_result_0_item_success_filteer in filtered_result_0_data_success_filteer:
        parameters.append({
            "tags": "contained",
            "indicator": filtered_result_0_item_success_filteer[0],
            "overwrite": False,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_contained")

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