"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_2' block
    filter_2(container=container)

    return

@phantom.playbook_block()
def block_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_hash_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_hash = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:playbook_input:hash"])

    parameters = []

    # build parameters list for 'block_hash_1' call
    for filtered_input_0_hash_item in filtered_input_0_hash:
        if filtered_input_0_hash_item[0] is not None:
            parameters.append({
                "hash": filtered_input_0_hash_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block hash", parameters=parameters, name="block_hash_1", assets=["carbon black"], callback=mark_evidence_2)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["block_hash_1:action_result.status", "==", "success"]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        indicator_tag_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def indicator_tag_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_tag_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:block_hash_1:action_result.parameter.hash"])

    parameters = []

    # build parameters list for 'indicator_tag_1' call
    for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
        parameters.append({
            "tags": "blocked",
            "indicator": filtered_result_0_item_filter_1[0],
            "overwrite": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="indicator_tag_1")

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:hash", "!=", ""]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def mark_evidence_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_evidence_2() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container": id_value,
        "content_type": "action_run_id",
        "input_object": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []

    parameters.append({
        "container": id_value,
        "input_object": results,
        "content_type": "action_run_id",
    })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_2", callback=filter_1)

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