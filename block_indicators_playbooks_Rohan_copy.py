"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'block_hash_1' block
    block_hash_1(container=container)
    # call 'block_ip_1' block
    block_ip_1(container=container)

    return

@phantom.playbook_block()
def block_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_hash_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_hash = phantom.collect2(container=container, datapath=["playbook_input:hash"])

    parameters = []

    # build parameters list for 'block_hash_1' call
    for playbook_input_hash_item in playbook_input_hash:
        if playbook_input_hash_item[0] is not None:
            parameters.append({
                "hash": playbook_input_hash_item[0],
                "comment": "this is a bad hash",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block hash", parameters=parameters, name="block_hash_1", assets=["carbon black"], callback=block_hash_success)

    return


@phantom.playbook_block()
def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    parameters = []

    # build parameters list for 'block_ip_1' call
    for playbook_input_ip_item in playbook_input_ip:
        if playbook_input_ip_item[0] is not None:
            parameters.append({
                "ip": playbook_input_ip_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block ip", parameters=parameters, name="block_ip_1", assets=["zscaler"], callback=block_ip_success)

    return


@phantom.playbook_block()
def block_hash_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_hash_success() called")

    ################################################################################
    # block hash success
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["block_hash_1:action_result.status", "==", "success"]
        ],
        name="block_hash_success:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        indicator_tag_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def block_ip_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_ip_success() called")

    ################################################################################
    # block ip success
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["block_ip_1:action_result.status", "==", "success"]
        ],
        name="block_ip_success:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        indicator_tag_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def indicator_tag_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_tag_1() called")

    filtered_result_0_data_block_hash_success = phantom.collect2(container=container, datapath=["filtered-data:block_hash_success:condition_1:block_hash_1:action_result.parameter.hash"])

    parameters = []

    # build parameters list for 'indicator_tag_1' call
    for filtered_result_0_item_block_hash_success in filtered_result_0_data_block_hash_success:
        parameters.append({
            "indicator": filtered_result_0_item_block_hash_success[0],
            "tags": "blocked",
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="indicator_tag_1")

    return


@phantom.playbook_block()
def indicator_tag_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_tag_2() called")

    filtered_result_0_data_block_ip_success = phantom.collect2(container=container, datapath=["filtered-data:block_ip_success:condition_1:block_ip_1:action_result.parameter.ip"])

    parameters = []

    # build parameters list for 'indicator_tag_2' call
    for filtered_result_0_item_block_ip_success in filtered_result_0_data_block_ip_success:
        parameters.append({
            "indicator": filtered_result_0_item_block_ip_success[0],
            "tags": "blocked",
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="indicator_tag_2")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    block_ip_1_result_data = phantom.collect2(container=container, datapath=["block_ip_1:action_result.status"])
    block_hash_1_result_data = phantom.collect2(container=container, datapath=["block_hash_1:action_result.status"])

    block_ip_1_result_item_0 = [item[0] for item in block_ip_1_result_data]
    block_hash_1_result_item_0 = [item[0] for item in block_hash_1_result_data]

    output = {
        "note_content": block_ip_1_result_item_0,
        "note_title": ["Block Indicators Report"],
        "note_content_2": block_hash_1_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return