"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'disable_user_1' block
    disable_user_1(container=container)

    return

@phantom.playbook_block()
def disable_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("disable_user_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_user = phantom.collect2(container=container, datapath=["playbook_input:user"])

    parameters = []

    # build parameters list for 'disable_user_1' call
    for playbook_input_user_item in playbook_input_user:
        if playbook_input_user_item[0] is not None:
            parameters.append({
                "user_id": playbook_input_user_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("disable user", parameters=parameters, name="disable_user_1", assets=["azure_ad"], callback=mark_evidence_1)

    return


@phantom.playbook_block()
def mark_evidence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_evidence_1() called")

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

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_1", callback=disable_tokens_1)

    return


@phantom.playbook_block()
def disable_tokens_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("disable_tokens_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_user = phantom.collect2(container=container, datapath=["playbook_input:user"])

    parameters = []

    # build parameters list for 'disable_tokens_1' call
    for playbook_input_user_item in playbook_input_user:
        if playbook_input_user_item[0] is not None:
            parameters.append({
                "user_id": playbook_input_user_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("disable tokens", parameters=parameters, name="disable_tokens_1", assets=["azure_ad"], callback=mark_evidence_2)

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

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_2")

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