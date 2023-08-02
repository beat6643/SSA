"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Phish Email Artifact", "==", "artifact:*.name"]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        trace_email_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def trace_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("trace_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.cleanSenderEmail","filtered-data:filter_1:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'trace_email_1' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        parameters.append({
            "sender_address": filtered_artifact_0_item_filter_1[0],
            "context": {'artifact_id': filtered_artifact_0_item_filter_1[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("trace email", parameters=parameters, name="trace_email_1", assets=["office365"], callback=filter_2)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.decodedSubject", "==", "trace_email_1:action_result.data.*.trace_data.Subject"]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_query_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:trace_email_1:action_result.data.*.trace_data.RecipientAddress","filtered-data:filter_2:condition_1:trace_email_1:action_result.data.*.trace_data.MessageId"])

    parameters = []

    # build parameters list for 'run_query_1' call
    for filtered_result_0_item_filter_2 in filtered_result_0_data_filter_2:
        if filtered_result_0_item_filter_2[0] is not None:
            parameters.append({
                "email": filtered_result_0_item_filter_2[0],
                "range": "0-10",
                "folder": "Inbox",
                "internet_message_id": filtered_result_0_item_filter_2[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["office365"], callback=delete_email_1)

    return


@phantom.playbook_block()
def delete_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("delete_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.t_ItemId.@Id","run_query_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'delete_email_1' call
    for run_query_1_result_item in run_query_1_result_data:
        if run_query_1_result_item[0] is not None:
            parameters.append({
                "id": run_query_1_result_item[0],
                "context": {'artifact_id': run_query_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("delete email", parameters=parameters, name="delete_email_1", assets=["office365"])

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