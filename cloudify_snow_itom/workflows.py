import sys
import time

from requests import (get,
                      Request,
                      Session,
                      HTTPError,
                      ConnectionError,
                      RequestException)
from requests.auth import HTTPBasicAuth

from cloudify import manager
from cloudify.decorators import workflow
from cloudify.exceptions import NonRecoverableError
from cloudify.utils import exception_to_error_cause

from .constants import (CCG_API_PATTERN,
                        DISCOVREY_API_PATTERN,
                        CLOUDIFY_ACTIONS_API_PATTERN,
                        DISCOVERY_RESULT_PATTERN,
                        TABLE_API_PATTEN,
                        CCG_SCAN_RESULT_PATTERN)
from .discovery_extractors import construct_discovery_payload
from .ccgscan_extractors import construct_ccg_scan_payload


def get_deployment_labels(deployment_id):
    cfy_client = manager.get_rest_client()
    deployment = cfy_client.deployments.get(deployment_id)
    labels = deployment.labels or []
    return labels


def _make_request_call(method, url, payload, auth):

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    req = Request(method,
                  url,
                  json=payload,
                  headers=headers,
                  auth=auth)

    prepped = req.prepare()
    session = Session()

    try:
        response = session.send(prepped)
    except (RequestException, ConnectionError, HTTPError) as e:
        raise NonRecoverableError(
            'Exception raised: {0}'.format(str(e)))

    result = {
        'status_code': response.status_code,
        'body': response.request.body,
        'content': response.content
    }

    if not response.ok:
        raise NonRecoverableError(
            'Request failed: {0}'.format(result))

    return response


def get_ccg_scan_run_id(ctx, snow_host, snow_auth, scan_run):
    url = TABLE_API_PATTEN.format(host=snow_host,
                                  tableName='sn_itom_ccg_scan_run')
    PARAMS = {
        "number": scan_run
    }

    r = get(url = url,
            params = PARAMS, auth=snow_auth)

    result = r.json()
    ctx.logger.info('result {0}'.format(result))
    scan_run_id = result.get('result', [])[0].get('sys_id')
    return scan_run_id


def submit_scan_jobs(ctx, snow_host, snow_auth, payload):
    url = CCG_API_PATTERN.format(host=snow_host,
                                 method='submit_scan_jobs')

    response = _make_request_call("POST", url, payload, snow_auth)

    return response.json()


def retrieve_scan_run_status(ctx, snow_host, snow_auth, payload):
    url = CCG_API_PATTERN.format(host=snow_host,
                                 method='retrieve_scan_run_status')

    isComplete = False
    while not isComplete:
        response = _make_request_call("POST", url, payload, snow_auth)

        isComplete = True
        responseObj = response.json()
        for res in responseObj.get("result", []):
            if res.get("status") != 'Completed':
                isComplete = False
                break
        if not isComplete:
            time.sleep(5)

    # ctx.logger.info('Scan_run_status {0}'.format(responseObj))


def retrieve_scan_run_results(ctx, snow_host, snow_auth, payload, dep_id):
    url = CCG_API_PATTERN.format(host=snow_host,
                                 method='retrieve_scan_results')

    response = _make_request_call("POST", url, payload, snow_auth)

    responseObj = response.json()

    summary = responseObj.get('result', [])[0].get('Audit Result Summary')
    if len(summary) > 0:
        if summary[0].get('Count', 0) != 0:
            # let's get the scan_run
            scan_run = responseObj.get('result', [])[0].get('Scan Run')
            # we need to get the id , which we can use to formulate link
            scan_run_id = \
                    get_ccg_scan_run_id(ctx, snow_host, snow_auth, scan_run)
            link = CCG_SCAN_RESULT_PATTERN.format(host=snow_host,
                                                    record_id=scan_run_id)
            comment = '[code]<code><h3>Violating Resources</h3></br><p>'
            comment += '<a href="{link}">{scan_run}</a></p>'.format(
                link=link, scan_run=scan_run)
            comment += '</p></code>[/code]'
            dep_labels = get_deployment_labels(dep_id)
            is_snow = False
            req_item_number = ''
            for label in dep_labels:
                if label['key'] == 'created_from' \
                        and label['value'] == 'servicenow':
                    is_snow = True
                elif label['key'] == 'sn_ref_number':
                    req_item_number = label['value']
            if is_snow:
                payload = {
                    "requested_item": {
                        "requested_item_number": req_item_number,
                        "additional_comments": comment
                    }
                }
                update_request_item_comments(ctx, snow_host, snow_auth, 
                    payload)

    ctx.logger.info('Scan_run_results {0}'.format(responseObj))


def run_pointed_discovery(ctx, snow_host, snow_auth, payload):
    url = DISCOVREY_API_PATTERN.format(host=snow_host,
                                       method='run_pointed_discovery')

    response = _make_request_call("POST", url, payload, snow_auth)

    return response.json()


def update_request_item_comments(ctx, snow_host, snow_auth, payload):
    url = CLOUDIFY_ACTIONS_API_PATTERN.format(host=snow_host,
        method='update_requested_item_comments')

    response =  _make_request_call("POST", url, payload, snow_auth)

    return response.json()


@workflow
def trigger_ccg_scan(ctx,
                     deployment_id,
                     snow_host,
                     snow_username,
                     snow_password,
                     service_account_ids,
                     policy_sets,
                     **kwargs):
    try:
        if snow_username and snow_password:
            snow_auth = HTTPBasicAuth(snow_username, snow_password)
        else:
            raise NonRecoverableError(
                "No valid authentication data provided.")

        payload = construct_ccg_scan_payload(deployment_id,
                                             service_account_ids,
                                             policy_sets)
        ctx.logger.info("payload {0}".format(payload))
        if not payload['scan_configuration']:
            return

        submit_result = submit_scan_jobs(ctx, snow_host, snow_auth, payload)
        # ctx.logger.debug("submit_result {0}".format(submit_result))
        scan_runs = submit_result.get('result', {}).get('scan_runs', [])
        scan_run_ids = []
        for scan_run in scan_runs:
            scan_run_ids.append(scan_run.get('scan_number'))

        if scan_run_ids:
            scan_payload = {
                "scan_runs": scan_run_ids
            }
            retrieve_scan_run_status(ctx, snow_host, snow_auth, scan_payload)
            retrieve_scan_run_results(ctx, snow_host, snow_auth, scan_payload,
                deployment_id)
        else:
            raise NonRecoverableError('Scan run ids is empty')

    except Exception as e:
        ctx.logger.error(
            'Error Occured while triggering ccg_scan {0}'.format(str(e)))


@workflow
def trigger_itom_discovery(ctx,
                           deployment_id,
                           snow_host,
                           snow_username,
                           snow_password,
                           service_account_ids,
                           **kwargs):
    try:
        if snow_username and snow_password:
            snow_auth = HTTPBasicAuth(snow_username, snow_password)
        else:
            raise NonRecoverableError(
                "No valid authentication data provided.")

        payload = construct_discovery_payload(snow_host,
                                              snow_auth,
                                              deployment_id,
                                              service_account_ids)
        ctx.logger.info("payload {0}".format(payload))
        if not payload['discovery_configuration']:
            return

        discovery_result = run_pointed_discovery(ctx,
                                                 snow_host,
                                                 snow_auth,
                                                 payload)
        

        # the summary should contain comma seperated discovery result ids
        summary = discovery_result.get('result', {}).get('summary', '')
        resources = payload.get('discovery_configuration', [])
        if len(summary.split(','))>0:
            comment = '[code]<code><h3>Discovered Resources</h3></br><p><ul>'
            for idx, discovery_sys_id in enumerate(summary.split(',')):
                link = DISCOVERY_RESULT_PATTERN.format(host=snow_host,
                    record_id=discovery_sys_id)
                comment += '<li> <a href="{link}">{resource}</a>'.format(
                    link=link, resource=resources[idx].get('resource_id', 
                    idx))
            comment += '</ul></p></code>[/code]'
            dep_labels = get_deployment_labels(deployment_id)
            is_snow = False
            req_item_number = ''
            for label in dep_labels:
                if label['key'] == 'created_from' \
                        and label['value'] == 'servicenow':
                    is_snow = True
                elif label['key'] == 'sn_ref_number':
                    req_item_number = label['value']
            if is_snow:
                payload = {
                    "requested_item": {
                        "requested_item_number": req_item_number,
                        "additional_comments": comment
                    }
                }
                update_request_item_comments(ctx, snow_host, snow_auth, 
                    payload)

        ctx.logger.debug("run_pointed_discovery {0}".format(discovery_result))

    except Exception:
        _, exc_value, exc_traceback = sys.exc_info()
        ctx.logger.error(
            'Error Occured while triggering itom_discovery {0}'.format(
                exception_to_error_cause(exc_value, exc_traceback)))
