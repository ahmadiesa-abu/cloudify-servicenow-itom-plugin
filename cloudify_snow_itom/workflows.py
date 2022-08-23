import sys
import time

from requests import (Request,
                      Session,
                      HTTPError,
                      ConnectionError,
                      RequestException)
from requests.auth import HTTPBasicAuth

from cloudify.decorators import workflow
from cloudify.exceptions import NonRecoverableError
from cloudify.utils import exception_to_error_cause

from .constants import (CCG_API_PATTERN,
                        DISCOVREY_API_PATTERN)
from .discovery_extractors import construct_discovery_payload
from .ccgscan_extractors import construct_ccg_scan_payload


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


def retrieve_scan_run_results(ctx, snow_host, snow_auth, payload):
    url = CCG_API_PATTERN.format(host=snow_host,
                                 method='retrieve_scan_results')

    response = _make_request_call("POST", url, payload, snow_auth)

    responseObj = response.json()

    ctx.logger.info('Scan_run_results {0}'.format(responseObj))


def run_pointed_discovery(ctx, snow_host, snow_auth, payload):
    url = DISCOVREY_API_PATTERN.format(host=snow_host,
                                       method='run_pointed_discovery')

    response = _make_request_call("POST", url, payload, snow_auth)

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
            raise NonRecoverableError("No valid authentication data provided.")

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
            retrieve_scan_run_results(ctx, snow_host, snow_auth, scan_payload)
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
            raise NonRecoverableError("No valid authentication data provided.")

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

        ctx.logger.debug("run_pointed_discovery {0}".format(discovery_result))

    except Exception:
        _, exc_value, exc_traceback = sys.exc_info()
        ctx.logger.error(
            'Error Occured while triggering itom_discovery {0}'.format(
                exception_to_error_cause(exc_value, exc_traceback)))
