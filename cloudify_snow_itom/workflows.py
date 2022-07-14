import time

from requests import (Request,
                      Session,
                      HTTPError,
                      ConnectionError,
                      RequestException)
from requests.auth import HTTPBasicAuth

from cloudify import manager
from cloudify.decorators import workflow
from cloudify.exceptions import NonRecoverableError

from .constants import (AZURE_REGIONS,
                        CCG_API_PATTERN,
                        DISCOVERY_MAPPINGS,
                        DISCOVREY_API_PATTERN)


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


def construct_configuration_payload(ctx,
                                    deployment_id,
                                    service_account_ids,
                                    policy_sets,
                                    conf_type):

    def extract_resource_ids(node_instance,
                             node_type,
                             region,
                             policy_sets,
                             conf_type):
        resource_ids = []
        if node_type == 'cloudify.nodes.aws.CloudFormation.Stack':
            policy_set = policy_sets.get("AWSVM")
            resources = node_instance.get('runtime_properties',
                                          {}).get('state')
            for resource in resources:
                if 'AWS::EC2::Instance' in resource.get('ResourceType'):
                    resource_ids.append({
                        "resource_id": resource.get("PhysicalResourceId"),
                        "region": region,
                        "cloud_type": "AWS",
                        "policy_set": policy_set,
                    })

        elif node_type == 'cloudify.azure.Deployment':
            policy_set = policy_sets.get("AZUREVM")
            providers = node_instance.get('runtime_properties', {}).get(
                'resource', {}).get('properties', {}).get('providers')
            look_in_dependencies = False
            for provider in providers:
                if 'Microsoft.Compute' in provider.get('namespace'):
                    resource_types = provider.get("resource_types")
                    for resource_type in resource_types:
                        if 'virtualMachines' in resource_type.get(
                                "resource_type"):
                            look_in_dependencies = True
                            break
            if look_in_dependencies:
                dependencies = node_instance.get(
                    'runtime_properties', {}).get(
                    'resource', {}).get('properties', {}).get(
                    'dependencies')

                for dependency in dependencies:
                    if 'Microsoft.Compute/virtualMachines' \
                            in dependency.get("resource_type"):
                        resource_ids.append({
                            "resource_id": dependency.get("id"),
                            "region": region,
                            "cloud_type": "AZURE",
                            "policy_set": policy_set,
                        })

        elif node_type == 'cloudify.nodes.terraform.Module':
            resources = node_instance.get('runtime_properties',
                                          {}).get('resources')

            for name, resource in resources.items():
                if 'aws_instance' in resource.get('type'):
                    instances = resource.get('instances')
                    policy_set = policy_sets.get("AWSVM")
                    for instance in instances:
                        attributes = instance.get('attributes')
                        resource_ids.append({
                            "resource_id": attributes.get("id"),
                            "region": attributes.get(
                                "availability_zone")[:-1],
                            "cloud_type": "AWS",
                            "policy_set": policy_set,
                        })
                elif 'azure' in resource.get('type') \
                        and 'virtual_machine' in resource.get('type'):
                    instances = resource.get('instances')
                    policy_set = policy_sets.get("AZUREVM")
                    for instance in instances:
                        attributes = instance.get('attributes')
                        if conf_type == 'scan':
                            region = AZURE_REGIONS.get(
                                attributes.get("location"))
                        elif conf_type == 'discovery':
                            region = attributes.get("location")
                        resource_ids.append({
                            "resource_id": attributes.get("id"),
                            "region": region,
                            "cloud_type": "AZURE",
                            "policy_set": policy_set,
                        })

        return resource_ids

    cfy_client = manager.get_rest_client()
    payload = {}
    if conf_type == 'scan':
        payload['scan_configuration'] = []
    elif conf_type == 'discovery':
        payload['discovery_configuration'] = []

    nodes = cfy_client.nodes.list(
        deployment_id=deployment_id,
        _include=['id', 'type', 'type_hierarchy', 'deployment_id',
                  'properties'],
        evaluate_functions=True)

    node_instances = cfy_client.node_instances.list(
        deployment_id=deployment_id,
        _include=['id', 'node_id', 'runtime_properties'])

    policies = {}

    SUPPORTED_AWS_TYPES = [
        "cloudify.nodes.terraform.Module",
        "cloudify.nodes.aws.ec2.Instances",
        "cloudify.nodes.aws.CloudFormation.Stack"]

    SUPPORTED_AZURE_TYPES = [
        "cloudify.azure.Deployment",
        "cloudify.nodes.terraform.Module",
        "cloudify.azure.nodes.compute.VirtualMachine",
        "cloudify.nodes.azure.compute.VirtualMachine"]

    supported_types = []
    if conf_type == 'scan':

        if "AWSVM" in policy_sets:
            supported_types.extend(SUPPORTED_AWS_TYPES)

        if "AZUREVM" in policy_sets:
            supported_types.extend(SUPPORTED_AZURE_TYPES)

    elif conf_type == 'discovery':

        if "AWS" in service_account_ids:
            supported_types.extend(SUPPORTED_AWS_TYPES)

        if "AZURE" in service_account_ids:
            supported_types.extend(SUPPORTED_AZURE_TYPES)

    # remove duplicates
    supported_types = list(set(supported_types))

    for node in nodes:
        if any(x in node.get('type_hierarchy') for x in supported_types):
            node_properties = node.get('properties', {})
            node_type = node.get('type')
            if node_type in policies:
                policies[node_type] = policies[node_type]
            else:
                policies[node_type] = {}

            for node_instance in node_instances:
                resource_ids = []
                if node_instance.get('node_id') != node.get('id'):
                    continue

                if node_type.find('aws') > -1:
                    cloud_type = 'AWS'
                    region = node_properties.get('client_config',
                                                 {}).get('region_name')
                    policy_set = policy_sets.get("AWSVM")

                    if node_type == 'cloudify.nodes.aws.ec2.Instances':

                        resource_id = node_instance.get(
                            'runtime_properties', {}).get('aws_resource_id')

                    elif node_type == \
                            'cloudify.nodes.aws.CloudFormation.Stack':
                        resource_id = None
                        resource_ids = extract_resource_ids(node_instance,
                                                            node_type,
                                                            region,
                                                            policy_sets,
                                                            conf_type)

                elif node_type.find('azure') > -1:
                    cloud_type = 'AZURE'
                    if conf_type == 'scan':
                        region = AZURE_REGIONS.get(node_properties.get(
                            'location'))
                    elif conf_type == 'discovery':
                        region = node_properties.get('location')
                    policy_set = policy_sets.get("AZUREVM")

                    if node_type in (
                            'cloudify.azure.nodes.compute.VirtualMachine',
                            'cloudify.nodes.azure.compute.VirtualMachine'):
                        resource_id = node_instance.get(
                            'runtime_properties', {}).get('resource_id')

                    elif node_type == 'cloudify.azure.Deployment':
                        resource_id = None
                        resource_ids = extract_resource_ids(node_instance,
                                                            node_type,
                                                            region,
                                                            policy_sets,
                                                            conf_type)

                elif node_type == 'cloudify.nodes.terraform.Module':
                    resource_id = None
                    region = None
                    resource_ids = extract_resource_ids(node_instance,
                                                        node_type,
                                                        region,
                                                        policy_sets,
                                                        conf_type)

                if resource_ids:
                    for resource in resource_ids:
                        region = resource.get("region")
                        if region in policies[node_type]:
                            policies[node_type][region] = \
                                policies[node_type][region]
                        else:
                            policies[node_type][region] = []

                        policies[node_type][region].append({
                            "cloud_type": resource.get("cloud_type"),
                            "resource_id": resource.get("resource_id"),
                            "policy_set": resource.get("policy_set"),
                        })
                elif resource_id:
                    if region in policies[node_type]:
                        policies[node_type][region] = \
                            policies[node_type][region]
                    else:
                        policies[node_type][region] = []
                    policies[node_type][region].append({
                        "cloud_type": cloud_type,
                        "resource_id": resource_id,
                        "policy_set": policy_set,
                    })

    # ctx.logger.info('policies {0}'.format(policies))
    for policy_set, regions in policies.items():
        for region, resource_array in regions.items():
            if conf_type == 'scan':

                scan_configuration = {
                    "service_account_name": "",
                    "logical_datacenters": [region],
                    "logical_datacenter": region,
                    "mid_server": "",
                    "use_mid": False,
                }
                for resource in resource_array:
                    cloud_type = resource["cloud_type"]
                    resource_id = resource["resource_id"]
                    if not resource_id:
                        continue
                    if cloud_type in service_account_ids:
                        service_account_id = service_account_ids[cloud_type]
                    else:
                        raise NonRecoverableError(
                            "service_account_ids don't have {0} ".format(
                                cloud_type))
                    scan_configuration["service_account_id"] = \
                        service_account_id
                    if "resource_arns" not in scan_configuration:
                        scan_configuration["resource_arns"] = []
                    if "resource_ids" not in scan_configuration:
                        scan_configuration["resource_ids"] = []
                    scan_configuration["resource_arns"].append(resource_id)
                    scan_configuration["resource_ids"].append(resource_id)
                    if "policy_set" in resource:
                        scan_configuration["policy_sets"] = \
                            resource["policy_set"]

                payload["scan_configuration"].append(scan_configuration)
            elif conf_type == 'discovery':

                for resource in resource_array:
                    cloud_type = resource["cloud_type"]
                    discovery_configuration = {
                        "logical_datacenter": region,
                        "cloud_type": cloud_type
                    }
                    resource_id = resource["resource_id"]
                    if not resource_id:
                        continue
                    if cloud_type in service_account_ids:
                        service_account_id = service_account_ids[cloud_type]
                    else:
                        raise NonRecoverableError(
                            "service_account_ids don't have {0} ".format(
                                cloud_type))
                    discovery_configuration["service_account_id"] = \
                        service_account_id
                    discovery_configuration["resource_type"] = \
                        DISCOVERY_MAPPINGS.get(cloud_type)
                    discovery_configuration["resource_id"] = resource_id
                    payload["discovery_configuration"].append(
                        discovery_configuration)

    return payload


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

        payload = construct_configuration_payload(ctx,
                                                  deployment_id,
                                                  service_account_ids,
                                                  policy_sets,
                                                  'scan')
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
            retrieve_scan_run_status(ctx, snow_host, snow_auth, scan_run_ids)
            retrieve_scan_run_results(ctx, snow_host, snow_auth, scan_run_ids)
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

        payload = construct_configuration_payload(ctx,
                                                  deployment_id,
                                                  service_account_ids,
                                                  {},
                                                  'discovery')
        ctx.logger.info("payload {0}".format(payload))
        if not payload['discovery_configuration']:
            return

        discovery_result = run_pointed_discovery(ctx,
                                                 snow_host,
                                                 snow_auth,
                                                 payload)

        ctx.logger.debug("run_pointed_discovery {0}".format(discovery_result))

    except Exception as e:
        ctx.logger.error(
            'Error Occured while triggering itom_discovery {0}'.format(str(e)))
