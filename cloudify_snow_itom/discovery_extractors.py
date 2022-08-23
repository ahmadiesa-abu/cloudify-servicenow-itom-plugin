from requests import (Request,
                      Session,
                      HTTPError,
                      ConnectionError,
                      RequestException)

from cloudify import manager
from cloudify.exceptions import NonRecoverableError

from .constants import (TABLE_API_PATTEN, TERRAFORM_MAPPINGS,
                        CLOUDIFY_MAPPINGS)


def check_if_type_supported(snow_host, snow_auth, rtype):
    url = TABLE_API_PATTEN.format(host=snow_host,
                                  tableName='sn_capi_resource_type')
    req = Request("GET",
                  url,
                  params={"name": rtype},
                  auth=snow_auth)

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
    if len(response.json().get('result', [])) > 0:
        # return True
        if response.json().get('result')[0].get('pattern', ''):
           return True
    return False


def extract_cfn_resources(snow_host, snow_auth, node_instance, region):
    resource_ids = []
    resources = node_instance.get('runtime_properties', {}).get('state')
    for resource in resources:
        rtype = resource.get('ResourceType')
        if check_if_type_supported(snow_host, snow_auth, rtype):
            resource_ids.append({
                "resource_id": resource.get("PhysicalResourceId"),
                "resource_type": rtype,
                "region": region,
                "cloud_type": "AWS",
            })

    return resource_ids


def extract_arm_resources(snow_host, snow_auth, node_instance, region):
    resource_ids = []
    resource = node_instance.get('runtime_properties', {}).get('resource', {})
    rtype = resource.get('type')
    if check_if_type_supported(snow_host, snow_auth, rtype):
        resource_ids.append({
            "resource_id": resource.get("id"),
            "resource_type": rtype,
            "region": region,
            "cloud_type": "AZURE",
        })
    dependencies = resource.get("properties", {}).get('dependencies', [])
    for dependency in dependencies:
        rtype = dependency.get('resource_type')
        if check_if_type_supported(snow_host, snow_auth, rtype):
            resource_ids.append({
                "resource_id": dependency.get("id"),
                "resource_type": rtype,
                "region": region,
                "cloud_type": "AZURE",
            })
        depends_on = dependency.get('depends_on', [])
        for dep in depends_on:
            rtype = dep.get('resource_type')
            if check_if_type_supported(snow_host, snow_auth, rtype):
                resource_ids.append({
                    "resource_id": dep.get("id"),
                    "resource_type": rtype,
                    "region": region,
                    "cloud_type": "AZURE",
                })

    return resource_ids


def extract_terraform_resources(snow_host, snow_auth, node_instance, region):
    resource_ids = []
    valid_region = ''
    resources = node_instance.get('runtime_properties', {}).get('resources',
                                                                {})
    for name, resource in resources.items():
        rtype = TERRAFORM_MAPPINGS.get(resource.get('type'))
        if not rtype:
            continue
        cloud_type = ""
        if 'Microsoft' in rtype:
            cloud_type = "AZURE"
        elif 'AWS' in rtype:
            cloud_type = "AWS"
        if check_if_type_supported(snow_host, snow_auth, rtype):
            for instance in resource.get("instances", []):
                attributes = instance.get("attributes", {})
                if cloud_type == 'AWS' and "availability_zone" in attributes:
                    region = attributes.get("availability_zone")[:-1]
                elif cloud_type == 'AZURE' and "location" in attributes:
                    region = attributes.get("location")
                if not valid_region and region:
                    valid_region = region
                resource_ids.append({
                    "resource_id": attributes.get("id"),
                    "resource_type": rtype,
                    "region": region,
                    "cloud_type": cloud_type,
                })
    # fix up region for some resources that doesn't have
    # the property from terraform resource json
    for resource in resource_ids:
        if not resource.get('region', ''):
            resource['region'] = valid_region

    return resource_ids


def extract_azure_resource(snow_host, snow_auth, node_instance, region):
    resource = node_instance.get('runtime_properties', {}).get('resource', {})
    rtype = resource.get('type')
    if not rtype:
        return {}
    if check_if_type_supported(snow_host, snow_auth, rtype):
        return {
            "resource_id": resource.get("id"),
            "resource_type": rtype,
            "region": region,
            "cloud_type": "AZURE",
        }

    return {}


def extract_aws_resource(snow_host, snow_auth, node_instance, rtype, region):
    rtype = CLOUDIFY_MAPPINGS.get('AWS').get(rtype)
    if not rtype:
        return {}
    resource = node_instance.get("runtime_properties", {})
    if check_if_type_supported(snow_host, snow_auth, rtype):
        return {
            "resource_id": resource.get("aws_resource_id"),
            "resource_type": rtype,
            "region": region,
            "cloud_type": "AWS",
        }

    return {}


def construct_discovery_payload(snow_host,
                                snow_auth,
                                deployment_id,
                                service_account_ids):
    payload = {'discovery_configuration': []}

    cfy_client = manager.get_rest_client()

    nodes = cfy_client.nodes.list(
        deployment_id=deployment_id,
        _include=['id', 'type', 'type_hierarchy', 'deployment_id',
                  'properties'],
        evaluate_functions=True)

    node_instances = cfy_client.node_instances.list(
        deployment_id=deployment_id,
        _include=['id', 'node_id', 'runtime_properties'])

    azure_types = CLOUDIFY_MAPPINGS.get('AZURE').keys()
    aws_types = CLOUDIFY_MAPPINGS.get('AWS').keys()
    supported_types = list(azure_types | aws_types)
    supported_types.append('cloudify.nodes.terraform.Module')

    resource_ids = []
    for node in nodes:
        if any(x in node.get('type_hierarchy') for x in supported_types):
            node_properties = node.get('properties', {})
            node_type = node.get('type')
            # AWS region
            region = node_properties.get('client_config',
                                         {}).get('region_name')
            # Azure region if not AWS
            region = region or node_properties.get('location')
            for node_instance in node_instances:
                if node_instance.get('node_id') != node.get('id'):
                    continue
                if node_type.find('aws') > -1:
                    if node_type != 'cloudify.nodes.aws.CloudFormation.Stack':
                        resource_id = extract_aws_resource(snow_host,
                                                           snow_auth,
                                                           node_instance,
                                                           node_type,
                                                           region)
                        if resource_id:
                            resource_ids.append(resource_id)
                    else:
                        cfn_resources = extract_cfn_resources(snow_host,
                                                              snow_auth,
                                                              node_instance,
                                                              region)
                        if cfn_resources:
                            resource_ids.extend(cfn_resources)
                elif node_type.find('azure') > -1:
                    if node_type != 'cloudify.azure.Deployment':
                        resource_id = extract_azure_resource(snow_host,
                                                             snow_auth,
                                                             node_instance,
                                                             region)
                        if resource_id:
                            resource_ids.append(resource_id)
                    else:
                        arm_resources = extract_arm_resources(snow_host,
                                                              snow_auth,
                                                              node_instance,
                                                              region)
                        if arm_resources:
                            resource_ids.extend(arm_resources)
                elif node_type == 'cloudify.nodes.terraform.Module':
                    terraform_resources = \
                        extract_terraform_resources(snow_host,
                                                    snow_auth,
                                                    node_instance,
                                                    region)
                    if terraform_resources:
                        resource_ids.extend(terraform_resources)

    for resource in resource_ids:
        cloud_type = resource.get("cloud_type")
        region = resource.get("region")
        resource_type = resource.get("resource_type")
        resource_id = resource.get("resource_id")
        if not resource_id:
            continue
        discovery_configuration = {
            "logical_datacenter": region,
            "cloud_type": cloud_type
        }
        if cloud_type in service_account_ids:
            service_account_id = service_account_ids[cloud_type]
        else:
            raise NonRecoverableError(
                "service_account_ids don't have {0} ".format(cloud_type))
        discovery_configuration["service_account_id"] = service_account_id
        discovery_configuration["resource_type"] = resource_type
        discovery_configuration["resource_id"] = resource_id
        payload["discovery_configuration"].append(
            discovery_configuration)
    return payload
