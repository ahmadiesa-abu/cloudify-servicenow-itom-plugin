from cloudify import manager
from cloudify.exceptions import NonRecoverableError

from .constants import (AZURE_REGIONS,
                        CLOUDIFY_MAPPINGS,
                        TERRAFORM_MAPPINGS)

SUPPORTED_TYPES = [
    'AWS::EC2::Instance',
    'Microsoft.Compute/virtualMachines',
]


def check_if_type_supported(rtype):
    return rtype in SUPPORTED_TYPES


def extract_cfn_resources(node_instance, region):
    resource_ids = []
    resources = node_instance.get('runtime_properties', {}).get('state')
    for resource in resources:
        rtype = resource.get('ResourceType')
        if check_if_type_supported(rtype):
            resource_ids.append({
                "resource_id": resource.get("PhysicalResourceId"),
                "resource_type": rtype,
                "region": region,
                "cloud_type": "AWS",
            })

    return resource_ids


def extract_arm_resources(node_instance, region):
    resource_ids = []
    resource = node_instance.get('runtime_properties', {}).get('resource', {})
    rtype = resource.get('type')
    if check_if_type_supported(rtype):
        resource_ids.append({
            "resource_id": resource.get("id"),
            "resource_type": rtype,
            "region": region,
            "cloud_type": "AZURE",
        })
    dependencies = resource.get("properties", {}).get('dependencies', [])
    for dependency in dependencies:
        rtype = dependency.get('resource_type')
        if check_if_type_supported(rtype):
            resource_ids.append({
                "resource_id": dependency.get("id"),
                "resource_type": rtype,
                "region": region,
                "cloud_type": "AZURE",
            })
        depends_on = dependency.get('depends_on', [])
        for dep in depends_on:
            rtype = dep.get('resource_type')
            if check_if_type_supported(rtype):
                resource_ids.append({
                    "resource_id": dep.get("id"),
                    "resource_type": rtype,
                    "region": region,
                    "cloud_type": "AZURE",
                })

    return resource_ids


def extract_terraform_resources(node_instance, region):
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
        if check_if_type_supported(rtype):
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


def extract_azure_resource(node_instance, region):
    resource = node_instance.get('runtime_properties', {}).get('resource', {})
    rtype = resource.get('type')
    if not rtype:
        return {}
    if check_if_type_supported(rtype):
        return {
            "resource_id": resource.get("id"),
            "resource_type": rtype,
            "region": region,
            "cloud_type": "AZURE",
        }

    return {}


def extract_aws_resource(node_instance, rtype, region):
    rtype = CLOUDIFY_MAPPINGS.get('AWS').get(rtype)
    if not rtype:
        return {}
    resource = node_instance.get("runtime_properties", {})
    if check_if_type_supported(rtype):
        return {
            "resource_id": resource.get("aws_resource_id"),
            "resource_type": rtype,
            "region": region,
            "cloud_type": "AWS",
        }

    return {}


def construct_ccg_scan_payload(deployment_id,
                               service_account_ids,
                               policy_sets):
    payload = {'scan_configuration': []}

    cfy_client = manager.get_rest_client()

    nodes = cfy_client.nodes.list(
        deployment_id=deployment_id,
        _include=['id', 'type', 'type_hierarchy', 'deployment_id',
                  'properties'],
        evaluate_functions=True)

    node_instances = cfy_client.node_instances.list(
        deployment_id=deployment_id,
        _include=['id', 'node_id', 'runtime_properties'])

    supported_types = []
    SUPPORTED_AWS_TYPES = [
        "cloudify.nodes.terraform.Module",
        "cloudify.nodes.aws.ec2.Instances",
        "cloudify.nodes.aws.CloudFormation.Stack"]

    SUPPORTED_AZURE_TYPES = [
        "cloudify.azure.Deployment",
        "cloudify.nodes.terraform.Module",
        "cloudify.azure.nodes.compute.VirtualMachine",
        "cloudify.nodes.azure.compute.VirtualMachine"]

    if "AWSVM" in policy_sets:
        supported_types.extend(SUPPORTED_AWS_TYPES)

    if "AZUREVM" in policy_sets:
        supported_types.extend(SUPPORTED_AZURE_TYPES)

    supported_types = list(set(supported_types))

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
                        resource_id = extract_aws_resource(node_instance,
                                                           node_type,
                                                           region)
                        if resource_id:
                            resource_ids.append(resource_id)
                    else:
                        cfn_resources = extract_cfn_resources(node_instance,
                                                              region)
                        if cfn_resources:
                            resource_ids.extend(cfn_resources)
                elif node_type.find('azure') > -1:
                    if node_type != 'cloudify.azure.Deployment':
                        resource_id = extract_azure_resource(node_instance,
                                                             region)
                        if resource_id:
                            resource_ids.append(resource_id)
                    else:
                        arm_resources = extract_arm_resources(node_instance,
                                                              region)
                        if arm_resources:
                            resource_ids.extend(arm_resources)
                elif node_type == 'cloudify.nodes.terraform.Module':
                    terraform_resources = \
                        extract_terraform_resources(node_instance,
                                                    region)
                    if terraform_resources:
                        resource_ids.extend(terraform_resources)

    for resource in resource_ids:
        cloud_type = resource.get("cloud_type")
        region = resource.get("region")
        # in case of azure we need to get name from mapping
        if cloud_type == 'AZURE':
            region = AZURE_REGIONS.get(resource.get("region"),
                                       resource.get("region"))
        resource_id = resource.get("resource_id")
        if not resource_id:
            continue
        resource_type = resource.get("resource_type")
        for scan_config in payload.get("scan_configuration", []):
            if region == scan_config.get("logical_datacenter"):
                scan_config.get("resource_ids", []).append(resource_id)
                break
        else:
            scan_configuration = {
                "service_account_name": "",
                "logical_datacenters": [region],
                "logical_datacenter": region,
                "mid_server": "",
                "use_mid": False,
            }
            if cloud_type in service_account_ids:
                service_account_id = service_account_ids[cloud_type]
            else:
                raise NonRecoverableError(
                    "service_account_ids don't have {0} ".format(cloud_type))
            scan_configuration["service_account_id"] = \
                service_account_id
            if "resource_ids" not in scan_configuration:
                scan_configuration["resource_ids"] = []
            scan_configuration["resource_ids"].append(resource_id)
            policy_set = \
                policy_sets.get('AWSVM') if 'AWS' in resource_type \
                else policy_sets.get('AZUREVM')
            scan_configuration["policy_sets"] = policy_set
            payload["scan_configuration"].append(
                scan_configuration)
    return payload
