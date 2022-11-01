CCG_API_PATTERN = \
    'https://{host}/api/sn_itom_ccg/cloud_configuration_scan/{method}'

DISCOVREY_API_PATTERN = \
    'https://{host}/api/x_clop2_cloudify/cloud_resource_discovery/{method}'

CLOUDIFY_ACTIONS_API_PATTERN = \
    'https://{host}/api/x_clop2_cloudify/cloudify_actions/{method}'

DISCOVERY_RESULT_PATTERN = \
    'https://{host}/nav_to.do?uri=discovery_status.do?sys_id={record_id}'

CCG_SCAN_RESULT_PATTERN = \
    'https://{host}/nav_to.do?uri=sn_itom_ccg_audit_result_list.do?' + \
    'sysparm_query=scan_run%3D{record_id}'

TABLE_API_PATTEN = \
    'https://{host}/api/now/table/{tableName}'

AZURE_REGIONS = {
    'eastus': 'East US',
    'eastus2': 'East US 2',
    'southcentralus': 'South Central US',
    'westus2': 'West US 2',
    'westus3': 'West US 3',
    'australiaeast': 'Australia East',
    'southeastasia': 'Southeast Asia',
    'northeurope': 'North Europe',
    'swedencentral': 'Sweden Central',
    'uksouth': 'UK South',
    'westeurope': 'West Europe',
    'centralus': 'Central US',
    'southafricanorth': 'South Africa North',
    'centralindia': 'Central India',
    'eastasia': 'East Asia',
    'japaneast': 'Japan East',
    'koreacentral': 'Korea Central',
    'canadacentral': 'Canada Central',
    'francecentral': 'France Central',
    'germanywestcentral': 'Germany West Central',
    'norwayeast': 'Norway East',
    'switzerlandnorth': 'Switzerland North',
    'brazilsouth': 'Brazil South',
    'eastus2euap': 'East US 2 EUAP',
    'centralusstage': 'Central US (Stage)',
    'eastusstage': 'East US (Stage)',
    'eastus2stage': 'East US 2 (Stage)',
    'northcentralusstage': 'North Central US (Stage)',
    'southcentralusstage': 'South Central US (Stage)',
    'westusstage': 'West US (Stage)',
    'westus2stage': 'West US 2 (Stage)',
    'asia': 'Asia',
    'asiapacific': 'Asia Pacific',
    'australia': 'Australia',
    'brazil': 'Brazil',
    'canada': 'Canada',
    'europe': 'Europe',
    'france': 'France',
    'germany': 'Germany',
    'global': 'Global',
    'india': 'India',
    'japan': 'Japan',
    'korea': 'Korea',
    'norway': 'Norway',
    'singapore': 'Singapore',
    'southafrica': 'South Africa',
    'switzerland': 'Switzerland',
    'uae': 'United Arab Emirates',
    'uk': 'United Kingdom',
    'unitedstates': 'United States',
    'unitedstateseuap': 'United States EUAP',
    'eastasiastage': 'East Asia (Stage)',
    'southeastasiastage': 'Southeast Asia (Stage)',
    'northcentralus': 'North Central US',
    'westus': 'West US',
    'jioindiawest': 'Jio India West',
    'uaenorth': 'UAE North',
    'centraluseuap': 'Central US EUAP',
    'westcentralus': 'West Central US',
    'southafricawest': 'South Africa West',
    'australiacentral': 'Australia Central',
    'australiacentral2': 'Australia Central 2',
    'australiasoutheast': 'Australia Southeast',
    'japanwest': 'Japan West',
    'jioindiacentral': 'Jio India Central',
    'koreasouth': 'Korea South',
    'southindia': 'South India',
    'westindia': 'West India',
    'canadaeast': 'Canada East',
    'francesouth': 'France South',
    'germanynorth': 'Germany North',
    'norwaywest': 'Norway West',
    'switzerlandwest': 'Switzerland West',
    'ukwest': 'UK West',
    'uaecentral': 'UAE Central',
    'brazilsoutheast': 'Brazil Southeast'
}

TERRAFORM_MAPPINGS = {
    # Azure Cases
    'azurerm_api_management': 'Microsoft.ApiManagement/service',
    'azurerm_availability_set': 'Microsoft.Compute/availabilitySets',
    'azurerm_managed_disk': 'Microsoft.Compute/disks',
    'azurerm_image': 'Microsoft.Compute/images',
    'azurerm_linux_virtual_machine': 'Microsoft.Compute/virtualMachines',
    'azurerm_linux_virtual_machine_scale_set':
        'Microsoft.Compute/virtualMachineScaleSets',
    'azurerm_orchestrated_virtual_machine_scale_set':
        'Microsoft.Compute/virtualMachineScaleSets',
    'azurerm_virtual_machine': 'Microsoft.Compute/virtualMachines',
    'azurerm_virtual_machine_scale_set':
        'Microsoft.Compute/virtualMachineScaleSets',
    'azurerm_windows_virtual_machine': 'Microsoft.Compute/virtualMachines',
    'azurerm_windows_virtual_machine_scale_set':
        'Microsoft.Compute/virtualMachineScaleSets',
    'azurerm_application_gateway': 'Microsoft.Network/applicationGateways',
    'azurerm_lb': 'Microsoft.Network/loadBalancers',
    'azurerm_network_interface': 'Microsoft.Network/networkInterfaces',
    'azurerm_network_security_group':
        'Microsoft.Network/networkSecurityGroups',
    'azurerm_public_ip': 'Microsoft.Network/publicIPAddresses',
    'azurerm_route_table': 'Microsoft.Network/routeTables',
    'azurerm_subnet': 'Microsoft.Network/subnets',
    'azurerm_virtual_network': 'Microsoft.Network/virtualNetworks',
    'azurerm_template_deployment': 'Microsoft.Resources/deployments',
    'azurerm_resource_group_template_deployment':
        'Microsoft.Resources/deployments',
    'azurerm_resource_group': 'Microsoft.Resources/resourceGroups',
    'azurerm_storage_blob': 'Microsoft.Storage/blobs',
    'azurerm_storage_account': 'Microsoft.Storage/storageAccounts',
    # AWS Cases
    'aws_acm_certificate': 'AWS::ACM::Certificate',
    'aws_cloudformation_stack': 'AWS::CloudFormation::Stack',
    'aws_cloudtrail': 'AWS::CloudTrail',
    'aws_dynamodb_table': 'AWS::DynamoDB::Table',
    'aws_customer_gateway': 'AWS::EC2::CustomerGateway',
    'aws_eip': 'AWS::EC2::EIP',
    'aws_imagebuilder_image': 'AWS::EC2::Image',
    'aws_instance': 'AWS::EC2::Instance',
    'aws_ec2_instance_type': 'AWS::EC2::InstanceType',
    'aws_internet_gateway': 'AWS::EC2::InternetGateway',
    'aws_key_pair': 'AWS::EC2::Keypair',
    'aws_nat_gateway': 'AWS::EC2::NatGateway',
    'aws_network_acl': 'AWS::EC2::NetworkAcl',
    'aws_default_network_acl': 'AWS::EC2::NetworkAcl',
    'aws_network_interface': 'AWS::EC2::NetworkInterface',
    'aws_route_table': 'AWS::EC2::RouteTable',
    'aws_default_route_table': 'AWS::EC2::RouteTable',
    'aws_security_group': 'AWS::EC2::SecurityGroup',
    'aws_default_security_group': 'AWS::EC2::SecurityGroup',
    'aws_subnet': 'AWS::EC2::Subnet',
    'aws_default_subnet': 'AWS::EC2::Subnet',
    'aws_ebs_volume': 'AWS::EC2::Volume',
    'aws_vpc': 'AWS::EC2::VPC',
    'aws_default_vpc': 'AWS::EC2::VPC',
    'aws_vpn_connection': 'AWS::EC2::VPNConnection',
    'aws_vpn_gateway': 'AWS::EC2::VPNGateway',
    'aws_lb': 'AWS::ElasticLoadBalancing::LoadBalancer',
    'aws_elb': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
    'aws_iam_group': 'AWS::IAM::Group',
    'aws_iam_policy': 'AWS::IAM::Policy',
    'aws_iam_role': 'AWS::IAM::Role',
    'aws_iam_user': 'AWS::IAM::User',
    'aws_db_instance': 'AWS::RDS::DBInstance',
    'aws_db_security_group': 'AWS::RDS::DBSecurityGroup',
    'aws_db_snapshot': 'AWS::RDS::DBSnapshot',
    'aws_route53_zone': 'AWS::Route53::HostedZone',
    'aws_s3_bucket': 'AWS::S3::Bucket',
}

CLOUDIFY_MAPPINGS = {
    # Azure Plugin
    'AZURE': {
        'cloudify.azure.nodes.ResourceGroup': '',
        'cloudify.azure.nodes.storage.StorageAccount': '',
        'cloudify.azure.nodes.storage.DataDisk': '',
        'cloudify.azure.nodes.storage.FileShare': '',
        'cloudify.azure.nodes.network.VirtualNetwork': '',
        'cloudify.azure.nodes.network.NetworkSecurityGroup': '',
        'cloudify.azure.nodes.network.NetworkSecurityRule': '',
        'cloudify.azure.nodes.network.Subnet': '',
        'cloudify.azure.nodes.network.RouteTable': '',
        'cloudify.azure.nodes.network.Route': '',
        'cloudify.azure.nodes.network.NetworkInterfaceCard': '',
        'cloudify.azure.nodes.network.IPConfiguration': '',
        'cloudify.azure.nodes.network.PublicIPAddress': '',
        'cloudify.azure.nodes.compute.AvailabilitySet': '',
        'cloudify.azure.nodes.compute.VirtualMachine': '',
        'cloudify.azure.nodes.compute.WindowsVirtualMachine': '',
        'cloudify.azure.nodes.compute.VirtualMachineExtension': '',
        'cloudify.azure.nodes.network.LoadBalancer': '',
        'cloudify.azure.nodes.network.LoadBalancer.BackendAddressPool': '',
        'cloudify.azure.nodes.network.LoadBalancer.Probe': '',
        'cloudify.azure.nodes.network.LoadBalancer.IncomingNATRule': '',
        'cloudify.azure.nodes.network.LoadBalancer.Rule': '',
        'cloudify.azure.Deployment': '',
        'cloudify.azure.nodes.compute.ContainerService': '',
        'cloudify.azure.nodes.Plan': '',
        'cloudify.azure.nodes.WebApp': '',
        'cloudify.azure.nodes.PublishingUser': '',
        'cloudify.azure.nodes.compute.ManagedCluster': '',
        'cloudify.nodes.azure.ResourceGroup': '',
        'cloudify.nodes.azure.storage.StorageAccount': '',
        'cloudify.nodes.azure.storage.DataDisk': '',
        'cloudify.nodes.azure.storage.FileShare': '',
        'cloudify.nodes.azure.network.VirtualNetwork': '',
        'cloudify.nodes.azure.network.NetworkSecurityGroup': '',
        'cloudify.nodes.azure.network.NetworkSecurityRule': '',
        'cloudify.nodes.azure.network.Subnet': '',
        'cloudify.nodes.azure.network.RouteTable': '',
        'cloudify.nodes.azure.network.Route': '',
        'cloudify.nodes.azure.network.NetworkInterfaceCard': '',
        'cloudify.nodes.azure.network.IPConfiguration': '',
        'cloudify.nodes.azure.network.PublicIPAddress': '',
        'cloudify.nodes.azure.compute.AvailabilitySet': '',
        'cloudify.nodes.azure.compute.VirtualMachine': '',
        'cloudify.nodes.azure.compute.WindowsVirtualMachine': '',
        'cloudify.nodes.azure.compute.VirtualMachineExtension': '',
        'cloudify.nodes.azure.network.LoadBalancer': '',
        'cloudify.nodes.azure.network.LoadBalancer.BackendAddressPool': '',
        'cloudify.nodes.azure.network.LoadBalancer.Probe': '',
        'cloudify.nodes.azure.network.LoadBalancer.IncomingNATRule': '',
        'cloudify.nodes.azure.network.LoadBalancer.Rule': '',
        'cloudify.nodes.azure.compute.ContainerService': '',
        'cloudify.nodes.azure.Plan': '',
        'cloudify.nodes.azure.WebApp': '',
        'cloudify.nodes.azure.PublishingUser': '',
        'cloudify.nodes.azure.compute.ManagedCluster': '',
    },
    # AWS Plugin
    'AWS': {
        'cloudify.nodes.aws.dynamodb.Table': 'AWS::DynamoDB::Table',
        'cloudify.nodes.aws.iam.Group': 'AWS::IAM::Group',
        'cloudify.nodes.aws.iam.AccessKey': 'AWS::IAM::AccessKey',
        'cloudify.nodes.aws.iam.User': 'AWS::IAM::User',
        'cloudify.nodes.aws.iam.Role': 'AWS::IAM::Role',
        'cloudify.nodes.aws.iam.RolePolicy': 'AWS::IAM::ManagedPolicy',
        'cloudify.nodes.aws.iam.InstanceProfile': 'AWS::IAM::InstanceProfile',
        'cloudify.nodes.aws.iam.Policy': 'AWS::IAM::Policy',
        'cloudify.nodes.aws.lambda.Function': 'AWS::Lambda::Function',
        'cloudify.nodes.aws.lambda.Permission': 'AWS::Lambda::Permission',
        'cloudify.nodes.aws.rds.Instance': 'AWS::RDS::DBInstance',
        'cloudify.nodes.aws.rds.SubnetGroup': 'AWS::RDS::DBSubnetGroup',
        'cloudify.nodes.aws.rds.OptionGroup': 'AWS::RDS::OptionGroup',
        'cloudify.nodes.aws.rds.ParameterGroup': 'AWS::RDS::DBParameterGroup',
        'cloudify.nodes.aws.route53.HostedZone': 'AWS::Route53::HostedZone',
        'cloudify.nodes.aws.route53.RecordSet': 'AWS::Route53::RecordSet',
        'cloudify.nodes.aws.SQS.Queue': 'AWS::SQS::Queue',
        'cloudify.nodes.aws.SNS.Topic': 'AWS::SNS::Topic',
        'cloudify.nodes.aws.SNS.Subscription': 'AWS::SNS::Subscription',
        'cloudify.nodes.aws.elb.LoadBalancer':
            'AWS::ElasticLoadBalancingV2::LoadBalancer',
        'cloudify.nodes.aws.elb.Classic.LoadBalancer':
            'AWS::ElasticLoadBalancing::LoadBalancer',
        'cloudify.nodes.aws.elb.Rule':
            'AWS::ElasticLoadBalancingV2::ListenerRule',
        'cloudify.nodes.aws.elb.TargetGroup':
            'AWS::ElasticLoadBalancingV2::TargetGroup',
        'cloudify.nodes.aws.s3.Bucket': 'AWS::S3::Bucket',
        'cloudify.nodes.aws.s3.BucketPolicy': 'AWS::S3::BucketPolicy',
        'cloudify.nodes.aws.ec2.Vpc': 'AWS::EC2::VPC',
        'cloudify.nodes.aws.ec2.VpcPeering': 'AWS::EC2::VPCPeeringConnection',
        'cloudify.nodes.aws.ec2.Subnet': 'AWS::EC2::Subnet',
        'cloudify.nodes.aws.ec2.SecurityGroup': 'AWS::EC2::SecurityGroup',
        'cloudify.nodes.aws.ec2.SecurityGroupRuleIngress':
            'AWS::EC2::SecurityGroupEgress',
        'cloudify.nodes.aws.ec2.SecurityGroupRuleEgress':
            'AWS::EC2::SecurityGroupIngress',
        'cloudify.nodes.aws.ec2.NATGateway': 'AWS::EC2::NatGateway',
        'cloudify.nodes.aws.ec2.Interface': 'AWS::EC2::NetworkInterface',
        'cloudify.nodes.aws.ec2.Instances': 'AWS::EC2::Instance',
        'cloudify.nodes.aws.ec2.SpotInstances': 'AWS::EC2::Instance',
        'cloudify.nodes.aws.ec2.Keypair': 'AWS::EC2::KeyPair',
        'cloudify.nodes.aws.ec2.ElasticIP': 'AWS::EC2::EIP',
        'cloudify.nodes.aws.ec2.NetworkACL': 'AWS::EC2::NetworkAcl',
        'cloudify.nodes.aws.ec2.NetworkAclEntry': 'AWS::EC2::NetworkAclEntry',
        'cloudify.nodes.aws.ec2.DHCPOptions': 'AWS::EC2::DHCPOptions',
        'cloudify.nodes.aws.ec2.VPNGateway': 'AWS::EC2::VPNGateway',
        'cloudify.nodes.aws.ec2.VPNConnection': 'AWS::EC2::VPNConnection',
        'cloudify.nodes.aws.ec2.VPNConnectionRoute':
            'AWS::EC2::VPNConnectionRoute',
        'cloudify.nodes.aws.ec2.CustomerGateway': 'AWS::EC2::CustomerGateway',
        'cloudify.nodes.aws.ec2.InternetGateway': 'AWS::EC2::InternetGateway',
        'cloudify.nodes.aws.ec2.TransitGateway': 'AWS::EC2::TransitGateway',
        'cloudify.nodes.aws.ec2.TransitGatewayRouteTable':
            'AWS::EC2::TransitGatewayRouteTable',
        'cloudify.nodes.aws.ec2.TransitGatewayRoute':
            'AWS::EC2::TransitGatewayRoute',
        'cloudify.nodes.aws.ec2.RouteTable': 'AWS::EC2::RouteTable',
        'cloudify.nodes.aws.ec2.Route': 'AWS::EC2::Route',
        'cloudify.nodes.aws.ec2.EBSVolume': 'AWS::EC2::Volume',
        'cloudify.nodes.aws.ec2.EBSAttachment': 'AWS::EC2::VolumeAttachment',
        'cloudify.nodes.aws.cloudwatch.Alarm': 'AWS::CloudWatch::Alarm',
        'cloudify.nodes.aws.cloudwatch.Rule': 'AWS::CloudWatch::InsightRule',
        'cloudify.nodes.aws.efs.FileSystem': 'AWS::EFS::FileSystem',
        'cloudify.nodes.aws.efs.MountTarget': 'AWS::EFS::MountTarget',
        'cloudify.nodes.aws.kms.CustomerMasterKey': 'AWS::KMS::Key',
        'cloudify.nodes.aws.kms.Alias': 'AWS::KMS::Alias',
        'cloudify.nodes.aws.CloudFormation.Stack':
            'AWS::CloudFormation::Stack',
        'cloudify.nodes.aws.ecs.Cluster': 'AWS::ECS::Cluster',
        'cloudify.nodes.aws.ecs.Service': 'AWS::ECS::Service',
        'cloudify.nodes.aws.ecs.TaskDefinition': 'AWS::ECS::TaskDefinition',
        'cloudify.nodes.swift.s3.Bucket': 'AWS::S3::Bucket',
        'cloudify.nodes.aws.eks.Cluster': 'AWS::EKS::Cluster',
        'cloudify.nodes.aws.eks.NodeGroup': 'AWS::EKS::Nodegroup',
        'cloudify.nodes.aws.codepipeline.Pipeline':
            'AWS::CodePipeline::Pipeline',
    }
}
