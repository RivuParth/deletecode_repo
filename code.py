import boto3
import re
# def terminate(client,method_name, resource_arn, **resource_param):
#     try:
#         # Check if resource can be terminated before deletion
#         if method_name == 'terminate_instances' or method_name == 'terminate_environment':
#             print(f"Terminating resource with ARN {resource_arn}...")
#             client.getattribute(method_name)(**resource_param)
#         elif method_name == 'update_distribution':
#             print(f"Disabling resource with ARN {resource_arn}...")
#             client.getattribute(method_name)(**resource_param)
        # Wait for the resource to be terminated
    #    if service_name == 'ec2':
    #         waiter = client.get_waiter('instance_terminated')
    #         waiter.wait(InstanceIds=[resource_param['InstanceIds'][0]])
    #     elif service_name == 'elasticbeanstalk':
    #         waiter = client.get_waiter('environment_terminated')
    #         waiter.wait(EnvironmentName=resource_name)
    #     elif service_name == 'cloudfront':
    #         waiter = client.get_waiter('distribution_deployed')
    #         waiter.wait(Id=resource_param['Id'], WaiterConfig={'Delay': 30, 'MaxAttempts': 30})
    # except Exception as e:
    #     print(f"Error terminating resource with ARN {resource_arn}: {e}")
    #     return

def delete_resource(client,method_name, resource_arn, **resource_param):
    try:
        # Delete resource
        print(f"Deleting resource with ARN {resource_param}...")
        response = client.getattribute(method_name)(**resource_param)
        print(f"Successfully deleted resource with ARN {resource_arn}")
        return ({"data" : "Deletion Successful"})
    except Exception as e:
        print(f"Error deleting resource with ARN {resource_arn}: {e}")
        return ({"data" : "Error deleting resource with ARN {resource_arn}: {e}"})


def terminate_and_delete_resource(resource_arn):
    # Extract the service name and resource type from the ARN
    arn_parts = resource_arn.split(':')
    service_name = arn_parts[2]
    resource_type = arn_parts[5].split('/')[0]
    resource_param = {resource_type + 'Id': arn_parts[5].split('/')[1]}
    print(f"{resource_type}")
    resource_name = None

    # Connect to the appropriate service client
    client = boto3.client(service_name)

    if service_name == 'ec2':
      match resource_type :
        case "instance":
            method_name = 'terminate_instances'
            resource_param = {'InstanceIds': [resource_param['instanceId']]}
            
        case "local-gateway-route":
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableId = arn_parts[5].split('/')[1]
            resource_param = {' DestinationCidrBlock': resourceid, 'LocalGatewayRouteTableId': LocalGatewayRouteTableId}
            
        case "local-gateway-route-table":
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableIdurceid = arn_parts[5].split('/')[1]
            resource_param = {'LocalGatewayRouteTableId': LocalGatewayRouteTableIdurceid}
            
        case "local-gateway-route-table-virtual-interface-group-association":
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableVirtualInterfaceGroupAssociationId = arn_parts[5].split('/')[1]
            resource_param = {'LocalGatewayRouteTableVirtualInterfaceGroupAssociationId': LocalGatewayRouteTableVirtualInterfaceGroupAssociationId}
            
        case "local-gateway-route-table-vpc-association":
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableVpcAssociationId = arn_parts[5].split('/')[1]
            resource_param = {'LocalGatewayRouteTableVpcAssociationId': LocalGatewayRouteTableVpcAssociationId}
            
        case "managed-prefix-list":
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            PrefixListId = arn_parts[5].split('/')[1]
            resource_param = {'PrefixListId': PrefixListId}
            
        case "nat-gateway":
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NatGatewayId = arn_parts[5].split('/')[1]
            resource_param = {'NatGatewayId': NatGatewayId}
        case 'network-acl':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkAclId = arn_parts[5].split('/')[1]
            resource_param = {'NetworkAclId': NetworkAclId}
            
        case 'network-insights-access-scope':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsAccessScopeId = arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsAccessScopeId': NetworkInsightsAccessScopeId}
            
        case 'network-insights-access-scope-analysis':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsAccessScopeAnalysisId = arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsAccessScopeAnalysisId': NetworkInsightsAccessScopeAnalysisId}
            
        case 'network-insights-path':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsPathId = arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsPathId': NetworkInsightsPathId}
            
        case 'network-interface':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInterfaceId = arn_parts[5].split('/')[1]
            resource_param = {'NetworkInterfaceId': NetworkInterfaceId}
            
        case 'network-interface-permission':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInterfacePermissionId = arn_parts[5].split('/')[1]
            resource_param = {'NetworkInterfacePermissionId': NetworkInterfacePermissionId}
            
        case 'placement-group':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            GroupName = arn_parts[5].split('/')[1]
            resource_param = {'GroupName': GroupName}
        case "public-ipv4-pool":
            method_name = "delete_" + resource_type.replace("-","_")
            PoolId = arn_parts[5].split('/')[1]
            resource_param = { "PoolId": PoolId }
            
        case "queued-reserved-instances":
            method_name = "delete_" + resource_type.replace("-","_")
            ReservedInstancesIds = arn_parts[5].split('/')[1]
            resource_param = { "ReservedInstancesIds": ReservedInstancesIds }
            
        case "route":
            method_name = "delete_" + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = { "RouteTableId": resourceid }
            
        case "security-group":
            method_name = "delete_" + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            GroupId = arn_parts[5].split('/')[1]
            resource_param = { "GroupId": GroupId }
            
        case "network-acl-entry":
            method_name = "delete_" + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            ruleNumber = arn_parts[5].split('/')[3]
            egress= True if (arn_parts[5].split('/')[2]=='egress') else False
            resource_param = { "Egress": egress, "NetworkAclId": resourceid, "RuleNumber": ruleNumber }


        case 'security-group':
            method_name = 'delete_security_group'
            resource_name = client.describe_security_groups(GroupIds=[resource_param['security-groupId']])['SecurityGroups'][0]['GroupName']
            resource_param = {'GroupName': resource_name}
          
        case 'route-table':
            method_name = 'delete_route_table'
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'RouteTableId': resourceid}
            
        case 'transit-gateway-peering-attachment':
            method_name = 'delete_transit_gateway_peering_attachment'
            TransitGatewayAttachmentId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayAttachmentId': TransitGatewayAttachmentId}
             
        case 'transit-gateway-policy-table':
            method_name = 'delete_transit_gateway_policy_table'
            TransitGatewayPolicyTableId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayPolicyTableId': TransitGatewayPolicyTableId}
             
        case 'transit-gateway-prefix-list-reference':
            method_name = 'delete_transit_gateway_prefix_list_reference'
            TransitGatewayRouteTableId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayRouteTableId': TransitGatewayRouteTableId}
             
        case 'transit-gateway-route':
            method_name = 'delete_transit_gateway_route'
            TransitGatewayRouteTableId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayRouteTableId': TransitGatewayRouteTableId}
             
        case 'transit_gateway_route':
            method_name = 'delete_transit_gateway_route'
            TransitGatewayRouteTableId = arn_parts[5].split('/')[1]
            DestinationCidrBlockId = arn_parts[5].split('/')[2]
            resource_param = {'TransitGatewayRouteTableId': TransitGatewayRouteTableId,
                              'DestinationCidrBlockId': DestinationCidrBlockId}
             
        case 'transit_gateway_route_table_announcement':
            method_name = 'delete_transit_gateway_route_table_announcement'
            TransitGatewayRouteTableAnnouncementId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayRoute':TransitGatewayRouteTableAnnouncementId}

        case 'transit-gateway-vpc-attachment':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayAttachmentId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayAttachmentId': TransitGatewayAttachmentId}
         
        case 'verified-access-endpoint':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessEndpointId = arn_parts[5].split('/')[1]
            resource_param = {'VerifiedAccessEndpointId': VerifiedAccessEndpointId}
         
        case 'verified-access-group':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessGroupId = arn_parts[5].split('/')[1]
            ClientToken = arn_parts[5].split('/')[2]
            resource_param = {'VerifiedAccessGroupId': VerifiedAccessGroupId,
                         'ClientToken': ClientToken}
         
        case 'verified-access-instance':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessInstanceId = arn_parts[5].split('/')[1]
            resource_param = {'VerifiedAccessInstanceId': VerifiedAccessInstanceId}
         
        case 'verified-access-trust-provider':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessTrustProviderId = arn_parts[5].split('/')[1]
            resource_param = {'VerifiedAccessTrustProviderId': VerifiedAccessTrustProviderId}
         
        case 'delete-volume':
            method_name = 'delete_' + resource_type.replace("-","_")
            VolumeId = arn_parts[5].split('/')[1]
            resource_param = {'VolumeId': VolumeId}
         
        case 'delete-vpc':
            method_name = 'delete_' + resource_type.replace("-","_")
            VpcId = arn_parts[5].split('/')[1]
            resource_param = {'VpcId': VpcId}
       
    
   
    elif service_name == 'elasticbeanstalk':
        if resource_type == 'environment':
            method_name = 'terminate_environment'
        else:
            print(f"Error: Unable to delete resource of type {resource_type} in {service_name}")
            return
    elif service_name == 'cloudfront':
        if resource_type == 'distribution':
            method_name = 'update_distribution'
            resource_param = {'Id': resource_param['distributionId'], 'DistributionConfig': {'Enabled': False}}
        else:
            print(f"Error: Unable to delete resource of type {resource_type} in {service_name}")
            return
    else:
        #Get the resource name using resource_arn
        if resource_type == 'table':
            resource_name = client.describe_table(TableName=resource_arn)['Table']['TableName']
            method_name = 'delete_table'
            resource_param = {'TableName': resource_name}
        elif resource_type == 'bucket':
            resource_name = resource_arn.split('/')[-1]
            method_name = 'delete_bucket'
            resource_param = {'Bucket': resource_name}
        elif resource_type == 'stack':
            resource_name = resource_arn.split('/')[-1]
            method_name = 'delete_stack'
            resource_param = {'StackName': resource_name}
        else:
            print(f"Error: Unable to delete resource of type {resource_type} in {service_name}")
            return

    if "delete" in method_name:
        delete_resource(client,method_name, resource_arn, **resource_param)
    # else:
    #     terminate(client,method_name, resource_arn, **resource_param)



if __name__ == '__main__':
    terminate_and_delete_resource("arn:aws:ec2:us-west-2:123456789012:local-gateway-route/loc-049df61146f120899/0.0.0.0/0")
