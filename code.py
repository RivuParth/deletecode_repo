import boto3
import re


# def terminate(client,method_name, resource_arn, **resource_param):
#     try:
#         # Check if resource can be terminated before deletion
#         if method_name == 'terminate_instances' or method_name == 'terminate_environment':
#             print(f"Terminating resource with ARN {resource_arn}...")
#             client._getattribute_(method_name)(**resource_param)
#         elif method_name == 'update_distribution':
#             print(f"Disabling resource with ARN {resource_arn}...")
#             client._getattribute_(method_name)(**resource_param)
#         # Wait for the resource to be terminated
#         if service_name == 'ec2':
#             waiter = client.get_waiter('instance_terminated')
#             waiter.wait(InstanceIds=[resource_param['InstanceIds'][0]])
#         elif service_name == 'elasticbeanstalk':
#             waiter = client.get_waiter('environment_terminated')
#             waiter.wait(EnvironmentName=resource_name)
#         elif service_name == 'cloudfront':
#             waiter = client.get_waiter('distribution_deployed')
#             waiter.wait(Id=resource_param['Id'], WaiterConfig={'Delay': 30, 'MaxAttempts': 30})
#     except Exception as e:
#         print(f"Error terminating resource with ARN {resource_arn}: {e}")
#         return

def delete_resource(client,method_name, resource_arn, **resource_param):
    try:
        # Delete resource
        print(f"Deleting resource with ARN {resource_param}...")
        response = client._getattribute_(method_name)(**resource_param)
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
        if resource_type == 'instance':
            method_name = 'terminate_instances'
            resource_param = {'InstanceIds': [resource_param['instanceId']]}
        elif resource_type == 'security-group':
            method_name = 'delete_security_group'
            resource_name = client.describe_security_groups(GroupIds=[resource_param['security-groupId']])['SecurityGroups'][0]['GroupName']
            resource_param = {'GroupName': resource_name}
        elif resource_type == 'route-table':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'RouteTableId': resourceid}
        #SURJAYAN
        elif resource_type == 'carrier-gateway':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'CarrierGatewayId': resourceid}
            
        elif resource_type == 'client-vpn-endpoint':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'ClientVpnEndpointId': resourceid}
            
        elif resource_type == 'client-vpn-route':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid1 = arn_parts[5].split('/')[1]
            resource_param = {'ClientVpnEndpointId': resourceid}
            resourceid2 = arn_parts[5].split('/')[1]
            resource_param = {'DestinationCidrBlock': resourceid}
            
        elif resource_type == 'coip-cidr':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid1 = arn_parts[5].split('/')[1]
            resource_param = {'Cidr': resourceid}
            resourceid2 = arn_parts[5].split('/')[1]
            resource_param = {'CoipPoolId': resourceid}
            
        elif resource_type == 'coip-pool':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'CoipPoolId': resourceid}
            
        elif resource_type == 'customer-gateway':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'CustomerGatewayId': resourceid}
            
        elif resource_type == 'dhcp-options':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'DhcpOptionsId': resourceid}
            
        elif resource_type == 'egress-only-internet-gateway':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'EgressOnlyInternetGatewayId': resourceid}
            
        elif resource_type == 'fleets':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'FleetIds': resourceid}
            
        elif resource_type == 'flow-logs':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'FlowLogIds': resourceid}
            
        elif resource_type == 'fpga-image':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'FpgaImageId': resourceid}
            
        elif resource_type == 'instance-event-window':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'InstanceEventWindowId': resourceid}
            
        elif resource_type == 'internet-gateway':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'InternetGatewayId': resourceid}
            
        elif resource_type == 'ipam':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'IpamId': resourceid}
            
        elif resource_type == 'ipam-pool':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'IpamPoolId': resourceid}
            
        elif resource_type == 'ipam-resource-discovery':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'IpamResourceDiscoveryId': resourceid}
            
        elif resource_type == 'ipam-scope':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'IpamScopeId': resourceid}
            
        elif resource_type == 'key-pair':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'KeyPairId': resourceid}
            
        elif resource_type == 'launch-template':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'LaunchTemplateId': resourceid}
        
        elif resource_type == 'launch-template-versions':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'LaunchTemplateId': resourceid}

    #    PARTHA
        elif resource_type == 'transit-gateway-peering-attachment':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayAttachmentId =arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayAttachmentId': TransitGatewayAttachmentId}

        elif resource_type == 'transit-gateway-policy-table':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayPolicyTableId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayPolicyTableId': TransitGatewayPolicyTableId}

        elif resource_type == 'transit-gateway-prefix-list-reference':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayRouteTableId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayRouteTableId': TransitGatewayRouteTableId}

        elif resource_type == 'transit-gateway-route':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayRouteTableId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayRouteTableId': TransitGatewayRouteTableId}
        elif resource_type == 'transit_gateway_route':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayRouteTableId = arn_parts[5].split('/')[1]
            DestinationCidrBlockId = arn_parts[5].split('/')[2]
            resource_param = {'TransitGatewayRouteTableId': TransitGatewayRouteTableId,
							'DestinationCidrBlockId': DestinationCidrBlockId}
        elif resource_type == 'transit_gateway_route_table_announcement':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayRouteTableAnnouncementId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayRouteTableAnnouncementId': TransitGatewayRouteTableAnnouncementId}
        elif resource_type == 'transit-gateway-vpc-attachment':
            method_name = 'delete_' + resource_type.replace("-","_")
            TransitGatewayAttachmentId = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayAttachmentId': TransitGatewayAttachmentId}
        elif resource_type == 'verified-access-endpoint':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessEndpointId = arn_parts[5].split('/')[1]
            resource_param = {'VerifiedAccessEndpointId': VerifiedAccessEndpointId}
         # check
        elif resource_type == 'verified-access-group':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessGroupId = arn_parts[5].split('/')[1]
            ClientToken = arn_parts[5].split('/')[2]
            resource_param = {'VerifiedAccessGroupId': VerifiedAccessGroupId,
                             'ClientToken': ClientToken}
        elif resource_type == 'verified-access-instance':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessInstanceId = arn_parts[5].split('/')[1]
            resource_param = {'VerifiedAccessInstanceId': VerifiedAccessInstanceId}
        elif resource_type == 'verified-access-trust-provider':
            method_name = 'delete_' + resource_type.replace("-","_")
            VerifiedAccessTrustProviderId = arn_parts[5].split('/')[1]
            resource_param = {'VerifiedAccessTrustProviderId': VerifiedAccessTrustProviderId}
        elif resource_type == 'delete-volume':
            method_name = 'delete_' + resource_type.replace("-","_")
            VolumeId = arn_parts[5].split('/')[1]
            resource_param = {'VolumeId': VolumeId}
        elif resource_type == 'delete-vpc':
            method_name = 'delete_' + resource_type.replace("-","_")
            VpcId = arn_parts[5].split('/')[1]
            resource_param = {'VpcId': VpcId}

    #    RUPESH
        elif resource_type == 'snapshot':
            method_name = 'delete_' + resource_type
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'SnapshotId': resourceid}
        elif resource_type == 'spot-datafeed-subscription':
            method_name = 'delete_' + resource_type.replace("-","_")
        elif resource_type == 'subnet':
            method_name = 'delete_' + resource_type
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'SubnetId': resourceid}
        elif resource_type == 'subnet-cidr-reservation':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'SubnetCidrReservationId': resourceid}
        elif resource_type == 'tags':
            method_name = 'delete_' + resource_type
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'Resources': [resourceid]}
        elif resource_type == 'traffic-mirror-filter':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TrafficMirrorFilterId': resourceid}
        elif resource_type == 'traffic-mirror-rule':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TrafficMirrorFilterRuleId': resourceid}
        elif resource_type == 'traffic-mirror-session':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TrafficMirrorSessionId': resourceid}
        elif resource_type == 'traffic-mirror-target':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TrafficMirrorTargetId': resourceid}
        elif resource_type == 'transit-gateway':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayId': resourceid}
        elif resource_type == 'transit-gateway-connect':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayAttachmentId': resourceid}
        elif resource_type == 'transit-gateway-connect-peer':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayConnectPeerId': resourceid}
        elif resource_type == 'transit-gateway-multicast-domain':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'TransitGatewayMulticastDomainId': resourceid}

        # DEBABRATA
        elif resource_type == 'launch-template':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            version= arn_parts[5].split('/')[2]
            resource_param = {'LaunchTemplateId': resourceid,
                            'Versions': '['+ version +',]' } 
        elif resource_type == 'local-gateway-route':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableId =arn_parts[5].split('/')[1]
            resource_param = {' DestinationCidrBlock': resourceid,
           'LocalGatewayRouteTableId':LocalGatewayRouteTableId }
        elif resource_type == 'local-gateway-route-table':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableIdurceid =arn_parts[5].split('/')[1]
            resource_param = {'LocalGatewayRouteTableId': LocalGatewayRouteTableIdurceid }
        elif resource_type == 'local-gateway-route-table-virtual-interface-group-association':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableVirtualInterfaceGroupAssociationId =arn_parts[5].split('/')[1]
            resource_param = {'LocalGatewayRouteTableVirtualInterfaceGroupAssociationId': LocalGatewayRouteTableVirtualInterfaceGroupAssociationId }
        elif resource_type == 'local-gateway-route-table-vpc-association':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            LocalGatewayRouteTableVpcAssociationId =arn_parts[5].split('/')[1]
            resource_param = {'LocalGatewayRouteTableVpcAssociationId': LocalGatewayRouteTableVpcAssociationId }
        elif resource_type == 'managed-prefix-list':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            PrefixListId =arn_parts[5].split('/')[1]
            resource_param = {'PrefixListId': PrefixListId }
        elif resource_type == 'nat-gateway':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NatGatewayId =arn_parts[5].split('/')[1]
            resource_param = {'NatGatewayId': NatGatewayId}
        elif resource_type == 'network-acl':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkAclId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkAclId': NetworkAclId}
        elif resource_type == 'network-acl':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkAclId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkAclId': NetworkAclId}
        elif resource_type == 'network-insights-access-scope':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsAccessScopeId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsAccessScopeId': NetworkInsightsAccessScopeId}
        elif resource_type == 'network-insights-access-scope-analysis':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsAccessScopeAnalysisId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsAccessScopeAnalysisId': NetworkInsightsAccessScopeAnalysisId}
        elif resource_type == 'network-insights-access-scope-analysis':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsAccessScopeAnalysisId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsAccessScopeAnalysisId': NetworkInsightsAccessScopeAnalysisId}
        elif resource_type == 'network-insights-path':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInsightsPathId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkInsightsPathId': NetworkInsightsPathId}
        elif resource_type == 'network-interface':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInterfaceId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkInterfaceId': NetworkInterfaceId}
        elif resource_type == 'network-interface-permission':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            NetworkInterfacePermissionId =arn_parts[5].split('/')[1]
            resource_param = {'NetworkInterfacePermissionId': NetworkInterfacePermissionId}
        elif resource_type == 'placement-group':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            GroupName =arn_parts[5].split('/')[1]
            resource_param = {'GroupName': GroupName}
        elif resource_type == 'public-ipv4-pool':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            PoolId =arn_parts[5].split('/')[1]
            resource_param = {'PoolId': PoolId}
        elif resource_type == 'queued-reserved-instances':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            ReservedInstancesIds =arn_parts[5].split('/')[1]
            resource_param = {'ReservedInstancesIds': ReservedInstancesIds}
        elif resource_type == 'route':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'RouteTableId': resourceid}
        elif resource_type == 'route-table':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'RouteTableId': resourceid}
        elif resource_type == 'route-table':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            resource_param = {'RouteTableId': resourceid}
        elif resource_type == 'security-group':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            GroupId =arn_parts[5].split('/')[1]
            resource_param = {'GroupId': GroupId}
        elif resource_type == 'network-acl-entry':
            method_name = 'delete_' + resource_type.replace("-","_")
            resourceid = arn_parts[5].split('/')[1]
            ruleNumber= arn_parts[5].split('/')[3]
            egress= True if (arn_parts[5].split('/')[2]=='egress') else False
            resource_param = {  'Egress': egress,
                                'NetworkAclId': resourceid,
                                'RuleNumber': ruleNumber}
        # KIRON
        # elif resource_type == 'vpc-endpoint-connection-notifications':
        #     method_name = 'delete_' + resource_type
        #     resourceid = arn_parts[5].split('/')[1]
        #     resource_param = {'ConnectionNotificationIds': resourceid}
        # elif resource_type == 'vpc-endpoint-service-configurations':
        #     method_name = 'delete_' + resource_type
        #     resourceid = arn_parts[5].split('/')[1]
        #     resource_param = {'ServiceIds': resourceid}
        # elif resource_type == 'vpc-endpoints':
        #     method_name = 'delete_' + resource_type
        #     resourceid = arn_parts[5].split('/')[1]
        #     resource_param = {'VpcEndpointIds': resourceid}
        # # elif resource_type == 'vpc-peering-connection':
        # #     method_name = 'delete_' + resource_type
        # #     resourceid = arn_parts[5].split('/')[1]
        # #     resource_param = {'VpcPeeringConnectionId: resourceid}
        # elif resource_type == 'vpn-connection':
        #     method_name = 'delete_' + resource_type
        #     resourceid = arn_parts[5].split('/')[1]
        #     resource_param = {'VpnConnectionId': resourceid}
        # elif resource_type == 'vpn-connection-route':
        #     method_name = 'delete_' + resource_type
        #     resourceid 1= arn_parts[5].split('/')[1]
        #     resource_param = {'DestinationCidrBlock': resourceid}
        #     resourceid 
        #     2= arn_parts[5].split('/')[1]
        #     resource_param = {'VpnConnectionId': resourceid}
        # elif resource_type == 'byoip-cidr':
        #     method_name = 'delete_' + resource_type.deprovision("-","_")
        #     resourceid = arn_parts[5].split('/')[1]
        #     resource_param = {'Cidr': resourceid}
        # elif resource_type == 'ipam-pool-cidr':
        #     method_name = 'delete_' + resource_type.deprovision("-"'"_") 
        #     resourceid1= arn_parts[5].split('/')[1]
        #     resource_param = {'IpamPoolId'': resourceid}
        #     resourceid 2= arn_parts[5].split('/')[1]
        #     resource_param = {'Cidr': resourceid}
        # elif resource_type == 'public-ipv4-pool-cidr':
        #     method_name = 'delete_' + resource_type.deprovision("-"'"_") 
        #     resourceid1= arn_parts[5].split('/')[1]
        #     resource_param = {'PoolId'': resourceid}
        #     resourceid 2= arn_parts[5].split('/')[1]
        #     resource_param = {'Cidr': resourceid}
        # elif resource_type == 'image':
        #     method_name = 'delete_' + resource_type.deregister("-","_")
        #     resourceid = arn_parts[5].split('/')[1]
        #     resource_param = {'ImageId': resourceid}

        else:
            method_name = 'delete_' + resource_type.replace("-","_")
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
    terminate_and_delete_resource("arn:aws:ec2:us-west-2:123456789012:transit-gateway-peering-attachment/tpg-attach-abcdef01")