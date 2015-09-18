#!/usr/bin/python
DOCUMENTATION = '''
---
module: azure_deploy
short_description: Create or destroy Azure deployments via Azure Resource Manager API
version_added: "2.0"
description:
     - Create or destroy Azure deployments via Azure Resource Manager API using requests and Python SDK for Azure
options:
  subscription_id:
    description:
      - The Azure subscription to deploy the template into
    required: true
  resource_group_name:
    description:
      - The resource group name to use or create to host the deployed template
    required: true
  deployment_name:
    description:
      - The name of the deployment
    required: true
  state:
    description:
      - If state is "present", template will be created.  If state is "present" and if stack exists and template has
        changed, it will be updated. If state is "absent", stack will be removed.
    required: true
  template:
    description:
      - The local path of the Azure deployment template. This parameter is mutually exclusive with 'template_url'.
        Either one of them is required if "state" parameter is "present". Must give full path to the file, relative to
        the working directory. If using roles this may look like "roles/azure_template/files/azure_template-example.json"
    required: false
    default: None
  template_link:
    description:
      - Location of file containing the template body. This parameter is mutually exclusive with 'template'. Either one
        of them is required if "state" parameter is "present"
    required: false
    default: None
  parameters:
    description:
      - a list of hashes of all the template variables for the deployment template
    required: false
    default: None
  parameters_link:
    description:
      - Location of file containing the parameters body. This parameter is mutually exclusive with 'parameters'. Either
        one of them is required if "state" parameter is "present"
    required: false
    default: None
  location:
    description:
      - Where the resource group should live
    require: false
    default: West US

author: "David Justice (@devigned)"
'''

EXAMPLES = '''
# Destroy a template deployment
- name: Destroy Azure Deploy
  azure_deploy:
    state: absent
    subscription_id: subscription_id
    resource_group_name: dev-ops-cle
    deployment_name: test01

# Create or update a template deployment based on uris to paramters and a template
- name: Create Azure Deploy
  azure_deploy:
    state: present
    subscription_id: subscription_id
    resource_group_name: dev-ops-cle
    deployment_name: test01
    parameters_link: 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-simple-linux-vm/azuredeploy.parameters.json'
    template_link: 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-simple-linux-vm/azuredeploy.json'

# Create or update a template deployment based on a uri to the template and parameters specified inline
- name: Create Azure Deploy
  azure_deploy:
    state: present
    subscription_id: cbbdaed0-fea9-4693-bf0c-d446ac93c030
    resource_group_name: dev-ops-cle
    deployment_name: test01
    parameters:
      newStorageAccountName:
        value: devopsclestorage
      adminUsername:
        value: devopscle
      adminPassword:
        value: Password1!
      dnsNameForPublicIP:
        value: devopscleazure
    template_link: 'https://github.com/Azure/azure-quickstart-templates/raw/master/101-simple-linux-vm/azuredeploy.json'

# Create or update a template deployment based on an inline template and parameters
- name: Create Azure Deploy
  azure_deploy:
    state: present
    subscription_id: cbbdaed0-fea9-4693-bf0c-d446ac93c030
    resource_group_name: dev-ops-cle
    deployment_name: test01
    template:
      $schema: "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
      contentVersion: "1.0.0.0"
      parameters:
        newStorageAccountName:
          type: "string"
          metadata:
            description: "Unique DNS Name for the Storage Account where the Virtual Machine's disks will be placed."
        adminUsername:
          type: "string"
          metadata:
            description: "User name for the Virtual Machine."
        adminPassword:
          type: "securestring"
          metadata:
            description: "Password for the Virtual Machine."
        dnsNameForPublicIP:
          type: "string"
          metadata:
            description: "Unique DNS Name for the Public IP used to access the Virtual Machine."
        ubuntuOSVersion:
          type: "string"
          defaultValue: "14.04.2-LTS"
          allowedValues:
            - "12.04.5-LTS"
            - "14.04.2-LTS"
            - "15.04"
          metadata:
            description: "The Ubuntu version for the VM. This will pick a fully patched image of this given Ubuntu version. Allowed values: 12.04.5-LTS, 14.04.2-LTS, 15.04."
      variables:
        location: "West US"
        imagePublisher: "Canonical"
        imageOffer: "UbuntuServer"
        OSDiskName: "osdiskforlinuxsimple"
        nicName: "myVMNic"
        addressPrefix: "10.0.0.0/16"
        subnetName: "Subnet"
        subnetPrefix: "10.0.0.0/24"
        storageAccountType: "Standard_LRS"
        publicIPAddressName: "myPublicIP"
        publicIPAddressType: "Dynamic"
        vmStorageAccountContainerName: "vhds"
        vmName: "MyUbuntuVM"
        vmSize: "Standard_D1"
        virtualNetworkName: "MyVNET"
        vnetID: "[resourceId('Microsoft.Network/virtualNetworks',variables('virtualNetworkName'))]"
        subnetRef: "[concat(variables('vnetID'),'/subnets/',variables('subnetName'))]"
      resources:
        -
          type: "Microsoft.Storage/storageAccounts"
          name: "[parameters('newStorageAccountName')]"
          apiVersion: "2015-05-01-preview"
          location: "[variables('location')]"
          properties:
            accountType: "[variables('storageAccountType')]"
        -
          apiVersion: "2015-05-01-preview"
          type: "Microsoft.Network/publicIPAddresses"
          name: "[variables('publicIPAddressName')]"
          location: "[variables('location')]"
          properties:
            publicIPAllocationMethod: "[variables('publicIPAddressType')]"
            dnsSettings:
              domainNameLabel: "[parameters('dnsNameForPublicIP')]"
        -
          type: "Microsoft.Network/virtualNetworks"
          apiVersion: "2015-05-01-preview"
          name: "[variables('virtualNetworkName')]"
          location: "[variables('location')]"
          properties:
            addressSpace:
              addressPrefixes:
                - "[variables('addressPrefix')]"
            subnets:
              -
                name: "[variables('subnetName')]"
                properties:
                  addressPrefix: "[variables('subnetPrefix')]"
        -
          type: "Microsoft.Network/networkInterfaces"
          apiVersion: "2015-05-01-preview"
          name: "[variables('nicName')]"
          location: "[variables('location')]"
          dependsOn:
            - "[concat('Microsoft.Network/publicIPAddresses/', variables('publicIPAddressName'))]"
            - "[concat('Microsoft.Network/virtualNetworks/', variables('virtualNetworkName'))]"
          properties:
            ipConfigurations:
              -
                name: "ipconfig1"
                properties:
                  privateIPAllocationMethod: "Dynamic"
                  publicIPAddress:
                    id: "[resourceId('Microsoft.Network/publicIPAddresses',variables('publicIPAddressName'))]"
                  subnet:
                    id: "[variables('subnetRef')]"
        -
          type: "Microsoft.Compute/virtualMachines"
          apiVersion: "2015-06-15"
          name: "[variables('vmName')]"
          location: "[variables('location')]"
          dependsOn:
            - "[concat('Microsoft.Storage/storageAccounts/', parameters('newStorageAccountName'))]"
            - "[concat('Microsoft.Network/networkInterfaces/', variables('nicName'))]"
          properties:
            hardwareProfile:
              vmSize: "[variables('vmSize')]"
            osProfile:
              computername: "[variables('vmName')]"
              adminUsername: "[parameters('adminUsername')]"
              adminPassword: "[parameters('adminPassword')]"
            storageProfile:
              imageReference:
                publisher: "[variables('imagePublisher')]"
                offer: "[variables('imageOffer')]"
                sku: "[parameters('ubuntuOSVersion')]"
                version: "latest"
              osDisk:
                name: "osdisk"
                vhd:
                  uri: "[concat('http://',parameters('newStorageAccountName'),'.blob.core.windows.net/',variables('vmStorageAccountContainerName'),'/',variables('OSDiskName'),'.vhd')]"
                caching: "ReadWrite"
                createOption: "FromImage"
            networkProfile:
              networkInterfaces:
                -
                  id: "[resourceId('Microsoft.Network/networkInterfaces',variables('nicName'))]"
            diagnosticsProfile:
              bootDiagnostics:
                enabled: "true"
                storageUri: "[concat('http://',parameters('newStorageAccountName'),'.blob.core.windows.net')]"
    parameters:
      newStorageAccountName:
        value: devopsclestorage
      adminUsername:
        value: devopscle
      adminPassword:
        value: Password1!
      dnsNameForPublicIP:
        value: devopscleazure
'''

try:
    import time
    import yaml
    import requests
    import azure
    from itertools import chain
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.resource import ResourceManagementClient

    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

AZURE_URL = "https://management.azure.com"
DEPLOY_URL_FORMAT = "/subscriptions/{}/resourcegroups/{}/providers/microsoft.resources/deployments/{}?api-version={}"
API_VERSION = "2014-01-01"


def get_token(domain_or_tenant, client_id, client_secret):
    """
    Get an Azure Active Directory token for a service principal
    :param domain_or_tenant: The domain or tenant id of your Azure Active Directory instance
    :param client_id: The client id of your application in Azure Active Directory
    :param client_secret: One of the application secrets created in your Azure Active Directory application
    :return: an authenticated bearer token to be used with requests to the API
    """
    #  the client id we can borrow from azure xplat cli
    grant_type = 'client_credentials'
    token_url = 'https://login.microsoftonline.com/{}/oauth2/token'.format(domain_or_tenant)

    payload = {
        'grant_type': grant_type,
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://management.core.windows.net/'
    }

    res = requests.post(token_url, data=payload)
    return res.json()['access_token'] if res.status_code == 200 else None


def get_azure_connection_info(module):
    azure_url = module.params.get('azure_url')
    tenant_or_domain = module.params.get('tenant_or_domain')
    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_secret')
    security_token = module.params.get('security_token')
    resource_group_name = module.params.get('resource_group_name')
    subscription_id = module.params.get('subscription_id')

    if not azure_url:
        if 'AZURE_URL' in os.environ:
            azure_url = os.environ['AZURE_URL']
        else:
            azure_url = None

    if not subscription_id:
        if 'AZURE_SUBSCRIPTION_ID' in os.environ:
            subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
        else:
            subscription_id = None

    if not resource_group_name:
        if 'AZURE_RESOURCE_GROUP_NAME' in os.environ:
            resource_group_name = os.environ['AZURE_RESOURCE_GROUP_NAME']
        else:
            resource_group_name = None

    if not security_token:
        if 'AZURE_SECURITY_TOKEN' in os.environ:
            security_token = os.environ['AZURE_SECURITY_TOKEN']
        else:
            security_token = None

    if not tenant_or_domain:
        if 'AZURE_TENANT_ID' in os.environ:
            tenant_or_domain = os.environ['AZURE_TENANT_ID']
        elif 'AZURE_DOMAIN' in os.environ:
            tenant_or_domain = os.environ['AZURE_DOMAIN']
        else:
            tenant_or_domain = None

    if not client_id:
        if 'AZURE_CLIENT_ID' in os.environ:
            client_id = os.environ['AZURE_CLIENT_ID']
        else:
            client_id = None

    if not client_secret:
        if 'AZURE_CLIENT_SECRET' in os.environ:
            client_secret = os.environ['AZURE_CLIENT_SECRET']
        else:
            client_secret = None

    return dict(azure_url=azure_url,
                tenant_or_domain=tenant_or_domain,
                client_id=client_id,
                client_secret=client_secret,
                security_token=security_token,
                resource_group_name=resource_group_name,
                subscription_id=subscription_id)


def build_deployment_body(module):
    """
    Build the deployment body from the module parameters
    :param module: Ansible module containing the validated configuration for the deployment template
    :return: body as dict
    """
    properties = dict(mode='Incremental')
    properties['templateLink'] = \
        dict(uri=module.params.get('template_link'),
             contentVersion=module.params.get('content_version'))

    properties['parametersLink'] = \
        dict(uri=module.params.get('parameters_link'),
             contentVersion=module.params.get('content_version'))

    return dict(properties=properties)


def follow_deployment(client, group_name, deployment):
    state = deployment.properties.provisioning_state
    if state == azure.mgmt.common.OperationStatus.Failed or \
                    state == azure.mgmt.common.OperationStatus.Succeeded or \
                    state == "Canceled" or \
                    state == "Deleted":
        return deployment
    else:
        time.sleep(30)
        result = client.deployments.get(group_name, deployment.name)
        return follow_deployment(client, group_name, result.deployment)


def follow_delete(client, location):
    result = client.get_long_running_operation_status(location)
    if result.status == azure.mgmt.common.OperationStatus.Succeeded:
        return True
    elif result.status == azure.mgmt.common.OperationStatus.Failed:
        return False
    else:
        time.sleep(30)
        return follow_delete(client, location)


def deploy_template(module, client, conn_info):
    """
    Deploy the targeted template and parameters
    :param module: Ansible module containing the validated configuration for the deployment template
    :param client: resource management client for azure
    :param conn_info: connection info needed
    :return:
    """

    deployment_name = conn_info["deployment_name"]
    group_name = conn_info["resource_group_name"]

    deploy_parameter = azure.mgmt.resource.DeploymentProperties()
    deploy_parameter.mode = azure.mgmt.resource.DeploymentMode.incremental

    if module.params.get('parameters_link') is None:
        deploy_parameter.parameters = json.dumps(module.params.get('parameters'), ensure_ascii=False)
    else:
        parameters_link = azure.mgmt.resource.ParametersLink()
        parameters_link.uri = module.params.get('parameters_link')
        deploy_parameter.parameters_link = parameters_link

    if module.params.get('template_link') is None:
        deploy_parameter.template = json.dumps(module.params.get('template'), ensure_ascii=False)
    else:
        template_link = azure.mgmt.resource.TemplateLink()
        template_link.uri = module.params.get('template_link')
        deploy_parameter.template_link = template_link

    deployment = azure.mgmt.resource.Deployment(properties=deploy_parameter)
    params = azure.mgmt.resource.ResourceGroup(location=module.params.get('location'), tags=module.params.get('tags'))
    try:
        client.resource_groups.create_or_update(group_name, params)
        result = client.deployments.create_or_update(group_name, deployment_name, deployment)
        return follow_deployment(client, group_name, result.deployment)
    except azure.common.AzureHttpError as e:
        module.fail_json(msg='Deploy create failed with status code: %s and message: "%s"' % (e.status_code, e.message))


def deploy_url(subscription_id, resource_group_name, deployment_name, api_version=API_VERSION):
    return AZURE_URL + DEPLOY_URL_FORMAT.format(subscription_id, resource_group_name, deployment_name, api_version)


def default_headers(token, with_content=False):
    headers = {'Authorization': 'Bearer {}'.format(token), 'Accept': 'application/json'}
    if with_content:
        headers['Content-Type'] = 'application/json'
    return headers


def destroy_template(module, client, conn_info):
    """
    Destroy the targeted deployment
    :param module: ansible module
    :param client: resource management client for azure
    :param conn_info: connection info needed
    :return: final response after destruction
    """

    try:
        client.resource_groups.get(conn_info['resource_group_name'])
    except azure.common.AzureMissingResourceHttpError:
        return True

    try:
        url = deploy_url(conn_info['subscription_id'], conn_info['resource_group_name'], conn_info["deployment_name"])
        res = requests.delete(url, headers=default_headers(conn_info['security_token']))
        if res.status_code == 404 or res.status_code == 204:
            return True

        if res.status_code == 202:
            location = res.headers['location']
            return follow_delete(client, location)

        if res.status_code == requests.codes.ok:
            return True
        else:
            module.fail_json(
                msg='Delete deploy failed with status code: %s and message: %s' % (res.status_code, res.text))
    except azure.common.AzureHttpError as e:
        if e.status_code == 404 or e.status_code == 204:
            return True
        else:
            module.fail_json(
                msg='Delete deploy failed with status code: %s and message: %s' % (e.status_code, e.message))


def get_dependencies(dep_tree, resource_type):
    matches = [value for value in dep_tree.values() if value['dep'].resource_type == resource_type]
    for child_tree in [value['children'] for value in dep_tree.values()]:
        matches += get_dependencies(child_tree, resource_type)
    return matches


def build_hierarchy(module, dependencies, tree=None):
    tree = dict(top=True) if tree is None else tree
    for dep in dependencies:
        if dep.resource_name not in tree:
            tree[dep.resource_name] = dict(dep=dep, children=dict())
        if isinstance(dep, azure.mgmt.resource.Dependency) and dep.depends_on is not None and len(dep.depends_on) > 0:
            build_hierarchy(module, dep.depends_on, tree[dep.resource_name]['children'])

    if 'top' in tree:
        tree.pop('top', None)
        keys = list(tree.keys())
        for key1 in keys:
            for key2 in keys:
                if key2 in tree and key1 in tree[key2]['children']:
                    tree[key2]['children'][key1] = tree[key1]
                    tree.pop(key1)
    return tree


class ResourceId:
    def __init__(self, **kwargs):
        self.resource_name = kwargs.get('resource_name')
        self.resource_provider_api_version = kwargs.get('api_version')
        self.resource_provider_namespace = kwargs.get('resource_namespace')
        self.resource_type = kwargs.get('resource_type')
        self.parent_resource_path = kwargs.get('parent_resource_path')
        pass


def get_resource_details(client, group, name, resource_type, namespace, api_version):
    res_id = ResourceId(resource_name=name, api_version=api_version, resource_namespace=namespace,
                        resource_type=resource_type)
    return client.resources.get(group, res_id).resource


def get_ip_dict(ip):
    p = json.loads(ip.properties)
    d = p['dnsSettings']
    return dict(name=ip.name,
                id=ip.id,
                public_ip=p['ipAddress'],
                public_ip_allocation_method=p['publicIPAllocationMethod'],
                dns_settings=d)


def get_instances(module, client, group, deployment):
    dep_tree = build_hierarchy(module, deployment.properties.dependencies)
    vms = get_dependencies(dep_tree, resource_type="Microsoft.Compute/virtualMachines")

    vms_and_ips = [(vm, get_dependencies(vm['children'], "Microsoft.Network/publicIPAddresses")) for vm in vms]
    vms_and_ips = [(vm['dep'], [get_resource_details(client,
                                                     group,
                                                     ip['dep'].resource_name,
                                                     "publicIPAddresses",
                                                     "Microsoft.Network",
                                                     "2015-05-01-preview") for ip in ip_list]) for vm, ip_list in vms_and_ips if len(ip_list) > 0]

    return [dict(vm_name=vm.resource_name, ips=[get_ip_dict(ip) for ip in ips]) for vm, ips in vms_and_ips]


def main():
    argument_spec = dict(
        azure_url=dict(default=AZURE_URL),
        subscription_id=dict(required=True),
        deployment_name=dict(required=True),
        client_secret=dict(no_log=True),
        client_id=dict(),
        tenant_or_domain=dict(),
        security_token=dict(aliases=['access_token'], no_log=True),
        resource_group_name=dict(required=True),
        state=dict(default='present', choices=['present', 'absent']),
        template=dict(default=None, type='dict'),
        parameters=dict(default=None, type='dict'),
        template_link=dict(default=None),
        parameters_link=dict(default=None),
        location=dict(default="West US")
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['template_link', 'template'], ['parameters_link', 'parameters']],
    )

    conn_info = get_azure_connection_info(module)

    if conn_info['security_token'] is None and \
            (conn_info['client_id'] is None or conn_info['client_secret'] is None or conn_info[
                'tenant_or_domain'] is None):
        module.fail_json(msg='security token or client_id, client_secret and tenant_or_domain is required')

    if not HAS_DEPS:
        module.fail_json(msg='requests and azure are required for this module')

    if conn_info['security_token'] is None:
        conn_info['security_token'] = get_token(conn_info['tenant_or_domain'],
                                                conn_info['client_id'],
                                                conn_info['client_secret'])

    if conn_info['security_token'] is None:
        module.fail_json(msg='failed to retrieve a security token from Azure Active Directory')

    credentials = SubscriptionCloudCredentials(module.params.get('subscription_id'), conn_info['security_token'])
    resource_client = ResourceManagementClient(credentials)
    conn_info['deployment_name'] = module.params.get('deployment_name')

    if module.params.get('state') == 'present':
        deployment = deploy_template(module, resource_client, conn_info)
        data = dict(name=deployment.name,
                    group_name=conn_info['resource_group_name'],
                    id=deployment.id,
                    outputs=deployment.properties.outputs,
                    instances=get_instances(module, resource_client, conn_info['resource_group_name'], deployment),
                    changed=True,
                    msg='deployment created')
        module.exit_json(**data)
    else:
        destroy_template(module, resource_client, conn_info)
        module.exit_json(changed=True, msg='deployment deleted')


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
