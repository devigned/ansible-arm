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
    default: null
  template_link:
    description:
      - Location of file containing the template body. This parameter is mutually exclusive with 'template'. Either one
        of them is required if "state" parameter is "present"
    required: false
    default: null
  parameters:
    description:
      - a list of hashes of all the template variables for the deployment template
    required: false
    default: {}
  parameters_link:
    description:
      - Location of file containing the parameters body. This parameter is mutually exclusive with 'parameters'. Either
        one of them is required if "state" parameter is "present"
    required: false
    default: null
  location:
    description:
      - Where the resource group should live
    require: false
    default: West US
  tags:
    description:
      - Tags to associate to the resource group
    require: false
    default: {}

author: "David Justice (@devigned)"
'''

EXAMPLES = '''
# destroy a template deployment
- name: Destroy Azure Deploy
  azure_deploy:
    state: absent
    subscription_id: subscription_id
    resource_group_name: dev-ops-cle
    deployment_name: test01

# create or update a template deployment based on uris to paramters and a template
- name: Create Azure Deploy
  azure_deploy:
    state: present
    subscription_id: subscription_id
    resource_group_name: dev-ops-cle
    deployment_name: test01
    parameters_link: 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-simple-linux-vm/azuredeploy.parameters.json'
    template_link: 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-simple-linux-vm/azuredeploy.json'
'''

try:
    import time
    import yaml
    import requests
    import azure
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
        deploy_parameter.parameters = module.params.get('parameters')
    else:
        parameters_link = azure.mgmt.resource.ParametersLink()
        parameters_link.uri = module.params.get('parameters_link')
        deploy_parameter.parameters_link = parameters_link

    if module.params.get('template_link') is None:
        deploy_parameter.template = module.params.get('template')
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
        location=dict(default="West US"),
        tags=dict(type='dict', default=dict())
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['template_link', 'template'], ['parameters_link', 'parameters']],
    )

    conn_info = get_azure_connection_info(module)

    if conn_info['security_token'] is None and (
                        conn_info['client_id'] is None or conn_info['client_secret'] is None or conn_info[
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

    creds = SubscriptionCloudCredentials(module.params.get('subscription_id'), conn_info['security_token'])
    resource_client = ResourceManagementClient(creds)
    conn_info['deployment_name'] = module.params.get('deployment_name')

    if module.params.get('state') == 'present':
        deployment = deploy_template(module, resource_client, conn_info)
        data = dict(name=deployment.name,
                    group_name=conn_info['resource_group_name'],
                    id=deployment.id,
                    outputs=deployment.properties.outputs,
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
