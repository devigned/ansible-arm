#!/usr/bin/python
DOCUMENTATION = '''
---
module: azure_deploy
short_description: Provision and Read Azure resources via the Azure Resource Manager REST API
version_added: "2.0"
description:
     - Launches or destroys an Azure deployment template
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
  template_format:
    description: For local templates, allows specification of json or yaml format
    default: json
    choices: [ json, yaml ]
    required: false
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
  content_version:
    description:
      - Version of the content inside of the template
    require: false
    default: 1.0.0.0
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
'''
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

AZURE_URL = "https://management.azure.com"
DEPLOY_URL_FORMAT = "/subscriptions/{}/resourcegroups/{}/providers/microsoft.resources/deployments/{}?api-version={}"
API_VERSION = "2014-01-01"

FINAL_STATES = ['Created', 'Deleted', 'Canceled', 'Failed', 'Succeeded']
INTERMEDIATE_STATES = ['NotSpecified', 'Accepted', 'Running', 'Registering', 'Creating', 'Deleting']


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
    response = requests.post(token_url, data=payload).json()
    return response['access_token']


class ProvisioningState(object):
    """
     Common provisioning states.
    """
    not_specified = 'NotSpecified'
    accepted = 'Accepted'
    running = 'Running'
    registering = 'Registering'
    creating = 'Creating'
    created = 'Created'
    deleting = 'Deleting'
    deleted = 'Deleted'
    canceled = 'Canceled'
    failed = 'Failed'
    succeeded = 'Succeeded'


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


def deploy_url(subscription_id, resource_group_name, deployment_name, api_version=API_VERSION):
    return AZURE_URL + DEPLOY_URL_FORMAT.format(subscription_id, resource_group_name, deployment_name, api_version)


def resource_group_url(subscription_id, resource_group_name, api_version=API_VERSION):
    return AZURE_URL + "/subscriptions/{}/resourcegroups/{}?api-version={}".format(subscription_id, resource_group_name, api_version)


def default_headers(token, with_content=False):
    headers = {'Authorization': 'Bearer {}'.format(token), 'Accept': 'application/json'}
    if with_content:
        headers['Content-Type'] = 'application/json'
    return headers


def build_deployment_body(module):
    """
    Build the deployment body from the module parameters
    :param module: Ansible module containing the validated configuration for the deployment template
    :return: body as dict
    """
    properties = dict(mode='Incremental')
    if module.params.get('template'):
        properties['template'] = module.params.get('template')
    else:
        properties['templateLink'] = \
            dict(uri=module.params.get('template_link'),
                 contentVersion=requests.get(module.params.get('template_link')).json()['contentVersion'])

    if module.params.get('parameters'):
        properties['parameters'] = module.params.get('parameters')
    else:
        properties['parametersLink'] = \
            dict(uri=module.params.get('parameters_link'),
                 contentVersion=module.params.get('content_version'))

    return dict(properties=properties)


def deploy_template(module, conn_info, name):
    """
    Deploy the targeted template and parameters
    :param module: Ansible module containing the validated configuration for the deployment template
    :param conn_info: connection info needed
    :param name: name of the deployment
    :return:
    """
    rg_url = resource_group_url(conn_info['subscription_id'], conn_info['resource_group_name'])

    if requests.get(rg_url, headers=default_headers(conn_info['security_token'])).status_code == 404:
        body = dict(location=module.params.get('location'))
        res = requests.put(rg_url, data=json.dumps(body), headers=default_headers(conn_info['security_token'], with_content=True))
        res.raise_for_status()
    url = deploy_url(conn_info['subscription_id'], conn_info['resource_group_name'], name)
    res = requests.get(url, headers=default_headers(conn_info['security_token']))
    if res.status_code == 404 or res.json()['properties']['provisioning_state'] in FINAL_STATES:
        body = build_deployment_body(module)
        res = requests.put(url,
                           headers=default_headers(conn_info['security_token'], with_content=True),
                           data=json.dumps(body))
        module.fail_json(msg=res.json())
        return handle_long_running(conn_info, res)
    else:
        res.raise_for_status()
        already_running = 'a template deployment matching subscription_id: {}, resource_group_name: {} and name: {} is already running.'.format(
            conn_info['subscription_id'], conn_info['resource_group_name'], conn_info['deployment_name'])
        module.fail_json(msg=already_running)
    return None


def destroy_template(conn_info, name):
    """
    Destroy the targeted deployment
    :param conn_info: connection info needed
    :param name: name of the deployment
    :return: final response after destruction
    """
    url = deploy_url(conn_info['subscription_id'], conn_info['resource_group_name'], name)
    res = requests.delete(url, headers=default_headers(conn_info['security_token']))
    if res.status_code != 404:
        res.raise_for_status()
        return handle_long_running(conn_info, res)
    return res


def handle_long_running(conn_info, res):
    """
    Chase the long running operation eventually returning the state after it has settled
    :param conn_info: the information we need to connect to azure
    :param res: the request that might be long running
    :return: the settled value of deployed template
    """
    if res.status_code == 202:
        location = res.headers['Location']
        res = requests.get(location, default_headers(conn_info['security_token']))
        res.raise_for_status()
        while res.status_code == 200 and res.json()['properties']['provisioning_state'] not in FINAL_STATES:
            time.sleep(20)
            res = requests.get(location, default_headers(conn_info['security_token']))
            res.raise_for_status()

        # we have reached a final state for the resource, so get the target of the operation and return it
        return requests.get(AZURE_URL + res.json()['properties']['target_resource']['id'],
                            default_headers(conn_info['security_token']))
    else:
        return res


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
        template=dict(default=None, required=False),
        template_link=dict(default=None, required=False),
        template_format=dict(default='json', choices=['json', 'yaml'], required=False),
        parameters=dict(required=False, type='dict', default={}),
        parameters_link=dict(default=None),
        content_version=dict(default='1.0.0.0'),
        location=dict(default="West US"),
        tags=dict(type='dict', default=dict())
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['template_link', 'template'], ['parameters_link', 'parameters']],
    )

    conn_info = get_azure_connection_info(module)

    if conn_info['security_token'] is None and (
                        conn_info['client_id'] is None or
                        conn_info['client_secret'] is None or
                    conn_info['tenant_or_domain'] is None):
        module.fail_json(msg='security token or client_id, client_secret and tenant_or_domain is required')

    if not HAS_REQUESTS:
        module.fail_json(msg='requests required for this module')

    if conn_info['security_token'] is None:
        conn_info['security_token'] = get_token(conn_info['tenant_or_domain'],
                                                conn_info['client_id'],
                                                conn_info['client_secret'])

    if conn_info['security_token'] is None:
        module.fail_json(msg='failed to retrieve a security token from Azure Active Directory')

    try:
        if module.params.get('state') == 'present':
            res = deploy_template(module, conn_info, module.params.get('deployment_name'))
            res.raise_for_status()
            module.exit_json(**res.json())
        else:
            destroy_template(conn_info, module.params.get('deployment_name'))
            module.exit_json(msg='deleted')
    except requests.exceptions.HTTPError:
        module.fail_json(msg='http failure {}'.format(traceback.format_exc()))

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
