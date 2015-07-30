#!/usr/bin/python
DOCUMENTATION = '''
---
module: azure_arm
short_description: Provision and Read Azure resources via the Azure Resource Manager REST API
version_added: "2.0"
description:

'''

import datetime
import yaml

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

MGMT_URL = "https://management.azure.com"
API_VERSION = "2014-01-01"


def get_token(domain_or_tenant, client_id, client_secret):
    '''
    Get an Azure Active Directory token for a service principal
    :param domain_or_tenant: The domain or tenant id of your Azure Active Directory instance
    :param client_id: The client id of your application in Azure Active Directory
    :param client_secret: One of the application secrets created in your Azure Active Directory application
    :return: an authenticated bearer token to be used with requests to the API
    '''
    #  the client id we can borrow from azure xplat cli
    grant_type = 'client_credentials'
    token_url = 'https://login.microsoftonline.com/{}/oauth2/token'.format(domain_or_tenant)

    payload = {
        'grant_type': grant_type,
        'client_id': client_id,
        'client_secret': client_secret,
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


def main():
    module = AnsibleModule(
        argument_spec=dict(
            creds_file=dict(),
            client_id=dict(),
            client_secret=dict(),
            tenant_or_domain=dict()
        )
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests required for this module')

    if module.params['creds_file'] is None and (
                    module.params['client_id'] or module.params['client_secret'] or module.params['tenant_or_domain']):
        module.fail_json(
            msg="you must specify either a creds_file or each of the following, client_id, client_secret, domain_or_tenant")

    date = str(datetime.datetime.now())
    print json.dumps({
        "time": date
    })

    with open(module.params['creds_file'], 'r') as stream:
        creds = yaml.safe_load(stream)

    get_token(creds['domain_or_tenant'], creds['client_id'], creds['client_secret'])


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
