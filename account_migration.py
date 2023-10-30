import click
import jenkins
import json
import utils
import update_permissions_for_ad_roles as update_roles
import requests

from policies.bdd_utils import behave_utils
from cloudx_sls_authorization.create_token import get_bearer_token
from time import sleep

def get_appsync_conn(env='prod', secret=None):
    secrets_client = behave_utils.get_connection('itx-abp', 'secretsmanager', 'us-east-1')
    appsync_conn_info = json.loads(secrets_client.get_secret_value(SecretId=secret,
                                                                   VersionStage='AWSCURRENT'
                                                                   ).get('SecretString'))
    return appsync_conn_info


def get_account_by_proj_id(projid, appsync_conn_info):
    params = {
        "project_id": projid,
    }
    query = '''
    query GetAccountByProjectId($project_id: String) {
        GetAccountByProjectId(project_id: $project_id) {
            items {
                IpList
                ami_exceptions
                applications
                aws_number
                db_service_accounts
                db_users
                dbas
                description
                ec2_security_groups
                exceptions_regex
                external_users
                log_buckets
                member_readonly_permission_exception
                new_api_users
                name
                owner
                pb_exceptions
                project_id
                redshift_service_accounts
                redshift_user_access_type
                regions
                s3_bucket_policy_admin
                s3_bucket_policy_exception_buckets
                s3x_bucket_roles
                s3x_ip_list
                services
                vpc_list
            },
            nextToken
        }
    }
    '''
    response = utils.execute_gql(
        query=query,
        variables=params,
        endpoint=appsync_conn_info.get('url'),
        key=appsync_conn_info.get('key')
    )
    # return response["data"]["GetAccountByProjectId"]["items"][0]
    if response.get("data", {}).get("GetAccountByProjectId", {}).get("items"):
        return response.get("data", {}).get("GetAccountByProjectId", {}).get("items")[0]
    return {}


def create_account(input_data, appsync_conn_info):
    """
    Insert data in accounts table

    Args:
        input_data: data dictionary
        appsync_endpoint: AppSync API endpoint
        appsync_api_key: API Key

    Returns: inserted data
    """
    # Setup query
    query = '''
            mutation CreateAccount($input: CreateAccountInput!) {
              createAccount(input: $input) {
                  id
                  aws_number 
                  project_id
                  owner 
                  regions
                  log_buckets
              }
            }
            '''
    # Setup headers

    # Setup variables
    variables = {
        "input": input_data
    }
    # Send request
    response = utils.execute_gql(
        query=query,
        variables=variables,
        endpoint=appsync_conn_info.get('url'),
        key=appsync_conn_info.get('key')
    )
    return response


def create_s3_exception_list(input_data, appsync_conn_info):
    """
    Insert data in accounts table

    Args:
        input_data: data dictionary
        appsync_endpoint: AppSync API endpoint
        appsync_api_key: API Key

    Returns: inserted data
    """
    # Setup query
    query = '''
        mutation CreateRule($input: CreateS3BucketExceptionRuleInput!) {
          createS3BucketExceptionRule(input: $input) {
            rule_name
            bucket_roles
            ip_list
            public
            ssl
            vpce_list
          }
        }
    '''

    # Setup variables
    variables = {
        "input": input_data
    }
    # Send request
    response = utils.execute_gql(
        query=query,
        variables=variables,
        endpoint=appsync_conn_info.get('url'),
        key=appsync_conn_info.get('key')
    )
    return response


def get_s3_exception_list(account, appsync_conn_info):
    """
    Insert data in accounts table

    Args:
        input_data: data dictionary
        appsync_endpoint: AppSync API endpoint
        appsync_api_key: API Key

    Returns: inserted data
    """
    # Setup query
    query = '''
        query MyQuery {
          listS3BucketExceptionRules(filter: {rule_name: {beginsWith: "input"}}) {
            items {
              bucket_roles
              ip_list
              public
              rule_name
              ssl
              vpce_list
            }
          }
        }'''

    query = query.replace('input', account)
    # Send request
    response = utils.execute_gql(
        query=query,
        variables=None,
        endpoint=appsync_conn_info.get('url'),
        key=appsync_conn_info.get('key')
    )
    return response


def get_jenkins_client_key():
    """
    Get jenkins creds from secret manager
    Args:
        aws_client:

    Returns:

    """
    secrets_client = behave_utils.get_connection1('itx-wab', 'secretsmanager', 'us-east-1')
    return secrets_client.get_secret_value(
        SecretId='jntlch/clx-awsapi-jenkins', VersionStage='AWSCURRENT').get('SecretString')


def get_jenkins_secret_info():
    """
    Get jenkins creds from secret manager
    Args:
        aws_client:

    Returns:

    """
    secrets_client = behave_utils.get_connection('itx-aaa', 'secretsmanager', 'us-east-1')
    return json.loads(secrets_client.get_secret_value(
        SecretId='JenkinsTrigger', VersionStage='AWSCURRENT').get('SecretString'))


def execute_jenkins_for_an_account(account):
    user_info = get_jenkins_secret_info()
    username = user_info['username']
    password = user_info['password']
    authenticationtoken = user_info['authtoken']
    jenkins_url = 'https://jenkins.eat.jnj.com/taam-dev'
    job_name = 'awsapi-Deployment-Jobs/nextbot-pipeline-ch-py3_9'
    branch_name = 'origin/master'
    try:
        print(jenkins_url)
        server = jenkins.Jenkins(jenkins_url, username=username, password=password)
    except Exception as e:
        print(f'failed to connect to jenkins. Error {e}')
        return

    parameters = {
        'IS_AMPLIFY_CHANGE': False,
        'APP_NAME': 'custodian',
        'ENV': 'prod',
        'IS_PREMERGE': False,
        'RUN_UNIT_TEST': False,
        'IS_C7N_PLUGIN_CHANGE': False,
        'IS_QUALMAP_CHANGE': False,
        'RUN_LINT': False,
        'BRANCH': branch_name,
        'IS_C7N_SCP_CHANGE': False,
        'POST_MERGE': False,
        'IS_C7N_POLICY_CHANGE': False,
        'RUN_ALL_C7N_BEHAVE_TESTS': False,
        'IS_SINGLE_ACCOUNT_CHANGE': True,
        'POLICIES_CHANGED': 'bdd_utils iam',
        'ProjectId': account
    }
    resp = server.build_job(job_name, parameters, token=authenticationtoken)
    build_id = server.get_queue_item(resp)['executable']['number']
    while True:
        resp = server.get_build_info(job_name, build_id)
        if resp['result'] == 'SUCCESS':
            print('successfully executed jenkins pipeline')
            break
        elif resp['result'] == 'FAILURE':
            print('jenkins pipeline execution failed')
            break
        else:
            print('jenkins pipeline still running, will check after 1 min')
            sleep(60)



def execute_jenkins_for_all_account(account):
    user_info = get_jenkins_secret_info()
    username = user_info['username']
    password = user_info['password']
    authenticationtoken = user_info['authtoken']
    jenkins_url = 'https://jenkins.eat.jnj.com/taam-dev'
    job_name = 'awsapi-Deployment-Jobs/aws-nextBot-pipeline'
    branch_name = 'origin/master'
    try:
        print(jenkins_url)
        server = jenkins.Jenkins(jenkins_url, username=username, password=password)
    except Exception as e:
        print('failed to connect to jenkins')
        return

    parameters = {
        'IS_AMPLIFY_CHANGE': False,
        'APP_NAME': 'custodian',
        'ENV': 'prod',
        'IS_PREMERGE': False,
        'RUN_UNIT_TEST': False,
        'IS_C7N_PLUGIN_CHANGE': True,
        'IS_QUALMAP_CHANGE': False,
        'RUN_LINT': False,
        'BRANCH': branch_name,
        'IS_C7N_SCP_CHANGE': False,
        'POST_MERGE': False,
        'IS_C7N_POLICY_CHANGE': False,
        'RUN_ALL_C7N_BEHAVE_TESTS': False,
        'IS_SINGLE_ACCOUNT_CHANGE': False,
        'PLUGINSS_CHANGED': 'utils'
    }
    resp = server.build_job(job_name, parameters, token=authenticationtoken)
    print('successfully triggered jenkins pipeline')


@click.command()
@click.option('-a', '--account', required=True, help='jnj project id')
@click.option('-c', '--clean', default=False, help='clean jnj metadata')
@click.option('-t', '--type', required=True, type=click.Choice(['self', 'full']))
def run(account, clean, type):

    # check if AD groups exists in JX2

    # move account from JNJ to CH Org
    account_org = behave_utils.get_connection(account, 'organizations', 'us-east-1')
    account_sts = behave_utils.get_connection(account, 'sts', 'us-east-1')
    ch_org = behave_utils.get_connection1('itx-waa', 'organizations', 'us-east-1')

    account_num = account_sts.get_caller_identity().get('Account')
    if not account_num:
        print(f'failed to migrate account {account}')
        input(f'Please move account {account} to CH org manually. Press any button to continue.')

    # add the default RDS permissions tag
    jnj_s3_res = behave_utils.get_resource_connection('itx-abp', 's3', 'us-east-1')
    dbuser_access_type = 'read_only'
    try:
        obj = jnj_s3_res.Object('itx-projects-rdsx', account)
        data = obj.get()['Body'].read().decode('utf-8')
        json_data = json.loads(data)
        dbuser_access_type = json_data.get('DBUserPreference', 'read_only')
    except Exception as e:
        if 'NoSuchKey' in str(e):
            pass

    # ch_org.invite_account_to_organization(
    #     Target={
    #         'Id': account_num,
    #         'Type': 'ACCOUNT'
    #     },
    #     Tags=[
    #         {
    #             'Key': 'dbuser_access_type',
    #             'Value': dbuser_access_type
    #         }
    #     ]
    # )

    # invite_id = account_org.list_handshakes_for_account(
    #     Filter={
    #         'ActionType': 'INVITE'
    #     }
    # ).get('Handshakes', [{}])[0].get('Id')
    # if invite_id:
    #     account_org.leave_organization()
    #
    #     account_org.accept_handshake(
    #         HandshakeId=invite_id
    #     )
    # else:
    #     print(f'invite id not found. Please move the account {account} manually')
    #     input('press enter once account is moved to new org')
    #
    # ou_map = {
    #     "self": "ou-n8hc-6o55vour",
    #     "full": "ou-n8hc-38v108t1"
    # }
    #
    # ch_org.move_account(
    #     AccountId=account_num,
    #     SourceParentId='r-n8hc',
    #     DestinationParentId=ou_map.get(type)
    # )
    # print("Account added to new org successfully")

    # # get appsync connections
    # jnj_appsync_info = get_appsync_conn(secret='NextBot/AppSync')
    # ch_appsync_info = get_appsync_conn(secret='NextBot/AppSync-ch')
    #
    # # read the account data from jnj appsync
    # jnj_data = get_account_by_proj_id(account, jnj_appsync_info)
    #
    # # write the account data to CH appsync
    # ch_account = get_account_by_proj_id(account, ch_appsync_info)
    # if not ch_account:
    #     resp = create_account(jnj_data, appsync_conn_info=ch_appsync_info)
    #     print(resp)
    #     ch_appsync_account_id = resp.get('data', {}).get('createAccount').get('id')
    # else:
    #     ch_appsync_account_id = ch_account.get('id')
    # print("Account data added to appsync successfully")
    #
    # # migrate any s3 related appsync info
    # s3_exceptions_resp = get_s3_exception_list(account, jnj_appsync_info)
    # s3_exceptions = s3_exceptions_resp.get('data', {}).get('listS3BucketExceptionRules', {}).get('items', [])
    #
    # for s3_exception in s3_exceptions:
    #     s3_exception['s3BucketExceptionRuleAccountId'] = ch_appsync_account_id
    #     create_s3_exception_list(s3_exception, ch_appsync_info)
    # print("S3 data added to appsync successfully")
    #
    # # copy account file from jnj s3 and store it in ch s3
    # jnj_s3 = behave_utils.get_connection('itx-abp', 's3', 'us-east-1')
    # ch_s3 = behave_utils.get_connection1('itx-wab', 's3', 'us-east-1')
    #
    # jnj_s3.download_file(Bucket='itx-accounts', Key=account, Filename=account)
    # ch_s3.upload_file(Filename=account, Bucket='itx-accounts-ch', Key=account)
    # print("accounts file uploaded successfully")
    #
    # # migrate EC2 related info
    # jnj_dynamo = behave_utils.get_connection('itx-abp', 'dynamodb', 'us-east-1')
    # ch_dynamo = behave_utils.get_connection1('itx-wab', 'dynamodb', 'us-east-1')
    #
    # jnj_data = jnj_dynamo.query(
    #     TableName='ec2_instances',
    #     KeyConditionExpression='project_id = :project_id',
    #     ExpressionAttributeValues={
    #         ':project_id': {'S': account}
    #     }
    # )
    #
    # for item in jnj_data.get('Items', []):
    #     if item.get('State', {}).get('S', '').lower() != 'terminated':
    #         ch_dynamo.put_item(
    #             TableName='ec2_instances',
    #             Item={
    #                 "project_id": {"S": account},
    #                 "region": item.get('region'),
    #                 "InstanceId": item.get('InstanceId'),
    #                 "PrivateIpAddress": item.get('PrivateIpAddress'),
    #                 "ImageId": item.get('ImageId'),
    #                 "update_ts": item.get('LaunchTime'),
    #                 "Hostname": item.get('Hostname', '')
    #             }
    #         )
    # print("ec2 data uploaded successfully")

    # TODO: run rds and redshift migration script -- this will migrate the SA, Users and Master pwd -- Murali
    # TODO: update the account table and db tables with required details

    # delete existing user roles
    # account_iam = behave_utils.get_connection(account, 'iam', 'us-east-1')
    # current_roles = []
    # token = None
    # while True:
    #     if not token:
    #         resp = account_iam.list_roles(
    #             PathPrefix='/project/owner/'
    #         )
    #     else:
    #         resp = account_iam.list_roles(
    #             PathPrefix='/project/owner/',
    #             Marker=token
    #         )
    #     current_roles.extend(resp.get('Roles', []))
    #     if resp.get('Marker'):
    #         token = resp.get('Marker')
    #     else:
    #         break
    #
    # token = None
    # while True:
    #     if not token:
    #         resp = account_iam.list_roles(
    #             PathPrefix='/project/member/'
    #         )
    #     else:
    #         resp = account_iam.list_roles(
    #             PathPrefix='/project/member/',
    #             Marker=token
    #         )
    #     current_roles.extend(resp.get('Roles', []))
    #     if resp.get('Marker'):
    #         token = resp.get('Marker')
    #     else:
    #         break
    #
    # for role in current_roles:
    #     inline_policies = []
    #     managed_policies = []
    #
    #     token = None
    #     while True:
    #         if not token:
    #             resp = account_iam.list_role_policies(
    #                 RoleName=role.get('RoleName')
    #             )
    #         else:
    #             resp = account_iam.list_role_policies(
    #                 RoleName=role.get('RoleName'),
    #                 Marker=token
    #             )
    #         inline_policies.extend(resp.get('PolicyNames', []))
    #         if resp.get('Marker'):
    #             token = resp.get('Marker')
    #         else:
    #             break
    #
    #     token = None
    #     while True:
    #         if not token:
    #             resp = account_iam.list_attached_role_policies(
    #                 RoleName=role.get('RoleName')
    #             )
    #         else:
    #             resp = account_iam.list_attached_role_policies(
    #                 RoleName=role.get('RoleName'),
    #                 Marker=token
    #             )
    #         managed_policies.extend(resp.get('AttachedPolicies', []))
    #         if resp.get('Marker'):
    #             token = resp.get('Marker')
    #         else:
    #             break
    #
    #     for inline_policy in inline_policies:
    #         account_iam.delete_role_policy(
    #             RoleName=role.get('RoleName'),
    #             PolicyName=inline_policy
    #         )
    #
    #     for managed_policy in managed_policies:
    #         account_iam.detach_role_policy(
    #             RoleName=role.get('RoleName'),
    #             PolicyArn=managed_policy.get('PolicyArn')
    #         )
    #
    #     account_iam.delete_role_permissions_boundary(
    #         RoleName=role.get('RoleName')
    #     )
    #
    #     account_iam.delete_role(
    #         RoleName=role.get('RoleName')
    #     )
    # print("existing user roles deleted successfully")

    # run iam sync
    # call the api directly - this way we'll know when sync is done and can run the next script
    token = get_bearer_token('https://clx-awsapi-jenkins-prod.jntlch.com', logoff(),
                             "https://login.microsoftonline.com/7ba64ac2-8a2b-417e-9b8f-fcf8238f2a56/oauth2/v2.0/token",
                             'https://clx-awsapi-ad-sync-internal-prod.jntlch.com/.default')
    url = f'https://chawsapi.apps.jnj.com/aws-ad-sync-service/v1/accounts/{account}/sync-idm'
    headers = {
        'Authorization': token
    }
    count = 0
    while True:
        response = requests.post(url, headers=headers, verify=False)
        status_code = response.status_code
        response_text = response.text
        count = count + 1
        if status_code == 200:
            # run ad-sync permissions migration script
            update_roles.main('prod', account)
            print("user roles created and updated successfully")
        else:
            # might take multiple runs of the api to sync all users since timeout is 1min
            if count == 5:
                print(f'Sync user API failed for {account}. Error: {response_text}')
                break
            else:
                continue

    # TODO: VPC migration - Pullan

    # execute jenkins c7n pipeline
    try:
        execute_jenkins_for_an_account(account)
    except Exception as e:
        print('failed to trigger or check status of jenkins - please verify manually')
        input('hit enter to continue')

    if clean:
        # take backup and delete JNJ proj_info data
        jnj_prj_data = jnj_dynamo.query(
            TableName='project_info',
            KeyConditionExpression='Id = :project_id',
            ExpressionAttributeValues={
                ':project_id': {'S': account}
            }
        )
        jnj_s3.put_object(Body=json.dumps(jnj_prj_data),
                          Bucket='itx-abp-ch-project-info-backup',
                          Key=account)
        print("project info entry backed up successfully")

        jnj_dynamo.delete_item(
            TableName='project_info',
            Key={
                'Id': {'S': account}
            }
        )
        print("project info entry deleted successfully")

        # delete appsync data
        # delete account bucket data

if __name__ == "__main__":
    run()
