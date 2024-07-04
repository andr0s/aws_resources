import argparse
import configparser
import os.path

import boto3


class TextColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Variables Exported
credentials_file_path = "~/.aws/credentials"


# Function to read AWS credentials from the ~/.aws/credentials file
def read_aws_credentials(config_file_path="~/.aws/config"):
    # Initialize the parser
    config = configparser.ConfigParser()

    # Read AWS credentials
    credentials_full_path = os.path.expanduser(credentials_file_path)
    config.read(credentials_full_path)
    credentials = {
        "access_key": config.get("default", "aws_access_key_id"),
        "secret_key": config.get("default", "aws_secret_access_key")
    }

    # Read AWS config for region
    config_full_path = os.path.expanduser(config_file_path)
    config.read(config_full_path)
    region = config.get("default", "region", fallback=None)

    # Return both credentials and region
    return {
        "access_key": credentials["access_key"],
        "secret_key": credentials["secret_key"],
        "region": region
    }


def get_all_regions():
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions


# Function to check EC2 resources
def check_ec2_resources():
    ec2_client = boto3.client('ec2')
    instances = ec2_client.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            print(f"Instance ID: {instance['InstanceId']} State: {instance['State']['Name']}")


# Function to check S3 resources
def check_s3_resources():
    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        print(f"Bucket Name: {bucket['Name']}")


# Function to check RDS resources
def check_rds_resources():
    rds_client = boto3.client('rds')
    dbs = rds_client.describe_db_instances()
    for db in dbs['DBInstances']:
        print(f"DB Name: {db['DBInstanceIdentifier']} Status: {db['DBInstanceStatus']}")


# Function to check DynamoDB resources
def check_dynamodb_resources():
    dynamodb_client = boto3.client('dynamodb')
    tables = dynamodb_client.list_tables()
    for table_name in tables['TableNames']:
        print(f"Table Name: {table_name}")


# Function to check all allocated Elastic IP addresses
def check_elastic_ips():
    ec2_client = boto3.client('ec2')

    # Describe Elastic IP addresses
    addresses = ec2_client.describe_addresses()

    # Loop through addresses to find allocated IPs
    for address in addresses['Addresses']:
        public_ip = address['PublicIp']
        allocation_id = address['AllocationId']
        instance_id = address.get('InstanceId', 'Not attached')
        print(f"Allocation ID: {allocation_id}, Public IP: {public_ip}, Instance ID: {instance_id}")


# Function to check Lambda resources
def check_lambda_resources():
    lambda_client = boto3.client('lambda')
    functions = lambda_client.list_functions()
    for func in functions['Functions']:
        print(f"Function Name: {func['FunctionName']} ARN: {func['FunctionArn']}")


# Function to check VPC resources
def check_vpc_resources():
    vpc_client = boto3.client('ec2')
    vpcs = vpc_client.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        print(f"VPC ID: {vpc['VpcId']} CIDR Block: {vpc['CidrBlock']}")


# Function to check CloudFront resources
def check_cloudfront_resources():
    cloudfront_client = boto3.client('cloudfront')
    distributions = cloudfront_client.list_distributions()
    for dist in distributions['DistributionList']['Items']:
        print(f"Distribution ID: {dist['Id']} Domain: {dist['DomainName']}")


# Function to check Route 53 resources
def check_route53_resources():
    route53_client = boto3.client('route53')
    zones = route53_client.list_hosted_zones()
    for zone in zones['HostedZones']:
        print(f"Zone ID: {zone['Id']} Name: {zone['Name']}")


# Function to check EBS resources
def check_ebs_resources():
    ebs_client = boto3.client('ec2')
    volumes = ebs_client.describe_volumes()
    for volume in volumes['Volumes']:
        print(f"Volume ID: {volume['VolumeId']} Size: {volume['Size']}GB")


# Function to check ELB resources
def check_elb_resources():
    elb_client = boto3.client('elbv2')  # For both Application and Network Load Balancers
    load_balancers = elb_client.describe_load_balancers()
    for lb in load_balancers['LoadBalancers']:
        print(f"Load Balancer Name: {lb['LoadBalancerName']} ARN: {lb['LoadBalancerArn']}")


# Function to check ECS resources
def check_ecs_resources():
    ecs_client = boto3.client('ecs')
    clusters = ecs_client.list_clusters()
    for cluster_arn in clusters['clusterArns']:
        print(f"Cluster ARN: {cluster_arn}")


# Function to check EKS resources
def check_eks_resources():
    eks_client = boto3.client('eks')
    clusters = eks_client.list_clusters()
    for cluster_name in clusters['clusters']:
        print(f"Cluster Name: {cluster_name}")


# Function to check Redshift resources
def check_redshift_resources():
    redshift_client = boto3.client('redshift')
    clusters = redshift_client.describe_clusters()
    for cluster in clusters['Clusters']:
        print(f"Cluster Name: {cluster['ClusterIdentifier']} Status: {cluster['ClusterStatus']}")


# Function to check SQS resources
def check_sqs_resources():
    sqs_client = boto3.client('sqs')
    queues = sqs_client.list_queues()
    if 'QueueUrls' in queues:  # Ensure queues exist
        for queue_url in queues['QueueUrls']:
            print(f"Queue URL: {queue_url}")


# Function to check SNS resources
def check_sns_resources():
    sns_client = boto3.client('sns')
    topics = sns_client.list_topics()
    for topic in topics['Topics']:
        print(f"Topic ARN: {topic['TopicArn']}")


# Function to check SES resources
def check_ses_resources():
    ses_client = boto3.client('ses')
    identities = ses_client.list_identities()
    for identity in identities['Identities']:
        print(f"Identity: {identity}")


# Function to check Elasticache resources
def check_elasticache_resources():
    elasticache_client = boto3.client('elasticache')
    clusters = elasticache_client.describe_cache_clusters()
    for cluster in clusters['CacheClusters']:
        print(f"Cluster Name: {cluster['CacheClusterId']} Status: {cluster['CacheClusterStatus']}")


# Function to check Kinesis resources
def check_kinesis_resources():
    kinesis_client = boto3.client('kinesis')
    streams = kinesis_client.list_streams()
    for stream_name in streams['StreamNames']:
        print(f"Stream Name: {stream_name}")


# Function to check Athena resources
def check_athena_resources():
    athena_client = boto3.client('athena')
    workgroups = athena_client.list_work_groups()
    for workgroup in workgroups['WorkGroups']:
        print(f"WorkGroup Name: {workgroup['Name']}")


# Function to check AWS Glue resources
def check_glue_resources():
    glue_client = boto3.client('glue')
    databases = glue_client.get_databases()
    for database in databases['DatabaseList']:
        print(f"Database Name: {database['Name']}")
    crawlers = glue_client.list_crawlers()
    for crawler_name in crawlers['CrawlerNames']:
        print(f"Crawler Name: {crawler_name}")


# Function to check Sagemaker resources
def check_sagemaker_resources():
    sagemaker_client = boto3.client('sagemaker')
    notebooks = sagemaker_client.list_notebook_instances()
    for notebook in notebooks['NotebookInstances']:
        print(f"Notebook Name: {notebook['NotebookInstanceName']} Status: {notebook['NotebookInstanceStatus']}")


# Function to check EMR resources
def check_emr_resources():
    emr_client = boto3.client('emr')
    clusters = emr_client.list_clusters()
    for cluster in clusters['Clusters']:
        print(f"Cluster Name: {cluster['Name']} Status: {cluster['Status']['State']}")


# Function to check Lex resources
def check_lex_resources():
    lex_client = boto3.client('lex-models')
    bots = lex_client.get_bots()
    for bot in bots['bots']:
        print(f"Bot Name: {bot['name']}")


# Function to check Quicksight resources
def check_quicksight_resources():
    # Quicksight requires an AWS account ID, hence we'll fetch it first.
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]

    quicksight_client = boto3.client('quicksight')
    dashboards = quicksight_client.list_dashboards(AwsAccountId=account_id)
    for dashboard in dashboards['DashboardSummaryList']:
        print(f"Dashboard Name: {dashboard['Name']}")


# Function to check Data Transfer resources
def check_data_transfer_resources():
    # Data Transfer doesn't have direct resources like other services. 
    # It's mostly related to the data transfer costs between AWS services or into/out of AWS.
    # There isn't a boto3 call to list "data transfer resources" per se. 
    # You can monitor data transfer costs via AWS Cost Explorer or similar.
    print(
        "Data Transfer does not have directly queryable resources like other services. Check AWS Cost Explorer for data transfer costs.")


# Function to check Step Functions resources
def check_step_functions_resources():
    sf_client = boto3.client('stepfunctions')
    state_machines = sf_client.list_state_machines()
    for sm in state_machines['stateMachines']:
        print(f"State Machine ARN: {sm['stateMachineArn']}")


# Function to check Direct Connect resources
def check_direct_connect_resources():
    dc_client = boto3.client('directconnect')
    connections = dc_client.describe_connections()
    for conn in connections['connections']:
        print(f"Connection ID: {conn['connectionId']}")


# Function to check CodeBuild resources
def check_codebuild_resources():
    cb_client = boto3.client('codebuild')
    projects = cb_client.list_projects()
    for project in projects['projects']:
        print(f"Project Name: {project}")


# Function to check CodeDeploy resources
def check_codedeploy_resources():
    cd_client = boto3.client('codedeploy')
    applications = cd_client.list_applications()
    for app in applications['applications']:
        print(f"Application Name: {app}")


# Function to check CodePipeline resources
def check_codepipeline_resources():
    cp_client = boto3.client('codepipeline')
    pipelines = cp_client.list_pipelines()
    for pipeline in pipelines['pipelines']:
        print(f"Pipeline Name: {pipeline['name']}")


# Function to check App Runner resources
def check_apprunner_resources():
    ar_client = boto3.client('apprunner')
    services = ar_client.list_services()
    for service in services['ServiceSummaryList']:
        print(f"Service ARN: {service['ServiceArn']}")


# Function to check MQ resources
def check_mq_resources():
    mq_client = boto3.client('mq')
    brokers = mq_client.list_brokers()
    for broker in brokers['BrokerSummaries']:
        print(f"Broker ID: {broker['BrokerId']}")


# Function to check Neptune resources
def check_neptune_resources():
    neptune_client = boto3.client('neptune')
    clusters = neptune_client.describe_db_clusters()
    for cluster in clusters['DBClusters']:
        print(f"Cluster Identifier: {cluster['DBClusterIdentifier']}")


# Function to check DocumentDB resources
def check_documentdb_resources():
    documentdb_client = boto3.client('docdb')
    clusters = documentdb_client.describe_db_clusters()
    for cluster in clusters['DBClusters']:
        print(f"Cluster Identifier: {cluster['DBClusterIdentifier']}")


# Function to check Transfer Family resources
def check_transfer_family_resources():
    transfer_client = boto3.client('transfer')
    servers = transfer_client.list_servers()
    for server in servers['Servers']:
        print(f"Server ID: {server['ServerId']}")


# Function to check Lightsail resources
def check_lightsail_resources():
    lightsail_client = boto3.client('lightsail')
    instances = lightsail_client.get_instances()
    for instance in instances['instances']:
        print(f"Instance Name: {instance['name']}")


# Function to check Polly resources
def check_polly_resources():
    polly_client = boto3.client('polly')
    lexicons = polly_client.list_lexicons()
    for lexicon in lexicons['Lexicons']:
        print(f"Lexicon Name: {lexicon['Name']}")


# Function to check Rekognition collections
def check_rekognition_resources():
    rekognition_client = boto3.client('rekognition')
    collections = rekognition_client.list_collections()
    for collection_id in collections['CollectionIds']:
        print(f"Rekognition Collection ID: {collection_id}")


# Function to check Translate resources
def check_translate_resources():
    print("Amazon Translate does not have listable resources. It translates input text.")


# Function to check Transcribe jobs
def check_transcribe_resources():
    transcribe_client = boto3.client('transcribe')
    jobs = transcribe_client.list_transcription_jobs()
    for job in jobs['TranscriptionJobSummaries']:
        print(f"Transcribe Job Name: {job['TranscriptionJobName']}")


# Function to check Fargate resources
def check_fargate_resources():
    print(
        "AWS Fargate is a serverless compute engine for containers. Directly querying Fargate resources might require checking ECS tasks and services that use the Fargate launch type.")


# Function to check Backup resources
def check_backup_resources():
    backup_client = boto3.client('backup')
    vaults = backup_client.list_backup_vaults()
    for vault in vaults['BackupVaultList']:
        print(f"Backup Vault Name: {vault['BackupVaultName']}")


# Function to check Macie resources
def check_macie_resources():
    macie_client = boto3.client('macie2')
    findings = macie_client.list_findings()
    for finding in findings['findingIds']:
        print(f"Macie Finding ID: {finding}")


# Function to check Textract resources
def check_textract_resources():
    print(
        "Amazon Textract extracts text and data. Directly querying listable Textract resources isn't straightforward via boto3.")


# Function to check Personalize resources
def check_personalize_resources():
    personalize_client = boto3.client('personalize')
    datasets = personalize_client.list_datasets()
    for dataset in datasets['datasets']:
        print(f"Personalize Dataset ARN: {dataset['datasetArn']}")


# Function to check Forecast resources
def check_forecast_resources():
    forecast_client = boto3.client('forecast')
    forecast_names = forecast_client.list_forecasts()
    for forecast in forecast_names['Forecasts']:
        print(f"Forecast ARN: {forecast['ForecastArn']}")


# Function to check Snowball resources
def check_snowball_resources():
    snowball_client = boto3.client('snowball')
    jobs = snowball_client.list_jobs()
    for job in jobs['JobListEntries']:
        print(f"Snowball Job ID: {job['JobId']}")


# Function to check Marketplace resources
def check_marketplace_resources():
    print(
        "AWS Marketplace resources may not be directly listable via boto3 in this context. Typically, you'd interact with the AWS Marketplace via the console or API to manage and purchase software.")


# Function to check Secrets Manager resources
def check_secrets_manager_resources():
    secrets_client = boto3.client('secretsmanager')
    secrets = secrets_client.list_secrets()
    for secret in secrets['SecretList']:
        print(f"Secret ARN: {secret['ARN']}")


# Function to check KMS keys
def check_kms_resources():
    kms_client = boto3.client('kms')
    keys = kms_client.list_keys()
    for key in keys['Keys']:
        print(f"Key ARN: {key['KeyArn']}")


# Function to check GuardDuty resources
def check_guardduty_resources():
    guardduty_client = boto3.client('guardduty')
    detectors = guardduty_client.list_detectors()
    for detector_id in detectors['DetectorIds']:
        print(f"GuardDuty Detector ID: {detector_id}")


# Function to check Inspector resources
def check_inspector_resources():
    inspector_client = boto3.client('inspector')
    templates = inspector_client.list_assessment_templates()
    for template in templates['assessmentTemplateArns']:
        print(f"Inspector Assessment Template ARN: {template}")


# Function to check WAF resources
def check_waf_resources():
    waf_client = boto3.client('waf')
    webacls = waf_client.list_web_acls()
    for webacl in webacls['WebACLs']:
        print(f"WAF WebACL ID: {webacl['WebACLId']}")


# Function to check Connect resources
def check_connect_resources():
    connect_client = boto3.client('connect')
    instances = connect_client.list_instances()
    for instance in instances['InstanceSummaryList']:
        print(f"Connect Instance ARN: {instance['Id']}")


# Function to check Pinpoint resources
def check_pinpoint_resources():
    pinpoint_client = boto3.client('pinpoint')
    apps = pinpoint_client.get_apps()
    for app in apps['ApplicationsResponse']['Item']:
        print(f"Pinpoint Application ID: {app['Id']}")


# Function to check CloudHSM resources
def check_cloudhsm_resources():
    cloudhsm_client = boto3.client('cloudhsmv2')
    clusters = cloudhsm_client.describe_clusters()
    for cluster in clusters['Clusters']:
        print(f"CloudHSM Cluster ID: {cluster['ClusterId']}")


# Function to check Shield resources
def check_shield_resources():
    shield_client = boto3.client('shield')
    protections = shield_client.list_protections()
    for protection in protections['Protections']:
        print(f"Shield Protection ID: {protection['ProtectionId']}")


# Function to check Config resources
def check_config_resources():
    config_client = boto3.client('config')
    recorders = config_client.describe_configuration_recorders()
    for recorder in recorders['ConfigurationRecorders']:
        print(f"Config Recorder Name: {recorder['name']}")


# Function to check CloudTrail resources
def check_cloudtrail_resources():
    cloudtrail_client = boto3.client('cloudtrail')
    trails = cloudtrail_client.describe_trails()
    for trail in trails['trailList']:
        print(f"CloudTrail Name: {trail['Name']}")


# Function to check EventBridge resources
def check_eventbridge_resources():
    eventbridge_client = boto3.client('events')
    buses = eventbridge_client.list_event_buses()
    for bus in buses['EventBuses']:
        print(f"EventBridge Bus Name: {bus['Name']}")


# Function to check X-Ray groups
def check_xray_resources():
    xray_client = boto3.client('xray')
    groups = xray_client.get_groups()
    for group in groups['Groups']:
        print(f"X-Ray Group Name: {group['GroupName']}")


# Function to check WorkSpaces resources
def check_workspaces_resources():
    workspaces_client = boto3.client('workspaces')
    directories = workspaces_client.describe_workspace_directories()
    for directory in directories['Directories']:
        print(f"WorkSpaces Directory ID: {directory['DirectoryId']}")


# Function to check AppStream resources
def check_appstream_resources():
    appstream_client = boto3.client('appstream')
    stacks = appstream_client.describe_stacks()
    for stack in stacks['Stacks']:
        print(f"AppStream Stack Name: {stack['Name']}")


# Function to check IoT Core resources
def check_iot_core_resources():
    iot_client = boto3.client('iot')
    things = iot_client.list_things()
    for thing in things['things']:
        print(f"IoT Core Thing Name: {thing['thingName']}")


# Function to check IoT Defender resources
# Note: IoT Defender uses the IoT client for resources like security profiles.
def check_iot_defender_resources():
    iot_client = boto3.client('iot')
    profiles = iot_client.list_security_profiles()
    for profile in profiles['securityProfileIdentifiers']:
        print(f"IoT Defender Security Profile Name: {profile['name']}")


# Function to check Kendra resources
def check_kendra_resources():
    kendra_client = boto3.client('kendra')
    indices = kendra_client.list_indices()
    for index in indices['IndexConfigurationSummaryItems']:
        print(f"Kendra Index Name: {index['Name']}")


# Function to check Ground Station resources
# Note: This service is specialized and might require special permissions.
def check_ground_station_resources():
    groundstation_client = boto3.client('groundstation')
    configs = groundstation_client.list_configs()
    for config in configs['configList']:
        print(f"Ground Station Config ARN: {config['configArn']}")


# Function to check Managed Blockchain resources
# Note: Limited listing capabilities are provided by boto3 for Managed Blockchain.
def check_managed_blockchain_resources():
    managedblockchain_client = boto3.client('managedblockchain')
    networks = managedblockchain_client.list_networks()
    for network in networks['Networks']:
        print(f"Managed Blockchain Network Name: {network['Name']}")


# Function to check Honeycode resources
# Note: Honeycode is primarily a UI-driven service; boto3 does not provide a dedicated API for it as of my last update.

# Function to check Outposts resources
def check_outposts_resources():
    outposts_client = boto3.client('outposts')
    outposts = outposts_client.list_outposts()
    for outpost in outposts['Outposts']:
        print(f"Outposts ID: {outpost['OutpostId']}")


# Function to check Braket resources
def check_braket_resources():
    braket_client = boto3.client('braket')
    devices = braket_client.search_devices()
    for device in devices['devices']:
        print(f"Braket Device Name: {device['deviceName']}")


# Function to check Chatbot resources
# Note: AWS Chatbot does not have listing operations in boto3 as of my last update.

# Function to check License Manager resources
def check_license_manager_resources():
    license_manager_client = boto3.client('license-manager')
    licenses = license_manager_client.list_licenses()
    for license in licenses['Licenses']:
        print(f"License Manager License ARN: {license['LicenseArn']}")


# Function to check EFS resources
def check_efs_resources():
    efs_client = boto3.client('efs')
    filesystems = efs_client.describe_file_systems()
    for fs in filesystems['FileSystems']:
        print(f"EFS File System ID: {fs['FileSystemId']}")


# Function to check Batch resources
def check_batch_resources():
    batch_client = boto3.client('batch')
    job_queues = batch_client.describe_job_queues()
    for queue in job_queues['jobQueues']:
        print(f"Batch Job Queue: {queue['jobQueueName']}")


# Function to check Snow Family resources
# Note: AWS Snow Family includes services like Snowball, but there isn't a direct 'list' operation for Snow Family as a whole.
def check_snow_family_resources():
    snowball_client = boto3.client('snowball')
    jobs = snowball_client.list_jobs()
    for job in jobs['JobListEntries']:
        print(f"Snowball Job ID: {job['JobId']}")


# Function to check RoboMaker resources
def check_robomaker_resources():
    robomaker_client = boto3.client('robomaker')
    simulations = robomaker_client.list_simulation_jobs()
    for sim in simulations['simulationJobSummaries']:
        print(f"RoboMaker Simulation ARN: {sim['arn']}")


# Function to check IoT Analytics resources
def check_iot_analytics_resources():
    iot_analytics_client = boto3.client('iotanalytics')
    datasets = iot_analytics_client.list_datasets()
    for dataset in datasets['datasetSummaries']:
        print(f"IoT Analytics Dataset Name: {dataset['datasetName']}")


# Function to check Timestream resources
def check_timestream_resources():
    timestream_client = boto3.client('timestream-write')
    databases = timestream_client.list_databases()
    for db in databases['Databases']:
        print(f"Timestream Database Name: {db['DatabaseName']}")


# Function to check QLDB resources
def check_qldb_resources():
    qldb_client = boto3.client('qldb')
    ledgers = qldb_client.list_ledgers()
    for ledger in ledgers['Ledgers']:
        print(f"QLDB Ledger Name: {ledger['Name']}")


# Function to check MSK resources
def check_msk_resources():
    msk_client = boto3.client('kafka')
    clusters = msk_client.list_clusters()
    for cluster in clusters['ClusterInfoList']:
        print(f"MSK Cluster ARN: {cluster['ClusterArn']}")


# Function to check FSx resources
# Note: This is repeated from a previous snippet. I'll include it again for completeness.
def check_fsx_resources():
    fsx_client = boto3.client('fsx')
    filesystems = fsx_client.describe_file_systems()
    for fs in filesystems['FileSystems']:
        print(f"FSx File System ID: {fs['FileSystemId']}")


# Function to check Chime resources
# Note: AWS Chime primarily focuses on direct actions, and does not offer a broad resource listing via boto3 as of my last update.

# Function to check DataSync resources
def check_datasync_resources():
    datasync_client = boto3.client('datasync')
    tasks = datasync_client.list_tasks()
    for task in tasks['Tasks']:
        print(f"DataSync Task ARN: {task['TaskArn']}")


# Function to check Elasticsearch resources
def check_elasticsearch_resources():
    es_client = boto3.client('es')
    domains = es_client.list_domain_names()
    for domain in domains['DomainNames']:
        print(f"Elasticsearch Domain Name: {domain['DomainName']}")


# Function to check Lake Formation resources
def check_lake_formation_resources():
    lake_formation_client = boto3.client('lakeformation')
    resources = lake_formation_client.list_resources()
    for resource in resources['ResourceInfoList']:
        print(f"Lake Formation Resource ARN: {resource['ResourceArn']}")


# Function to check Amplify resources
def check_amplify_resources():
    amplify_client = boto3.client('amplify')
    apps = amplify_client.list_apps()
    for app in apps['apps']:
        print(f"Amplify App Name: {app['name']}")


# Function to check Managed Apache Cassandra resources (Amazon Keyspaces)
def check_managed_apache_cassandra_resources():
    cassandra_client = boto3.client('cassandra')
    keyspaces = cassandra_client.list_keyspaces()
    for keyspace in keyspaces['Keyspaces']:
        print(f"Keyspace: {keyspace['Keyspace']}")


# Function to check IoT Events resources
def check_iot_events_resources():
    iot_events_client = boto3.client('iotevents')
    detectors = iot_events_client.list_detector_models()
    for detector in detectors['detectorModelSummaries']:
        print(f"IoT Events Detector Model: {detector['detectorModelName']}")


# Function to check IoT Things Graph resources
def check_iot_things_graph_resources():
    iot_things_graph_client = boto3.client('iotthingsgraph')
    flows = iot_things_graph_client.search_flows()
    for flow in flows['summaries']:
        print(f"IoT Things Graph Flow: {flow['id']}")


# Function to check IoT SiteWise resources
def check_iot_sitewise_resources():
    iot_sitewise_client = boto3.client('iotsitewise')
    assets = iot_sitewise_client.list_assets()
    for asset in assets['assetSummaries']:
        print(f"IoT SiteWise Asset: {asset['id']}")


# Function to check Nimble Studio resources
def check_nimble_studio_resources():
    nimble_client = boto3.client('nimble')
    studios = nimble_client.list_studios()
    for studio in studios['studios']:
        print(f"Nimble Studio: {studio['studioName']}")


# Function to check Lookout for Metrics resources
def check_lookout_for_metrics_resources():
    lookout_metrics_client = boto3.client('lookoutmetrics')
    anomaly_detectors = lookout_metrics_client.list_anomaly_detectors()
    for detector in anomaly_detectors['AnomalyDetectorSummaryList']:
        print(f"Lookout for Metrics Anomaly Detector: {detector['AnomalyDetectorName']}")


# Function to check Lookout for Vision resources
def check_lookout_for_vision_resources():
    lookout_vision_client = boto3.client('lookoutvision')
    projects = lookout_vision_client.list_projects()
    for project in projects['Projects']:
        print(f"Lookout for Vision Project: {project['ProjectName']}")


def check_devops_guru_resources():
    devops_guru_client = boto3.client('devops-guru')

    # List anomalies
    try:
        response = devops_guru_client.list_anomalies_for_insight(
            InsightId='your-insight-id',  # replace with your Insight ID
        )
        if 'ProactiveAnomalies' in response:
            for anomaly in response['ProactiveAnomalies']:
                print(f"Anomaly Id: {anomaly['Id']}, Status: {anomaly['Status']}")

        if 'ReactiveAnomalies' in response:
            for anomaly in response['ReactiveAnomalies']:
                print(f"Anomaly Id: {anomaly['Id']}, Status: {anomaly['Status']}")

    except Exception as e:
        print(f"An error occurred while listing DevOps Guru anomalies: {e}")

    # You can expand the function to list other resources or details related to AWS DevOps Guru


def check_chatbot_resources():
    sns_client = boto3.client('sns')

    # List the SNS topics
    response = sns_client.list_topics()

    for topic in response['Topics']:
        print(f"Topic ARN: {topic['TopicArn']}")


# Function to check Panorama resources
# As of my last update, there isn't a specific 'list' operation for AWS Panorama in boto3.

# Function to check CodeGuru resources
def check_codeguru_resources():
    codeguru_client = boto3.client('codeguru-reviewer')
    repositories = codeguru_client.list_repositories()
    for repo in repositories['RepositoryAssociationSummaries']:
        print(f"CodeGuru Associated Repository: {repo['Name']}")


# Function to check DevOps Guru resources
# Note: AWS DevOps Guru primarily focuses on insight gathering. A 'list' operation wasn't evident in boto3 as of my last update.

# Function to check Proton resources
def check_proton_resources():
    proton_client = boto3.client('proton')
    environments = proton_client.list_environments()
    for environment in environments['environments']:
        print(f"Proton Environment: {environment['name']}")


def check_chime_resources():
    chime_client = boto3.client('chime')

    # List Chime Accounts
    response = chime_client.list_accounts()
    if 'Accounts' in response:
        for account in response['Accounts']:
            print(f"Account Name: {account['Name']}, Account Id: {account['AccountId']}")


def check_honeycode_resources():
    honeycode_client = boto3.client('honeycode')

    # List the workbooks
    workbooks = honeycode_client.list_workbooks()

    for workbook in workbooks['workbookSummaries']:
        print(f"Workbook Name: {workbook['name']}, Workbook ARN: {workbook['workbookArn']}")


def check_panorama_resources():
    panorama_client = boto3.client('panorama')

    # Example: List devices (this is hypothetical and might not match the actual API)
    try:
        response = panorama_client.list_devices()
        if 'Devices' in response:
            for device in response['Devices']:
                print(f"Device Name: {device['DeviceName']}, Device Id: {device['DeviceId']}")
    except Exception as e:
        print(f"An error occurred while listing Panorama devices: {e}")


# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--hide-empty", action="store_true", help="Hide empty resources")
args = parser.parse_args()


 # Main execution loop
regions = get_all_regions()
for region in regions:
    print(f"\n{TextColors.BOLD}Checking resources in {region}{TextColors.ENDC}")
    
    # Set the region for this iteration
    boto3.setup_default_session(region_name=region)
     
    glob_attrs = list(globals().keys())
    for glob_attr in glob_attrs:
        attr_value = globals()[glob_attr]
        if not callable(attr_value) or not glob_attr.startswith('check_'):
            continue
        func_name = glob_attr[len('check_'):].replace('_resources', '')
        print(f'{TextColors.BOLD}# {func_name.upper()} in {region}{TextColors.ENDC}')
        try:
            attr_value()
        except Exception as e:
            print(f'{TextColors.FAIL}{str(e)}{TextColors.ENDC}')
