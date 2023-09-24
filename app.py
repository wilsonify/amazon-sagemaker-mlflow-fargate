# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_cdk import (
    App,
    Aws,
    CfnOutput,
    CfnParameter,
    Duration,
    RemovalPolicy,
    Stack,
    aws_ec2,
    aws_ecs,
    aws_ecs_patterns,
    aws_iam,
    aws_rds,
    aws_s3,
    aws_secretsmanager,
)
from constructs import Construct


class MLflowStack(Stack):
    def __init__(self, scope: Construct, identification: str, **kwargs) -> None:
        super().__init__(scope, identification, **kwargs)
        # ==============================
        # ======= CFN PARAMETERS =======
        # ==============================
        project_name_param = CfnParameter(scope=self, id="ProjectName", type="String")
        db_name = "mlflowdb"
        port = 3306
        username = "master"
        bucket_name = f"{project_name_param.value_as_string}-artifacts-{Aws.ACCOUNT_ID}"
        container_repo_name = "mlflow-containers"
        cluster_name = "mlflow"
        service_name = "mlflow"

        # ==================================================
        # ================= IAM ROLE =======================
        # ==================================================
        role = aws_iam.Role(
            scope=self,
            id="TASKROLE",
            assumed_by=aws_iam.ServicePrincipal(service="ecs-tasks.amazonaws.com"),
        )
        role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess")
        )
        role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess")
        )

        # ==================================================
        # ================== SECRET ========================
        # ==================================================
        s_string = aws_secretsmanager.SecretStringGenerator(
            password_length=20,
            exclude_punctuation=True
        )
        db_password_secret = aws_secretsmanager.Secret(
            scope=self,
            id="DBSECRET",
            secret_name="dbPassword",
            generate_secret_string=s_string
        )

        # ==================================================
        # ==================== VPC =========================
        # ==================================================
        public_subnet = aws_ec2.SubnetConfiguration(
            name="Public", subnet_type=aws_ec2.SubnetType.PUBLIC, cidr_mask=28
        )
        private_subnet = aws_ec2.SubnetConfiguration(
            name="Private", subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS, cidr_mask=28
        )
        isolated_subnet = aws_ec2.SubnetConfiguration(
            name="DB", subnet_type=aws_ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=28
        )

        vpc = aws_ec2.Vpc(
            scope=self,
            id="VPC",
            ip_addresses=aws_ec2.IpAddresses.cidr("10.0.0.0/24"),
            max_azs=2,
            nat_gateway_provider=aws_ec2.NatProvider.gateway(),
            nat_gateways=1,
            subnet_configuration=[public_subnet, private_subnet, isolated_subnet],
        )
        vpc.add_gateway_endpoint(
            "S3Endpoint", service=aws_ec2.GatewayVpcEndpointAwsService.S3
        )
        # ==================================================
        # ================= S3 BUCKET ======================
        # ==================================================
        artifact_bucket = aws_s3.Bucket(
            scope=self,
            id="ARTIFACTBUCKET",
            bucket_name=bucket_name,
            public_read_access=False,
        )
        # # ==================================================
        # # ================== DATABASE  =====================
        # # ==================================================
        # Creates a security group for AWS RDS
        sg_rds = aws_ec2.SecurityGroup(
            scope=self, id="SGRDS", vpc=vpc, security_group_name="sg_rds"
        )
        # Adds an ingress rule which allows resources in the VPC's CIDR to access the database.
        sg_rds.add_ingress_rule(
            peer=aws_ec2.Peer.ipv4("10.0.0.0/24"), connection=aws_ec2.Port.tcp(port)
        )

        database = aws_rds.DatabaseInstance(
            scope=self,
            id="MYSQL",
            database_name=db_name,
            port=port,
            credentials=aws_rds.Credentials.from_username(
                username=username, password=db_password_secret.secret_value
            ),
            engine=aws_rds.DatabaseInstanceEngine.mysql(
                version=aws_rds.MysqlEngineVersion.VER_8_0_34()
            ),
            instance_type=aws_ec2.InstanceType.of(
                aws_ec2.InstanceClass.BURSTABLE2, aws_ec2.InstanceSize.SMALL
            ),
            vpc=vpc,
            security_groups=[sg_rds],
            vpc_subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_ISOLATED
            ),
            # multi_az=True,
            removal_policy=RemovalPolicy.DESTROY,
            deletion_protection=False,
        )
        # ==================================================
        # =============== FARGATE SERVICE ==================
        # ==================================================
        cluster = aws_ecs.Cluster(
            scope=self, id="CLUSTER", cluster_name=cluster_name, vpc=vpc
        )

        task_definition = aws_ecs.FargateTaskDefinition(
            scope=self,
            id="MLflow",
            task_role=role,
            cpu=4 * 1024,
            memory_limit_mib=8 * 1024,
        )

        container = task_definition.add_container(
            id="Container",
            image=aws_ecs.ContainerImage.from_asset(directory="container"),
            environment={
                "BUCKET": f"s3://{artifact_bucket.bucket_name}",
                "HOST": database.db_instance_endpoint_address,
                "PORT": str(port),
                "DATABASE": db_name,
                "USERNAME": username,
            },
            secrets={"PASSWORD": aws_ecs.Secret.from_secrets_manager(db_password_secret)},
            logging=aws_ecs.LogDriver.aws_logs(stream_prefix="mlflow"),
        )
        port_mapping = aws_ecs.PortMapping(
            container_port=5000, host_port=5000, protocol=aws_ecs.Protocol.TCP
        )
        container.add_port_mappings(port_mapping)

        fargate_service = aws_ecs_patterns.NetworkLoadBalancedFargateService(
            scope=self,
            id="MLFLOW",
            service_name=service_name,
            cluster=cluster,
            task_definition=task_definition,
        )

        # Setup security group
        fargate_service.service.connections.security_groups[0].add_ingress_rule(
            peer=aws_ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=aws_ec2.Port.tcp(5000),
            description="Allow inbound from VPC for mlflow",
        )

        # Setup autoscaling policy
        scaling = fargate_service.service.auto_scale_task_count(max_capacity=2)
        scaling.scale_on_cpu_utilization(
            id="AUTOSCALING",
            target_utilization_percent=70,
            scale_in_cooldown=Duration.seconds(60),
            scale_out_cooldown=Duration.seconds(60),
        )
        # ==================================================
        # =================== OUTPUTS ======================
        # ==================================================
        CfnOutput(
            scope=self,
            id="LoadBalancerDNS",
            value=fargate_service.load_balancer.load_balancer_dns_name,
        )


if __name__ == "__main__":
    app = App()
    MLflowStack(app, "MLflowStack")
    app.synth()
