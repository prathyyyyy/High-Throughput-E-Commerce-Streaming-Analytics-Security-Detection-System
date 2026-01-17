from __future__ import print_function

import base64
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

import boto3
from aws_kinesis_agg.deaggregator import iter_deaggregate_records

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------

REGION = os.getenv("AWS_REGION", "ap-south-1")

# Required environment variables (fail fast if missing)
CLOUDWATCH_NAMESPACE = os.environ["cloudwatch_namespace"]
CLOUDWATCH_METRIC = os.environ["cloudwatch_metric"]
DDB_CONTROL_TABLE = os.environ["dynamodb_control_table"]
TOPIC_ARN = os.environ["topic_arn"]

# Optional: threshold for suspicious activity (can be overridden via env var)
DDoS_THRESHOLD = int(os.getenv("ddos_threshold", "10"))

# CloudWatch has a hard limit of 20 MetricData items per call
CLOUDWATCH_METRIC_BATCH_SIZE = 20

# ---------------------------------------------------------------------------
# AWS clients
# ---------------------------------------------------------------------------

cloudwatch = boto3.client("cloudwatch", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
db_table = dynamodb.Table("ddb-ecommerce-tab-1")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _build_ddb_item(json_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich the incoming JSON document with DynamoDB partition and sort keys.

    Partition key pattern:
        userid#<user_id>#appserver#<server-name>

    Sort key:
        current epoch timestamp (seconds since epoch, int)
    """
    user_id = str(json_document["user_id"])

    # In a real system, "app-server-tomcat-123" could also come from env/config.
    json_document["ddb_partition_key"] = f"userid#{user_id}#appserver#app-server-tomcat-123"
    json_document["ddb_sort_key"] = int(datetime.utcnow().timestamp())
    return json_document


def _build_metric(
    user_id: str,
    num_actions_per_watermark: str,
) -> Dict[str, Any]:
    """
    Build a single CloudWatch MetricData entry for put_metric_data.
    """
    return {
        "MetricName": CLOUDWATCH_METRIC,
        "Dimensions": [
            {
                "Name": "user_id",
                "Value": user_id,
            },
            {
                "Name": "num_actions_per_watermark",
                "Value": num_actions_per_watermark,
            },
        ],
        "Unit": "Count",
        "Value": 1.0,
        "StorageResolution": 1,
    }


def _flush_metrics(metric_buffer: List[Dict[str, Any]]) -> None:
    """
    Send any buffered CloudWatch metrics in batches of <= 20.

    This reduces the number of CloudWatch API calls compared to sending one
    metric per record.
    """
    if not metric_buffer:
        return

    # CloudWatch allows up to 20 MetricData items per request
    for i in range(0, len(metric_buffer), CLOUDWATCH_METRIC_BATCH_SIZE):
        batch = metric_buffer[i : i + CLOUDWATCH_METRIC_BATCH_SIZE]
        try:
            response = cloudwatch.put_metric_data(
                MetricData=batch,
                Namespace=CLOUDWATCH_NAMESPACE,
            )
            logger.info("CloudWatch put_metric_data response: %s", response)
        except Exception as e:
            # If metrics fail, we log and continue – we don't want to stop
            # processing the entire Lambda invocation.
            logger.exception("Failed to put metric data to CloudWatch: %s", e)


def _maybe_notify_ddos(user_id: str, num_actions: int, payload: Dict[str, Any]) -> None:
    """
    Send an SNS notification if the num_actions_per_watermark exceeds the
    configured DDoS_THRESHOLD.
    """
    if num_actions <= DDoS_THRESHOLD:
        return

    subject = (
        f"Possible DDoS detected, by user_id {user_id} "
        f"with a number of attempts of : {num_actions}/window"
    )

    try:
        response = sns.publish(
            TopicArn=TOPIC_ARN,
            Message=json.dumps(payload, default=str),
            Subject=subject,
        )
        logger.info(
            "High-severity incident notification sent via SNS. Response: %s",
            response,
        )
    except Exception as e:
        logger.exception("Failed to publish SNS notification: %s", e)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> str:
    """
    Lambda entrypoint.

    - Deaggregates Kinesis records (supports KPL-aggregated records).
    - Decodes and parses each record as JSON.
    - Writes micro-batch of items to DynamoDB via batch_writer.
    - Buffers CloudWatch metrics and submits them in efficient batches.
    - Sends SNS notifications for suspicious (possible DDoS) activity.
    """

    raw_kinesis_records = event.get("Records", [])
    logger.info("Received %d raw Kinesis records", len(raw_kinesis_records))

    record_count = 0
    metric_buffer: List[Dict[str, Any]] = []

    # DynamoDB batch_writer handles efficient batching / retries under the hood.
    with db_table.batch_writer() as batch_writer:
        for record in iter_deaggregate_records(raw_kinesis_records):
            try:
                # ------------------------------------------------------------------
                # 1. Decode and parse Kinesis payload
                # ------------------------------------------------------------------
                kinesis_data = record["kinesis"]["data"]
                payload_bytes = base64.b64decode(kinesis_data)
                json_document = json.loads(payload_bytes.decode("utf-8"))

                # Extract key fields
                input_user_id = str(json_document["user_id"])
                num_actions_str = str(json_document["num_actions_per_watermark"])
                num_actions_int = int(num_actions_str)

                # ------------------------------------------------------------------
                # 2. DynamoDB – enrich and write item
                # ------------------------------------------------------------------
                ddb_item = _build_ddb_item(json_document)
                batch_writer.put_item(Item=ddb_item)

                # ------------------------------------------------------------------
                # 3. CloudWatch – buffer metric
                # ------------------------------------------------------------------
                metric_buffer.append(
                    _build_metric(input_user_id, num_actions_str)
                )

                # Flush if we hit the batch size limit
                if len(metric_buffer) >= CLOUDWATCH_METRIC_BATCH_SIZE:
                    _flush_metrics(metric_buffer)
                    metric_buffer.clear()

                # ------------------------------------------------------------------
                # 4. DDoS / bot detection – SNS notification
                # ------------------------------------------------------------------
                _maybe_notify_ddos(
                    user_id=input_user_id,
                    num_actions=num_actions_int,
                    payload=json_document,
                )

                record_count += 1

            except Exception as e:
                # Log and continue to process remaining records
                logger.exception("Error when processing record: %s", e)

    # Flush any remaining metrics after we finish DynamoDB writes
    _flush_metrics(metric_buffer)

    result_message = f"Successfully processed {record_count} records."
    logger.info(result_message)
    return result_message
