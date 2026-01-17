import boto3
import csv
import io
import json
from time import sleep
from typing import List, Dict
from datetime import datetime  # timezone not needed now

# --- AWS clients & config ---

REGION = "ap-south-1"

s3_client = boto3.client("s3", region_name=REGION)
kinesis_client = boto3.client("kinesis", region_name=REGION)

KINESIS_STREAM_NAME = "ecommerce-raw-user-activity-stream-1"
STREAMING_PARTITION_KEY = "category_id"


def _rows_from_s3_csv(bucket: str, key: str):
    """
    Stream rows from a CSV file in S3 as dicts.
    This avoids loading the whole file into memory.
    """
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    body = obj["Body"]

    # Wrap the streaming body as a text file-like object
    with io.TextIOWrapper(body, encoding="utf-8") as text_stream:
        reader = csv.DictReader(text_stream)
        for row in reader:
            yield row


def _send_batch_to_kinesis(records: List[Dict]) -> None:
    """
    Send a batch of records to Kinesis using put_records.
    """
    if not records:
        return

    response = kinesis_client.put_records(
        StreamName=KINESIS_STREAM_NAME,
        Records=records
    )

    failed_count = response.get("FailedRecordCount", 0)
    http_status = response["ResponseMetadata"]["HTTPStatusCode"]

    print(f"[Kinesis] HTTP {http_status}, sent={len(records)}, failed={failed_count}")

    if failed_count > 0:
        for rec_resp in response["Records"]:
            if "ErrorCode" in rec_resp and rec_resp["ErrorCode"]:
                print("  Failed record error:", rec_resp["ErrorCode"], rec_resp.get("ErrorMessage"))


def stream_data_to_kinesis(
    input_s3_bucket: str,
    input_s3_key: str,
    batch_size: int = 500,
    throttle_secs: float = 0.0,
):
    """
    Read CSV from S3 -> stream to Kinesis in batches.
    """
    batch: List[Dict] = []

    try:
        for row in _rows_from_s3_csv(input_s3_bucket, input_s3_key):
            try:
                # Add transaction timestamp in ISO-8601 with MILLISECONDS, NO timezone
                # Example: "2025-12-07T20:52:53.684"
                now_utc = datetime.utcnow()
                row["txn_timestamp"] = now_utc.isoformat(timespec="milliseconds")

                # Prepare data payload (JSON)
                data_json = json.dumps(row)
                partition_key = str(row.get(STREAMING_PARTITION_KEY, "default"))

                record = {
                    "Data": data_json,
                    "PartitionKey": partition_key,
                }
                batch.append(record)

                if "category_code" in row:
                    print("Queued record for category_code:", row["category_code"])

                if len(batch) >= batch_size:
                    _send_batch_to_kinesis(batch)
                    batch.clear()

                    if throttle_secs > 0:
                        sleep(throttle_secs)

            except Exception as inner_err:
                print(f"[Row Error] {inner_err} | row={row}")

        # Flush remaining records
        if batch:
            _send_batch_to_kinesis(batch)

    except Exception as e:
        print(f"[Stream Error] {e}")


if __name__ == "__main__":
    for i in range(4):
        print(f"--- Run {i + 1} ---")
        stream_data_to_kinesis(
            input_s3_bucket="ecom-etl-s3-raw-apsouth1-dev",
            input_s3_key="ecom_user_activity_sample/2019-nov-sample.csv",
            batch_size=500,
            throttle_secs=0.25,)
