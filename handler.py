import json
import logging
import os
import time
import uuid
from functools import wraps

import boto3
from boto3.dynamodb.conditions import Key

# Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants
DEFAULT_TTL = 60 * 60 * 24

# Environment Constants
S3_BUCKET = os.environ.get("S3_BUCKET")
DDB_TABLE = os.environ.get("DDB_TABLE")

# Clients
s3 = boto3.resource("s3")
ddb = boto3.resource("dynamodb")
index_table = ddb.Table(DDB_TABLE)

def log_exceptions(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as exc:
            logger.exception("Exception running _store_data")
            raise
    return wrapper


@log_exceptions
def store_data(event, context):
    """Store data in S3 and index it in DynamoDB"""
    logger.info("Event was set to: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    try:
        req_json = json.loads(event["body"])
    except ValueError:
        return dict(statusCode=400, body="Invalid payload")
    s3_data = req_json["data"].encode("utf-8")
    s3_filename = device_id + uuid.uuid4().hex
    s3.Object(S3_BUCKET, s3_filename).put(Body=s3_data)
    index_table.put_item(
        Item=dict(
            fxa_uid=device_id,
            timestamp=int(time.time()*(10**9)),
            ttl=int(time.time()) + DEFAULT_TTL,
            s3_filename=s3_filename,
            s3_file_size=len(s3_data)
        )
    )
    result = {
        'statusCode': 200,
        'body': "Stored",
    }
    return result


@log_exceptions
def get_data(event, context):
    """Retrieve data from S3 using DynamoDB index"""
    logger.info("Event was set to: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    start_timestamp = None
    if event["queryStringParameters"] and "index" in event["queryStringParameters"]:
        start_timestamp = int(event["queryStringParameters"]["index"])
        logger.info("Start timestamp: {}".format(start_timestamp))
    key_cond = Key("fxa_uid").eq(device_id)
    if start_timestamp:
        key_cond = key_cond & Key("timestamp").gt(start_timestamp)
    results = index_table.query(
        Select="ALL_ATTRIBUTES",
        KeyConditionExpression=key_cond,
        ConsistentRead=True,
        Limit=10,
    ).get("Items", [])
    # Fetch all the payloads
    for item in results:
        response = s3.Object(S3_BUCKET, item["s3_filename"]).get()
        data = response["Body"].read().decode('utf-8')
        item["payload"] = data
    # Serialize the results for delivery
    messages = [{"timestamp": int(x["timestamp"]), "data": x["payload"]}
                for x in results]
    payload = {"last": True, "index": start_timestamp}
    if results:
        payload["last"] = len(results) < 10
        payload["index"] = int(results[-1]["timestamp"])
        payload["messages"] = messages
    return {
        'statusCode': 200,
        'body': json.dumps(payload),
        'headers': {
            "Content-Type": "application/json"
        },
    }
