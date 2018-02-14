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


class HandlerException(Exception):
    def __init__(self, status_code=500, message="Unknown Error"):
        self.status_code = status_code,
        self.message = message

    def __str__(self):
        return "{}: {}".format(self.status_code, self.message)


def log_exceptions(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as exc:
            logger.exception("Exception running _store_data: {}".format(exc))
            raise
    return wrapper


def fxa_validate(event):
    """Do whatever need be done to validate the FxA Token.

    Raise a HandlerException on error.

    """
    pass


@log_exceptions
def store_data(event, context):
    """Store data in S3 and index it in DynamoDB"""
    logger.info("Event was set to: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    # fx_uid = event["pathParameters"]["uid"]
    try:
        fxa_validate(event)
    except HandlerException as ex:
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=ex.status_code,
            body=json.dumps(dict(
                status=ex.status_code,
                error=ex.message
            ))
        )
    try:
        req_json = json.loads(event["body"])
    except ValueError:
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=400,
            body=json.dumps(dict(
                status=200,
                error="Invalid payload"
            ))
        )
    s3_data = req_json["data"].encode("utf-8")
    ttl = req_json.get("ttl", DEFAULT_TTL)
    s3_filename = device_id + uuid.uuid4().hex
    s3.Object(S3_BUCKET, s3_filename).put(Body=s3_data)
    index = int(time.time()*(10**9))
    try:
        index_table.put_item(
            Item=dict(
                fxa_uid=device_id,
                index=index,
                ttl=int(time.time()) + ttl,
                s3_filename=s3_filename,
                s3_file_size=len(s3_data)
            )
        )
    except Exception as ex:  # TODO: Limit this to just AWS errors
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=500,
            body=json.dumps(dict(
                status=500,
                error=ex.message,
            ))
        )
    return dict(
        headers={"Content-Type": "application/json"},
        statusCode=200,
        body=json.dumps(dict(
            status=200,
            index=index,
        ))
    )


@log_exceptions
def get_data(event, context):
    """Retrieve data from S3 using DynamoDB index"""
    logger.info("Event was set to: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    # get the channelid ('sendTab'?)
    channelid = "sendtab"
    limit = event["pathParameters"].get("limit")
    if not limit:
        limit = 10
    limit = min(limit, 10)
    # fx_uid = event["pathParameters"]["uid"]
    try:
        fxa_validate(event)
    except HandlerException as ex:
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=ex.status_code,
            body=json.dumps(dict(
                status=ex.status_code,
                error=ex.message
            ))
        )
    start_index = None
    if (event["queryStringParameters"] and
            "index" in event["queryStringParameters"]):
        start_index = int(event["queryStringParameters"]["index"])
        logger.info("Start index: {}".format(start_index))
    key_cond = Key("fxa_uid").eq(device_id)
    if start_index:
        key_cond = key_cond & Key("index").gt(start_index)
    results = index_table.query(
        Select="ALL_ATTRIBUTES",
        KeyConditionExpression=key_cond,
        ConsistentRead=True,
        Limit=limit,
    ).get("Items", [])
    # Fetch all the payloads
    for item in results:
        response = s3.Object(S3_BUCKET, item["s3_filename"]).get()
        data = response["Body"].read().decode('utf-8')
        item["data"] = data
        item["channel"] = channelid
        if 'index' not in item and item.get("timestamp"):
            item["index"] = item["timestamp"]
            del(item["timestamp"])
    # Serialize the results for delivery
    messages = [{"index": int(x["index"]), "data": x["data"]}
                for x in results]
    payload = {"last": True, "index": start_index}
    if results:
        # should this be comparing against "scannedCount"?
        payload["last"] = len(results) < limit
        payload["index"] = int(results[-1]["timestamp"])
        payload["messages"] = messages
    return dict(
        headers={"Content-Type": "application/json"},
        status=200,
        body=json.dumps(payload),
    )
