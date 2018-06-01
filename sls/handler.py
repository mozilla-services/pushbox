import json
import logging
import os
import time
import uuid
from functools import wraps

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

# Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants
DEFAULT_TTL = 60 * 60 * 24

# Environment Constants
S3_BUCKET = os.environ.get("S3_BUCKET", "pushbox-test")
DDB_TABLE = os.environ.get("DDB_TABLE", "pushbox_test")

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


def compose_key(uid, device_id):
    return "{}:{}".format(uid, device_id)


def get_max_index(key):
    result = index_table.query(
        KeyConditionExpression=Key("fxa_uid").eq(key),
        Select="ALL_ATTRIBUTES",
        ScanIndexForward=False,
        Limit=1,
    )
    if result['Count']:
        return int(result['Items'][0].get('index'))
    else:
        return 0


@log_exceptions
def store_data(event, context):
    """Store data in S3 and index it in DynamoDB"""
    logger.info("Event: {} ; Context: {}".format(event, context))
    device_id = event["pathParameters"]["deviceId"]
    fx_uid = event["pathParameters"]["uid"]
    try:
        key = compose_key(uid=fx_uid, device_id=device_id)
        req_json = json.loads(event["body"])
        logger.info("data: {}".format(req_json))
    except ValueError as ex:
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=400,
            body=json.dumps(dict(
                status=400,
                error="Invalid payload: {}".format(ex)
            ))
        )
    ttl = req_json.get("ttl", DEFAULT_TTL)
    s3_filename = device_id + uuid.uuid4().hex
    # Data is presumed to be an encrypted blob
    s3.Object(S3_BUCKET, s3_filename).put(Body=req_json["data"])
    index = get_max_index(key) + 1
    data_len = len(req_json["data"])
    for i in range(0, 10):
        try:
            index = index + i
            index_table.put_item(
                ConditionExpression=Attr('index').ne(index),
                Item=dict(
                    fxa_uid=key,
                    index=index,
                    device_id=device_id,
                    ttl=int(time.time()) + ttl,
                    s3_filename=s3_filename,
                    s3_file_size=data_len
                )
            )
            break
        except ClientError as ex:
            if ex.response['Error']['Code'] == \
                    'ConditionalCheckFailedException':
                pass
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
    logger.info("Getting data: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    fx_uid = event["pathParameters"]["uid"]
    limit = None
    # event could set "queryStringParameters" to the value None
    params = event.get("queryStringParameters")
    if params is not None:
        try:
            limit = int(params.get("limit"))
        except (ValueError, TypeError):
            limit = None
    if limit is None:
        limit = 10
    limit = min(10, max(0, limit))
    key = compose_key(uid=fx_uid, device_id=device_id)
    if limit == 0:
        index = get_max_index(key)
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=200,
            body=json.dumps(dict(index=index))
        )
    start_index = None
    if "index" in (event.get("queryStringParameters") or {}):
        start_index = int(event["queryStringParameters"]["index"])
        logger.info("Start index: {}".format(start_index))
    key_cond = Key("fxa_uid").eq(key)
    if start_index:
        key_cond = key_cond & Key("index").gt(start_index)
    results = index_table.query(
        Select="ALL_ATTRIBUTES",
        KeyConditionExpression=key_cond,
        ConsistentRead=True,
        Limit=limit,
    ).get("Items", [])
    logger.info("results: {}".format(results))
    # Fetch all the payloads
    for item in results:
        try:
            response = s3.Object(S3_BUCKET, item["s3_filename"]).get()
            data = response["Body"].read().decode('utf-8')
            item["data"] = data
        except ClientError as ex:
            logger.error(ex)
            return dict(
                headers={"Content-Type": "application/json"},
                statusCode=404,
                body="Content missing or expired"
            )
    # Serialize the results for delivery
    index = 0
    messages = []
    for result in results:
        result_index = int(result['index'])
        messages.append({'index': result_index,
                         'data': result['data']})
        index = max(index, result_index)
    payload = {"last": True, "index": start_index or 0}
    if results:
        # should this be comparing against "scannedCount"?
        payload["last"] = len(results) < limit
        payload["index"] = index
        payload["messages"] = messages
    return dict(
        headers={"Content-Type": "application/json"},
        statusCode=200,
        body=json.dumps(payload),
    )


@log_exceptions
def del_data(event, context=None):
    """Delete data for a given user/device/channel"""
    uid = event['pathParameters']["uid"]
    device_id = event['pathParameters']['deviceId']
    key = compose_key(uid=uid, device_id=device_id)
    items = index_table.query(
        Select="ALL_ATTRIBUTES",
        KeyConditionExpression=Key("fxa_uid").eq(key),
        ConsistentRead=True,
    ).get("Items", [])
    try:
        for item in items:
            s3.Object(S3_BUCKET, item["s3_filename"]).delete()
    except Exception as ex:
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=500,
            body=json.dumps(dict(
                status=500,
                error="Could not delete all data {}".format(ex),
            ))
        )
    return dict(
        headers={"Content-Type": "application/json"},
        statusCode=200,
        body="{}"
    )


@log_exceptions
def status(event, context=None):
    # Faux status to discover root.
    return dict(
        headers={"Content-Type": "application/json"},
        statusCode=200,
        body=json.dumps(dict(status=200, message="ok"))
    )


def test_index_storage():
    data = "BlockOfEncryptedStuff"
    store_result = store_data({
        "pathParameters": {
            "deviceId": "device-123",
            "uid": "uid-123"
        },
        "body": json.dumps({
            "data": data
        })
    }, None)
    fetch_result = get_data({
        "pathParameters": {
            "deviceId": "device-123",
            "uid": "uid-123"
        },
        "queryStringParameters": {
            "index": json.loads(store_result['body'])['index'] - 1
        },
    }, None)
    body = json.loads(fetch_result['body'])
    high_index = body['index']
    assert(body['last'])
    assert(body['index'] == json.loads(store_result['body'])['index'])
    assert(body['messages'][0]['data'] == data)

    index = get_data(
        {
            "pathParameters": {
                "deviceId": "device-123",
                "uid": "uid-123"
            },
            "queryStringParameters": {
                "limit": "0"
            },
        }, None)
    assert(high_index == json.loads(index["body"])["index"])
    print('Ok')


def test_delete_storge():
    del_data({
        "pathParameters": {
            "deviceId": "device-123",
            "uid": "uid-123"
        },
    })
    print("Ok")


if __name__ == "__main__":
    print("testing indexed data storage...")
    test_index_storage()
    print("testing delete...")
    test_delete_storge()
