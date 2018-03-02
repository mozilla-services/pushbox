import json
import logging
import os
import time
import uuid
from urllib import request, error
from functools import wraps

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

# Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants
DEFAULT_TTL = 60 * 60 * 24
SERVICES = [x.strip().lower()
            for x in os.environ.get("SERVICES", "sendtab").split(",")]

# Environment Constants
S3_BUCKET = os.environ.get("S3_BUCKET", "pushbox-test")
DDB_TABLE = os.environ.get("DDB_TABLE", "pushbox_test")
# use stage as default.
# prod = oauth.accounts.firefox.com
FXA_HOST = os.environ.get("FXA_VERIFY_HOST", "oauth.stage.mozaws.net")

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


def valid_service(service):
    if service not in SERVICES:
        raise HandlerException(
           status_code=404,
           message="Unknown service"
        )
    return service


def compose_key(uid, device_id, service):
    return "{}:{}:{}".format(service, uid, device_id)


def fxa_validate(event, device_id=None):
    """Return list of actions that this request is authorized to perform.

    Raise a HandlerException on error.

    """
    # extract the FxA OAuth token from the Authorization header
    try:
        assert event["headers"]["authorization"].lower().startswith("bearer")
        auth = event["headers"]["authorization"].strip().split(None, 1)[1]

    except KeyError:
        raise HandlerException(
            status_code=401,
            message="Missing authorization header")
    except IndexError:
        raise HandlerException(
            status_code=401,
            message="Invalid authorization header"
        )
    try:
        req = request.Request(
            "https://{}/v1/verify".format(FXA_HOST),
            method="POST",
            data=json.dumps({"token": auth}).encode('utf8'),
            headers={"Content-type": "application/json"})
        response = request.urlopen(req, timeout=5).read()
        scopes = set(json.loads(response)["scope"])
        actions = {}
        if "https://identity.mozilla.com/apps/pushbox/" in scopes:
            return ['send', 'recv']
        if "https://identity.mozilla.com/apps/pushbox/send" in scopes:
            actions['send'] = True
        if "https://identity.mozilla.com/apps/pushbox/recv" in scopes:
            actions["recv"] = True
        if ("https://identity.mozilla.com/apps/pushbox/send/{}".format(
                device_id) in scopes):
            actions["send"] = True
        if ("https://identity.mozilla.com/apps/pushbox/recv/{}".format(
                device_id) in scopes):
            actions["recv"] = True
        else:
            raise HandlerException(
                status_code=502,
                message="Unknown or invalid token response received"
            )
        return actions.keys()
    except KeyError:
        raise HandlerException(
            status_code=500,
            message="Token not found in authorization response")
    except error.URLError as ex:
        raise HandlerException(
            status_code=502,
            message="Could not verify auth {}".format(ex))
    except ValueError as ex:
        raise HandlerException(
            status_code=502,
            message="Could not parse auth response {}".format(ex))


@log_exceptions
def store_data(event, context):
    """Store data in S3 and index it in DynamoDB"""
    logger.info("Event was set to: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    fx_uid = event["pathParameters"]["uid"]
    try:
        service = valid_service(event["pathParameters"]["service"])
        if "send" not in fxa_validate(event, device_id):
            raise HandlerException(
                status_code=401,
                message="Operation not permitted"
            )
        key = compose_key(uid=fx_uid, device_id=device_id, service=service)
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
    result = index_table.query(
        KeyConditionExpression=Key("fxa_uid").eq(key),
        Select="ALL_ATTRIBUTES",
        ScanIndexForward=False,
        Limit=1,
    )
    if result['Count']:
        index = int(result['Items'][0].get('index'))+1
    else:
        index = 1
    for i in range(0, 10):
        try:
            index = index + i
            index_table.put_item(
                ConditionExpression=Attr('index').ne(index),
                Item=dict(
                    fxa_uid=key,
                    index=index,
                    device_id=device_id,
                    service=service,
                    ttl=int(time.time()) + ttl,
                    s3_filename=s3_filename,
                    s3_file_size=len(s3_data)
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
    logger.info("Event was set to: {}".format(event))
    device_id = event["pathParameters"]["deviceId"]
    fx_uid = event["pathParameters"]["uid"]
    limit = event["pathParameters"].get("limit")
    if not limit:
        limit = 10
    limit = min(limit, 10)
    try:
        service = valid_service(event["pathParameters"]["service"])
        if "recv" not in fxa_validate(event, device_id):
            raise HandlerException(
                status_code=401,
                message="Operation not permitted"
            )
        key = compose_key(uid=fx_uid, device_id=device_id, service=service)
    except HandlerException as ex:
        return dict(
            headers={"Content-Type": "application/json"},
            statusCode=ex.status_code,
            body=json.dumps(dict(
                status=ex.status_code,
                error="{}".format(ex),
            ))
        )
    start_index = None
    if "index" in event.get("queryStringParameters"):
        start_index = int(event["queryStringParameters"]["index"])
        logger.info("Start index: {}".format(start_index))
    key_cond = Key("fxa_uid").eq(key)
    if start_index:
        key_cond = key_cond & Key("index").gte(start_index)
    results = index_table.query(
        Select="ALL_ATTRIBUTES",
        KeyConditionExpression=key_cond,
        ConsistentRead=True,
        Limit=limit,
    ).get("Items", [])
    # Fetch all the payloads
    for item in results:
        try:
            response = s3.Object(S3_BUCKET, item["s3_filename"]).get()
            data = response["Body"].read().decode('utf-8')
            item["data"] = data
            item["service"] = service
        except ClientError as ex:
            return dict(
                headers={"Content-Type": "application/json"},
                status=404,
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
    payload = {"last": True, "index": start_index}
    if results:
        # should this be comparing against "scannedCount"?
        payload["last"] = len(results) < limit
        payload["index"] = index
        payload["messages"] = messages
    return dict(
        headers={"Content-Type": "application/json"},
        status=200,
        body=json.dumps(payload),
    )


@log_exceptions
def del_data(event, context=None):
    """Delete data for a given user/device/channel"""
    uid = event['pathParameters']["uid"]
    device_id = event['pathParameters']['deviceId']
    try:
        service = valid_service(event["pathParameters"]["service"])
        if "send" not in fxa_validate(event, device_id):
            raise HandlerException(
                status_code=401,
                message="Operation not permitted"
            )
        key = compose_key(uid=uid, device_id=device_id, service=service)
    except HandlerException as ex:
            return dict(
                headers={"Content-Type": "application/json"},
                statusCode=ex.status_code,
                body=json.dumps(dict(
                    status=ex.status_code,
                    error="{}".format(ex),
                ))
            )
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


def test_fxa_validate():
    """Test the FxA validation routines.

    This requires the PyFxA 0.5.0 module.

    """
    from fxa.tools.create_user import create_new_fxa_account
    from fxa.tools.bearer import get_bearer_token
    from fxa.constants import ENVIRONMENT_URLS

    try:
        email, password = create_new_fxa_account(
            fxa_user_salt=None,
            account_server_url=ENVIRONMENT_URLS['stage']['authentication'],
            prefix='fxa',
            content_server_url=ENVIRONMENT_URLS['stage']['content'],
        )
        bearer = get_bearer_token(
            email=email,
            password=password,
            scopes=["https://identity.mozilla.com/apps/pushbox/"],
            account_server_url=ENVIRONMENT_URLS['stage']['authentication'],
            oauth_server_url=ENVIRONMENT_URLS['stage']['oauth'],
            client_id="5882386c6d801776",
        )
        headers = {
            "authorization": "Bearer {}".format(bearer)
        }
        result = fxa_validate({"headers": headers}, None)
        assert(result == ['send', 'recv'])
        print("Ok")
        return headers
    except Exception as ex:
        print("Fail: {}".format(ex))
    pass


def test_index_storage(headers):
    data = "Some Data"
    store_result = store_data({
        "pathParameters": {
            "deviceId": "device-123",
            "uid": "uid-123",
            "service": "sendtab"
        },
        "headers": headers,
        "body": json.dumps({
            "data": data
        })
    }, None)
    fetch_result = get_data({
        "pathParameters": {
            "deviceId": "device-123",
            "uid": "uid-123",
            "service": "sendtab"
        },
        "headers": headers,
        "queryStringParameters": {
            "index": json.loads(store_result['body'])['index']
        },
    }, None)
    body = json.loads(fetch_result['body'])
    assert(body['last'])
    assert(body['index'] == json.loads(store_result['body'])['index'])
    assert(body['messages'][0]['data'] == data)
    print('Ok')


def test_delete_storge(headers):
    del_data({
        "pathParameters": {
            "deviceId": "device-123",
            "uid": "uid-123",
            "service": "sendtab"
        },
        "headers": headers,
    })
    print("Ok")


if __name__ == "__main__":
    print("testing FxA validation...")
    headers = test_fxa_validate()
    print("testing indexed data storage...")
    test_index_storage(headers)
    print("testing delete...")
    test_delete_storge(headers)
