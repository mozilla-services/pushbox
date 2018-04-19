import logging
import json
import os
from urllib import request, error
from functools import wraps

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FXA_SERVER_KEY = os.environ.get("FXA_SERVER_KEY", "configure_me").lower()

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
            logger.exception("Exception running validate: {}".format(exc))
            raise
    return wrapper


@log_exceptions
def validate(event):
    logger.info("Auth was set to: {}".format(event))
    # Parse the ARN.
    (user_id, device_id) = event['methodArn'].split(
        ":")[-1].split("/")[5:]
    if not device_id:
        raise HandlerException(
            status_code=500,
            message="Missing device_id")
    # extract the FxA Server Key from the Authorization header
    try:
        token = event["authorizationToken"]
        assert token.lower().startswith("fxa-server-key")
        auth = token.strip().split(None, 1)[1].lower()
    except KeyError:
        raise HandlerException(
            status_code=401,
            message="Missing authorization header")
    except IndexError:
        raise HandlerException(
            status_code=401,
            message="Invalid authorization header"
        )
    if auth != FXA_SERVER_KEY:
        raise HandlerException(
            status_code=401,
            message="Invalid authorization token"
        )
    return True


def generate_policy(event, effect, resource):
    arn_bits = event['methodArn'].split(':')
    region = arn_bits[3]
    account_id = arn_bits[4]
    # Parse the ARN.
    (api_id, stage, verb) = event['methodArn'].split(
        ":")[-1].split("/")[:3]
    # Bless everything because argblargblargblarg
    # region:accountId:restApiId:stage:
    resource_arn = "arn:aws:execute-api:{}:{}:{}/{}/{}/*".format(
        region,
        account_id,
        api_id,
        stage,
        verb
        )
    auth_response = dict(
        principalId="user"
    )
    if effect and resource:
        auth_response["policyDocument"] = dict(
            Version="2012-10-17",
            Statement=[
                dict(
                    Action="execute-api:Invoke",
                    Effect=effect,
                    Resource=resource_arn)
                ],
        )
    return auth_response


def fxa_validate(event, context):
    try:
        if not validate(event):
            raise Exception("Unauthorized")
    except HandlerException as ex:
        if ex.status_code == 401:
            logging.error("Unauthorized")
            raise Exception("Unauthorized")
        else:
            logging.error("Read Error: {}".format(ex))
            raise Exception("Server Error: {}".format(ex.message))
    return generate_policy(event, 'Allow', event.get("methodArn"))


def test_fxa_validate():

    token = os.environ.get("FXA_TOKEN")
    result = fxa_validate(
        {"type": 'TOKEN',
         "methodArn": ("arn:aws:execute-api:us-east-1:927034868273:3ksq"
                       "xftunj/dev/POST/v1/store/e6bddbeae45048"
                       "838e5a97eeba6633a7/11579fc58d0c5120329b5f7e0f7e"
                       "7c3a"),
         "authorizationToken": "FxA-Server-Key {}".format(token)},
        None)
    assert(result == {
        'principalId': 'user',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': 'Allow',
                'Resource': ('arn:aws:execute-api:us-east-1:927034868273:'
                             '3ksqxftunj/dev/POST/*')}]
        }
    })
    print("Ok")
    return token

if __name__ == "__main__":
    print("testing FxA validation...")
    token = test_fxa_validate()
    print("Authorization: FxA-Server-Key {}".format(token))
