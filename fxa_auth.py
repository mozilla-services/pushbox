import logging
import json
import os
from urllib import request, error
from functools import wraps

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FXA_HOST = os.environ.get("FXA_VERIFY_HOST", "oauth.stage.mozaws.net")


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
def validate(event, func):
    logger.info("Auth was set to: {} | {}".format(func, event))
    # Parse the ARN.
    (service, user_id, device_id) = event['methodArn'].split(
        ":")[-1].split("/")[5:]
    if not device_id:
        raise HandlerException(
            status_code=500,
            message="Missing device_id")
    # extract the FxA OAuth token from the Authorization header
    try:
        token = event["authorizationToken"]
        assert token.lower().startswith("bearer")
        auth = token.strip().split(None, 1)[1]
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
        logger.info("Calling: POST {} ({}) ".format(
            "https://{}/v1/verify".format(FXA_HOST),
            json.dumps(json.dumps({"token": auth}))
            ))
        req = request.Request(
            "https://{}/v1/verify".format(FXA_HOST),
            method="POST",
            data=json.dumps({"token": auth}).encode('utf8'),
            headers={"content-type": "application/json"})
        try:
            response = request.urlopen(req, timeout=5).read()
        except error.HTTPError as ex:
            raise HandlerException(
                status_code=ex.code,
                message="{} {}".format(ex.msg, ex.fp.read()))
        except Exception as ex:
            raise HandlerException(
                status_code=500,
                message="Exception: {}".format(ex)
            )
        scopes = set(json.loads(response)["scope"])
        actions = {}
        if "https://identity.mozilla.com/apps/pushbox/" in scopes:
            return ['write', 'read']
        if "https://identity.mozilla.com/apps/pushbox/send" in scopes:
            actions['write'] = True
        if "https://identity.mozilla.com/apps/pushbox/recv" in scopes:
            actions["read"] = True
        if ("https://identity.mozilla.com/apps/pushbox/send/{}".format(
                device_id) in scopes):
            actions["write"] = True
        if ("https://identity.mozilla.com/apps/pushbox/recv/{}".format(
                device_id) in scopes):
            actions["read"] = True
        return func in actions
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


def fxa_validate_read(event, context):
    try:
        if not validate(event, "read"):
            raise Exception("Unauthorized")
    except HandlerException as ex:
        if ex.status_code == 401:
            logging.error("Unauthorized")
            raise Exception("Unauthorized")
        else:
            logging.error("Read Error: {}".format(ex))
            raise Exception("Server Error: {}".format(ex.message))
    return generate_policy(event, 'Allow', event.get("methodArn"))


def fxa_validate_write(event, context):
    try:
        if not validate(event, "write"):
            raise Exception("Unauthorized")
    except HandlerException as ex:
        if ex.status_code == 401:
            logging.error("Unauthorized")
            raise Exception("Unauthorized")
        else:
            logging.error("Write Error: {}".format(ex))
            raise Exception("Server Error: {}".format(ex.message))
    return generate_policy(event, 'Allow', event.get("methodArn"))


def test_fxa_validate():
    """Test the FxA validation routines.

    This requires the PyFxA 0.5.0 module.

    """
    from fxa.tools.create_user import create_new_fxa_account
    from fxa.tools.bearer import get_bearer_token
    from fxa.constants import ENVIRONMENT_URLS

    token = os.environ.get("FXA_TOKEN")
    if not token:
        email, password = create_new_fxa_account(
            fxa_user_salt=None,
            account_server_url=ENVIRONMENT_URLS['stage']['authentication'],
            prefix='fxa',
            content_server_url=ENVIRONMENT_URLS['stage']['content'],
        )
        token = get_bearer_token(
            email=email,
            password=password,
            scopes=["https://identity.mozilla.com/apps/pushbox/"],
            account_server_url=ENVIRONMENT_URLS['stage']['authentication'],
            oauth_server_url=ENVIRONMENT_URLS['stage']['oauth'],
            client_id="5882386c6d801776",
        )
    print("Token: Bearer {}".format(token))
    result = fxa_validate_read(
        {"type": 'TOKEN',
         "methodArn": ("arn:aws:execute-api:us-east-1:927034868273:3ksq"
                       "xftunj/dev/POST/v1/store/sendtab/e6bddbeae45048"
                       "838e5a97eeba6633a7/11579fc58d0c5120329b5f7e0f7e"
                       "7c3a"),
         "authorizationToken": "Bearer {}".format(token)},
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
    print("Authorization: Bearer {}".format(token))
