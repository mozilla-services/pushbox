#! /bin/bash
set -e
#HOST=https://pushbox.dev.lcip.org
HOST=https://pushbox.dev.mozaws.net
#HOST=https://3ksqxftunj.execute-api.us-east-1.amazonaws.com/dev
AUTH=`bin/python fxa_auth.py | tail -1`
curl -v -X POST $HOST/v1/store/fakey/fakefake \
    -H "$AUTH" \
    -d '{"data": "Mary had a little lamb, with a nice mint jelly", "ttl": 25000}'
echo ""
curl -v -X GET $HOST/v1/store/fakey/fakefake \
    -H "$AUTH"
echo ""
