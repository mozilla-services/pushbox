#! /bin/bash
set -e
AUTH=`bin/python fxa_auth.py | tail -1`
HOST=https://pushbox.dev.mozaws.net
#HOST=https://3ksqxftunj.execute-api.us-east-1.amazonaws.com/dev
curl -v -X POST $HOST/v1/store/sendtab/fakey/fakefake \
    -H "$AUTH" \
    -d '{"data": "Mary had a little lamb, with a nice mint jelly", "ttl": 25000}'
echo ""
curl -v -X GET $HOST/v1/store/sendtab/fakey/fakefake \
    -H "$AUTH"
echo ""
