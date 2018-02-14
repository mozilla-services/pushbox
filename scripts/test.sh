#!/usr/bin/env bash
# Preliminary integration test script
if [ "$DHOST" == "" ]; then
    echo "Tip: Set DHOST = endpoint host name."
    DHOST=$0
fi
UID="test_uid"
DID="test_deviceid"
curl -v -X POST "https://$DHOST/dev/v1/store/$UID/$DID/sendtab" \
-H "Authentication: fxa sometoken" \
-d @post.data

curl -v -X GET "https://$DHOST/dev/v1/store/$UID/$DID/sendtab" \
-H "Authentication: fxa sometoken" \
