# Legacy Pushbox Serverless Prototype

***NOTE*** This is legacy and may be removed at any time.

This is a work in progress of the serverless PushBox supplimental sync
storage service using the [serverless](https://github.com/serverless) framework

## requirements:
* [aws cli](https://aws.amazon.com/cli/)
    * [See configuration info](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)
* [Python 3.6](https://www.python.org/downloads/release/python-364/)

Please note, Severless currently does not support python "offline", you will
have to `sls deploy` in order to test. (Remember to run `sls remove` after
to clean up.)


See [API doc](
https://docs.google.com/document/d/1YT6gh125Tu03eM42Vb_LKjvgxc4qrGGZsty1_ajf2YM/)

Installation:

```
$ npm install serverless
$ npm install serverless-python-requirements
$ npm install serverless-domain-manager --save-dev
```

# Deploying
## packaging
Images must stay less than about 200K. You should aggressively exclude
anything that is not absolutely necessary. Only directories and explicit
full file paths can be excluded.

## domain-manager

Unfortunately, there are a number of bugs with domain-manager.

1) It will look for the first certificate for a given domain match,
ths may result in it pulling an expired (or soon to be expired) cert from
the certificate manager. Apparently, you can't specify an ARN for a valid
certificate.
2) The cert MUST be in the region that you're deploying to.

## Deploy command
`sls deploy [-s stage]`

`-s` optionally changes the **stage** from `dev`


## Post deploy steps
You can specify the `stage` you want to deploy using the `-s` command line argument. If you
do not specify, the default value for `stage` is `dev`.

* Go to the [Amazon API Gateway:Custom Domain Names](https://console.aws.amazon.com/apigateway/home?region=us-east-1#/custom-domain-names) section
* Create a Custom Domain Name
* Set the *Domain Name* to match your desired host name (e.g. `pushbox.dev.mozaws.net`) You may
want to [verify the cert identifier from ACM](https://console.aws.amazon.com/acm/home)
* Set the **Base Path Mappings**
    * Leave **Path** empty
    * Set **Destination** to match your new API instance which is `$stage-pushbox(...)`.
    * Set the Stage to match your deployed stage

* Click ***Save***

It may take up to 40 minutes before the domain is available.
