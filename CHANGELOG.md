<a name="0.1.2"></a>
## 0.1.2 (2018-08-21)


#### Bug Fixes

*   Fix deployment SQS issue ([c3ab1dc7](https://github.com/mozilla-services/pushbox/commit/c3ab1dc77f32b555f62fcf9ade428fc3c1d35a2e), closes [#42](https://github.com/mozilla-services/pushbox/issues/42))
*   Allow AWS_LOCAL_SQS to specify more than just custom regions. ([a51e6ef0](https://github.com/mozilla-services/pushbox/commit/a51e6ef0d2933652019a1a27050aede7e7baea7b))
*   skip sqs mod testing on travis ([b0f3508b](https://github.com/mozilla-services/pushbox/commit/b0f3508bd9a96a3114e039478e657dbbeee00188), closes [#39](https://github.com/mozilla-services/pushbox/issues/39))



<a name="0.1.1"></a>
## 0.1.1 (2018-07-31)


#### Bug Fixes

*   strip FxA-Request-Id from the response ([ad09cdaa](https://github.com/mozilla-services/pushbox/commit/ad09cdaace7236e012af4a2fef43c199afcee342), closes [#36](https://github.com/mozilla-services/pushbox/issues/36))

#### Features

*   hacky support of ROCKET_LOG=off ([1c63ee3a](https://github.com/mozilla-services/pushbox/commit/1c63ee3a0242ad7f90ab6a4a2280c70dfe2ecb0e), closes [#33](https://github.com/mozilla-services/pushbox/issues/33))



<a name="0.1.0"></a>
## 0.1.0 (2018-07-25)


#### Bug Fixes

*   fix aws paramater typing ([9130cd16](https://github.com/mozilla-services/pushbox/commit/9130cd16b303b6934d962e151912d50d8b0bdeb2))
*   unquote data response & fix limit=0 indexing (#19) ([ba491c9a](https://github.com/mozilla-services/pushbox/commit/ba491c9ae8712609baa7034087edeed66ae822bb))

#### Features

*   support dockerflow style health checks ([59949d5e](https://github.com/mozilla-services/pushbox/commit/59949d5ee0421c0a839e2ba4eff6268da33748cf), closes [#30](https://github.com/mozilla-services/pushbox/issues/30))
*   add pass thru trace id (#26) ([b8aeb628](https://github.com/mozilla-services/pushbox/commit/b8aeb628d6f2981b4b38b2d5e164d44e3f97d71b), closes [#24](https://github.com/mozilla-services/pushbox/issues/24))
*   Add version.json (#28) ([f502bacd](https://github.com/mozilla-services/pushbox/commit/f502bacdaefa8219a61f4e07c07ab0edc0de2948), closes [#27](https://github.com/mozilla-services/pushbox/issues/27))
*   add errnos ([b4f500e6](https://github.com/mozilla-services/pushbox/commit/b4f500e6b179a3680fb79842a2ed994b44798ea8), closes [#23](https://github.com/mozilla-services/pushbox/issues/23))
*   Add documentation (#22) ([402038ff](https://github.com/mozilla-services/pushbox/commit/402038ff4f442e394a17794b66ad2e5f1f4260ae))
*   support lcip.org domain ([11a5cd44](https://github.com/mozilla-services/pushbox/commit/11a5cd448e3174156f1574ed07479e6094b51e37))
*   Move auth to own handler ([a53029ae](https://github.com/mozilla-services/pushbox/commit/a53029aec62d79382f56dd08e975e0c3744cc5da))
*   add primitive delete function ([3bd4a359](https://github.com/mozilla-services/pushbox/commit/3bd4a3596d36a049bc76582cc48d86731e959cdf))

#### Chore

*   install ca-certificates when building docker image. ([a4128d64](https://github.com/mozilla-services/pushbox/commit/a4128d64b8719b707dc0dce3fb502de10c0937b6))
*   initial skeleton ([1d3887d1](https://github.com/mozilla-services/pushbox/commit/1d3887d11a3e7a518f5453318a0ec8b80a4f2ed5))

#### Refactor

*   Convert to rust (#20) ([5ff075a5](https://github.com/mozilla-services/pushbox/commit/5ff075a5b4db8f687d7e197b7a6717cd3d77bcc1), closes [#16](https://github.com/mozilla-services/pushbox/issues/16))



