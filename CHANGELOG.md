<a name="0.3.0"></a>
## 0.3.0 (2020-02-29)


#### Refactor

*   cleanup no longer needed code ([a629a78c](https://github.com/mozilla-services/pushbox/commit/a629a78c6929c41750099f9e5b0283bd87d06b40))

#### Bug Fixes

*   fix query param handling per rocket 0.4 changes ([db6c36a7](https://github.com/mozilla-services/pushbox/commit/db6c36a769b33da5239f392ef58ab5dbd92c5256), closes [#61](https://github.com/mozilla-services/pushbox/issues/61))

#### Features

*   Differentiate GeneralError into more specific errors ([f328d882](https://github.com/mozilla-services/pushbox/commit/f328d882f6e568769b1148cde8b2ab4315766412), closes [#59](https://github.com/mozilla-services/pushbox/issues/59))

#### Chore

*   fix the mysql port ([3aca62a6](https://github.com/mozilla-services/pushbox/commit/3aca62a6eeeba62e0414ede3f67777006e19dd8e), closes [#65](https://github.com/mozilla-services/pushbox/issues/65))
*   cargo fix --edition-idioms ([51c1ea16](https://github.com/mozilla-services/pushbox/commit/51c1ea16f923090ea7eda931445565400ceb735c))
*   cargo fix --edition ([c7e2312f](https://github.com/mozilla-services/pushbox/commit/c7e2312fc868dea9292fe5f9639f15b39b82557d))
*   update deps ([733f6ac7](https://github.com/mozilla-services/pushbox/commit/733f6ac7cd6616bb21725fafae88c1180de4442c), closes [#63](https://github.com/mozilla-services/pushbox/issues/63))
*   update rust nightly ([6b24ecc8](https://github.com/mozilla-services/pushbox/commit/6b24ecc8654cc040ff82b651f20a2c7bcef92f22))
*   Dependency Update 10/2019 ([e9c1f043](https://github.com/mozilla-services/pushbox/commit/e9c1f043793d2ca60f444f713d2f8e935b668731))
*   Update deps ([0e426b0b](https://github.com/mozilla-services/pushbox/commit/0e426b0b332d18ea239bc34c09a0188a783b6332))
*   Update cargo deps ([40f3688a](https://github.com/mozilla-services/pushbox/commit/40f3688a78bc92fd2332c7016e5d7e8b586c2332))
*   Update dependencies ([b93d9183](https://github.com/mozilla-services/pushbox/commit/b93d9183cccac835912fbc0cb19cbf6cfe23ff35), closes [#53](https://github.com/mozilla-services/pushbox/issues/53))
*   Add Code of Conduct ([4b803d62](https://github.com/mozilla-services/pushbox/commit/4b803d6249568b4054a1df59a7db488852afb358))
*   library updates ([adad9ee4](https://github.com/mozilla-services/pushbox/commit/adad9ee40d9be32b2055cd845b74a82ccc31ee99))
*   remove /sls and add .dockerignore ([505bb197](https://github.com/mozilla-services/pushbox/commit/505bb19714de0d02fc22cf2eba15aba9080b90b1), closes [#46](https://github.com/mozilla-services/pushbox/issues/46))
*   utilize a rust-toolchain file ([2b65c02c](https://github.com/mozilla-services/pushbox/commit/2b65c02c42b77cacae9da61d3bb6cc1af98ac7b4))



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



