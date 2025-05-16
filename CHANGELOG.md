## [1.0.1](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/compare/1.0.0...1.0.1) (2025-05-16)

### Bug Fixes

* package import ([46dee8a](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/46dee8adc87b3ebe0df2bbe829e436e6cef0dab2))

### Performance improvements

* optimize ngrams extraction using for comprehension ([53ef5b7](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/53ef5b7b570193bf580458eedd5aa63b9f2edea7))

### General maintenance

* adjust docker compose ([30f6fed](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/30f6fed80ce31591e59e426f9d71ad4b534193ca))
* remove data split doc ([7263933](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/7263933333bd17933eec36ad1a0bb8ea5ec219d7))
* update docker image in compose file ([c4ab49e](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/c4ab49edfc2061579a62660cf1c10fd6e7b5de25))
* use poetry in dockerfile ([bf5540a](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/bf5540a81925615448a52f713d0922d9e493a4c8))

## 1.0.0 (2025-05-03)

### Features

* 50-50, 70-30, 62-38 splits ([5981d83](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/5981d83367026d47192aa9d5833f3e41fc4ec5e2))
* add basic clustering on 5 families ([f71744d](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/f71744deb4012ce66e7a001d560caf36b8102fd1))
* add docker compose for deployment ([45a217c](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/45a217c5c93ea981f342f393c16793664e014497))
* add widget for sliding window ([dea966c](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/dea966c2eecd0f9c9fe46a5a62dcbd0e798b44bb))
* analyze variance - weighted average timestamp correlation ([3a94cc4](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/3a94cc42141b7999aea687b4a10171cdcf60b9e0))
* best split based on KL and overlapping score ([60f3498](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/60f349847156fc0a207d421b6df9f82d1a00483b))
* best split based on max KL divergence ([405e2bf](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/405e2bfb271040b999ba0414af6b96a81128fc32))
* best split families contribution ([503c6c2](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/503c6c2df6f950b9e6c9009cba19a98389834dda))
* first submissions distribution ([9fdd8ee](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/9fdd8ee993b6dffa2297281c73fc9dffb1ed0003))
* impl score based on [#disappearing](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/issues/disappearing) families and [#appearing](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/issues/appearing) families ([115f383](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/115f38322850aac2c467b471d2d43309735531ab))
* optimize ngrams extraction ([4af8dd8](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/4af8dd8292749b3e95a64037b098a4b9fa96a2bd))

### Bug Fixes

* change docker compose image ([e5c4186](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/e5c41869d968bdb542d980e16242fe2fd9c44e12))
* cores in chunks ([af82240](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/af8224040ce6de2dafe8ed1e9c7a4b9ef69cc401))
* dir in merge notebook ([83d810a](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/83d810a5d04db99519dd53cfb7b4e860e0e699e6))
* docker build ([e92ec61](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/e92ec61df20ec2d18423051f494f74922e492789))
* errors ([f47bfb5](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/f47bfb5517a29a7703a8d5f3027c4e10ce6acdb5))
* feature extraction ([5688ae3](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/5688ae331587c4f4094ee37c96651dbaa914860f))
* ngrams extraction ([f7bd9e0](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/f7bd9e0525fd961e436dfaed05f0f12f64d80beb))
* ngrams extraction ([30c8f51](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/30c8f511eecf93ae67393cb0a4539c2adcc34154))
* output directory ([9cdbf68](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/9cdbf68c65a5f682834f54f543e2241ea23f36f7))
* python version ([023bfed](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/023bfed46a4dbce7be85c9b444fba9a753afbc91))
* remove pycache ([73c09c6](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/73c09c60dffdb9a7323f5685b53cfffc2056d8d1))
* top imports ([f7f5eb0](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/f7f5eb03b0ed306a77945be6cf20cc09b6425103))
* use jensen shannon distance instead of KL ([986a1cd](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/986a1cdf22c0851e4ad5f05c35b2f04d14330511))

### Documentation

* update readme ([c84fdba](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/c84fdba52dd9e1a40c3a092c5e83b0de074ed11a))

### Build and continuous integration

* add deploy image file ([d8788af](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/d8788af130ca2e069016bb920b3351f17379c060))

### General maintenance

* add capa config ([a08c599](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/a08c599594b92c4c1cffa7de4b410d828392abae))
* add capa script ([1d545af](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/1d545afce7d79bdbed6e37d8c4984818804abed8))
* add comment, refactor ([0abb51b](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/0abb51b7fd95d18b173c6a0373119659a9479dc2))
* add config ([29001c8](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/29001c83b065a30ccd2329a7755d2a72e780f787))
* add equidistanced splits ([e064bcf](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/e064bcf8a7e3f0b0fd5cf32e1a663bf9ae82d66e))
* add python poetry template ([54f2fcd](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/54f2fcd755d3cb84d0150edc42f70f88471d7866))
* add readme and requirements ([30a66ce](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/30a66ce446482ee68de948126ab429ec542cbf09))
* add registry image in docker compose ([8fa23fa](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/8fa23fa3b3e8a30f37d85a445c9a7c9fb4048095))
* add ruff dep ([bf2612f](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/bf2612f2c9c44cc5620e0f78616be3c28fefc06b))
* add slope graph w/linear regression ([3c6184c](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/3c6184c957a018f5b3d147d2de5bbf5eb7998065))
* add stdout files ([fc3d943](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/fc3d94319ce5f624999629532d6e9582c3f2d67a))
* add variance repo (save) ([71307cf](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/71307cf2f09b8710ccb13ff6299da01c1e0182e5))
* clean code in imports and malware dataset ([483e8e9](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/483e8e99ead74845d70eab8910c8b00f9d8fbc77))
* edit build_labels_data_frame ([8047dfb](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/8047dfb4afb58332b8058d827c926ea407e8c514))
* edit labels extraction ([e817f7e](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/e817f7e02de6ea5b117d912ad8c04f33909a8893))
* edit top ngrams extraction ([d859a79](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/d859a79d746f14bc7ac028153cb9360d75f96b8a))
* extract only ngrams ([57a9dff](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/57a9dffabd4f64adf43dc19d93be8058d539cac0))
* model static feature extractor, del unused dirs ([a536794](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/a5367943479b75b535ae6617f9ae95a08ec68cfd))
* modify objective function ([ab4e11a](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/ab4e11a3cb655bac2a534dfe93a69fd9e1fc3ac5))
* PCA notebook ([9f3461d](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/9f3461d27816f0934740b95b21d79fdc3abe7142))
* random projection + ac dendogram computation ([77de489](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/77de489285c3e6b8c7fc884ccd109134ead533d4))
* refine setup.py ([0c0cb56](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/0c0cb56c8de5f2ea614f09410a30f011a58af808))
* remove binary flag ([0f63917](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/0f63917cafbafcc274c80d149f0cd8faa72538f2))
* remove junk dir ([aee222d](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/aee222ddcc950bbddbc088aed1fa7b665ab6f5f4))
* remove plot arg ([2e0dd23](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/2e0dd23cf52adf1ba2433c958cc8b7b295529772))
* save ([50df144](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/50df1441d3b05f3cf2231e40043d44e21e638209))
* simplify docker compose ([dba1f08](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/dba1f08252d1550fd11c72efffc1c86c5fcb6322))
* small edits ([21cc7f5](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/21cc7f5d9c6b09c4d46df53cbe2816461235bd63))
* sort families in descending order based on probability difference train/test ([0953c10](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/0953c103196f03e28034dcf88e0a1d065d306159))
* start silhouette analysis ([8556416](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/8556416bb443e9a820bb7202528f25d888d7edc3))
* sync ([1d9e9dc](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/1d9e9dc08efd3f4720abef7943a6813fb8cb5b0f))
* sync ([cbee81c](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/cbee81c834153b30ec4e2a19439197a4daa05b1b))
* sync ([f76a573](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/f76a57322b573f022b86322733d90ba6f1731a76))
* sync ([8122993](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/81229933e51fe3b81c1d1d024413c45c3747f30f))
* sync kl divergence file, refactor family distr ([b80aa67](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/b80aa671eb9f79df6fed96b174257edcb32509c0))
* to snake case ([50a4597](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/50a4597f5b37d152730db16daaa0fb1a2f4b9a1f))
* update .gitignore ([51ce7f6](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/51ce7f6b37f388fb48bf13743d7c5efc6124e3dd))
* update notebook w/PCA ([1713a13](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/1713a138c807b12e6ec5c7b104f9d8a5983f3a2e))
* update readme ([4cf6bb7](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/4cf6bb74319b9efa0ec0b4d031f5aae769558dff))
* update setup.py ([ce141a5](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/ce141a5920dd5b53bdd85517f6662725bcf2b081))
* upload analyze variances ([1485734](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/14857348411856170999fffcb1c50a048999647b))
* upload feature extraction code ([48d1f20](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/48d1f203c11697580affed365486c157f5715468))
* upload notebooks ([28ba14c](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/28ba14c585b54479a2ffd1b614a22c53ec250a40))
* use shell commands in strings extraction ([c394cb0](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/c394cb09abe3494b4a8bc1b4aab4812be5649ff2))
* variance cumulative distribution ([1d489e3](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/1d489e3ae81519dbc329c86d3dd36c0039b3d18f))

### Style improvements

* format code ([202e740](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/202e740227dfe4b38decc0d4a8f3eaa72f314b34))

### Refactoring

* add best split timestamp ([71a7974](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/71a7974c717d639bd69620b22d062244c25aef33))
* add static method decorator ([394c9bb](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/394c9bb5292b35f1c73484cf9ddd76e7393baf12))
* clean base dir ([8f99e70](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/8f99e707f254ee3ce1b97d41765137463731443a))
* config file - move labels dataset build to setup_dataset package ([0d176fc](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/0d176fcefc8e684de7a3e3f86d3a45f7b15f486d))
* create classes, add cluster models random proj + knn + agglomerative cl ([3c167ac](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/3c167ac64e8b642a359d7f3dbab76d83ff9a2cf2))
* create config sum type ([ec3841d](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/ec3841de7fbadc5436f6b773359adebf0485bffe))
* feature extraction code ([eec1266](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/eec126651eadc08e788324ca30c0b465ab9ce72b))
* move best split code in separate package ([194b9b8](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/194b9b8c25185458aa604a35e94ae60d354d5329))
* move classification package, remove unused dirs ([78c5332](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/78c53326729148c59621aae14e077d11aea5707e))
* move packages ([1b07575](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/1b075757bed60b19f1671d8e72f01a8a2d9ac42a))
* notebook packages ([100dd60](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/100dd60e23e1082b600d5b93ee81e44f6fd6054a))
* organize code, delete unused dirs ([6278faa](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/6278faadc28794d65d36152f7aba3abd7660b2d8))
* packages ([8a5b64d](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/8a5b64d1164d9b951d2a80388c52314170c6a355))
* packages after setup.py ([bea84b7](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/bea84b7d0f682f52ea7004c0e9f76cd5d3bc93d5))
* remove unecessary dirs ([8fe805b](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/8fe805b3e44e34d34852a0b7277b850169cf9c1e))
* remove unused directories, update gitignore ([2c5fabb](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/2c5fabb48bffcbce45c6c588c19718d1ab19ec3a))
* rename file ([f6b283e](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/f6b283e0a3dcbecfc0cf5a42ee2485257322c254))
* top imports and top ngrams ([d2dbaee](https://github.com/Malware-Concept-Drift-Detection/dts-features-extraction/commit/d2dbaee57fa80d19a9edcdf3809d9e2f51979fec))
