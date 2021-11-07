using System.Diagnostics.CodeAnalysis;

namespace Konscious.Security.Cryptography.Test
{
    using System;
    using Xunit;

    [SuppressMessage("Microsoft.Naming", "CA1707")]
    public class ModifiedBlake2Tests
    {
        [Fact]
        public void Compress_MatchesArgon2ImplWithNonZeros()
        {
            ulong[] prev = {
                0xac08119e3c72f5b5UL, 0x2a13fdad0c703169UL, 0x5f1751422a7716bcUL, 0x0ec86d7ff58cb708UL,
                0x1aeb332d05f1d5ebUL, 0xdda5743e8949aa7eUL, 0x0eb23c256f2acb06UL, 0x5aed523fe93cfb2fUL,
                0xefa2a0583c370d8fUL, 0xba69ac974af68131UL, 0xb9bf395779a9a256UL, 0x4f1f28435f2d4826UL,
                0xf46e87503f904a58UL, 0x148cb33f2894640cUL, 0x93962fd7e863322aUL, 0x1b895ed10479aaa8UL,
                0x4c9215682f6c5d3cUL, 0x375c0e386cb788d6UL, 0xafcb9be2d58cffbbUL, 0x1b31e43bad8efadfUL,
                0x30c536294e57f0baUL, 0x15d67038d038e9deUL, 0x199dab68ee5e3303UL, 0xd542cfc1a894ecdaUL,
                0xeff4e9c7e0994a08UL, 0x224e94ae0ed1f729UL, 0x6e9f04249f2c201fUL, 0x8ddc2eabf9fed473UL,
                0x441679b88742976bUL, 0xc73a19660adcf39eUL, 0x994adf85535fd44dUL, 0xbde750e5d8c3c479UL,
                0xe442e6fd1c51f7adUL, 0x3e0f265b027c99eaUL, 0x9a10b30d709f7922UL, 0x9230cfa76893ff2aUL,
                0x2aea926674f971dcUL, 0x1cf54df9274b1d49UL, 0x37c7f35b33526356UL, 0xbc0a44c9bf1f71fcUL,
                0xd164263c6dc90855UL, 0x2476315d58f3e4a4UL, 0x9a0958813ca8e638UL, 0x60facc4afc041c82UL,
                0xe111f77637763f88UL, 0x0f9a3e354621d543UL, 0xd93c918202fd18b0UL, 0x3f7d27260c998a59UL,
                0xd335ae2fa011d3dfUL, 0x269b6aeb9765384cUL, 0x4f842cb7960500caUL, 0x62292f1c6073dcf5UL,
                0x8228969de666ef5dUL, 0x793b19f221df2f4dUL, 0x39d273e1ac9d1e2aUL, 0x624fc31546f1513fUL,
                0x88af32aca8e3f997UL, 0xdf5b4b652445d6f8UL, 0xcbe35643730ff80bUL, 0x8859d37e24b94032UL,
                0xbffc3bba4a37f0edUL, 0x371a2685a9b4faccUL, 0xb5d52b02e0513795UL, 0x21c567731d7f2c4eUL,
                0x5cac85577674fd20UL, 0xd899db5d0bbf7a3fUL, 0xc835ce7d457b2ef0UL, 0x1bc5da205f785943UL,
                0xfb02714430533a80UL, 0x02561bf3f1d13fbdUL, 0x38f355b23f9c63ddUL, 0xb7b66da7b2453b7bUL,
                0x04c50fb09a3d7604UL, 0x700906a29c25fe91UL, 0xa69be4ae7240c7b6UL, 0x5bb4bc8bc671510fUL,
                0xefe6b7769bdd154aUL, 0xc7cf61710591bfffUL, 0xa178909d7baaa5c4UL, 0xa8ff467883c9fde5UL,
                0x3a87a6b55a858b5cUL, 0xc8c58db5ec121ae0UL, 0xda92ccb84e8f4ff9UL, 0x111c3ce6dbae96a3UL,
                0xe4460cb6b51ad2aeUL, 0x8ff34ad8ea1b8881UL, 0x8e8dee723d5dfa45UL, 0x33529df799e32b10UL,
                0xdea9ef16f240e595UL, 0x5ad8942347237d90UL, 0xb1b4c1e11476b26eUL, 0xe727b1dcea913f1eUL,
                0x93596550e1d1fdccUL, 0x55a9a4883be6e1a9UL, 0x16219dc76f7c85c2UL, 0x1c1a8b1910a8461bUL,
                0xb0429af0158ab43cUL, 0xfc3156881086acbaUL, 0x5fef27b1caeab9aeUL, 0x0718de6358f5985dUL,
                0xd51fb4bc17b9ff32UL, 0x899e9b211b5ee6c7UL, 0x2028002e4263b33eUL, 0x3134371177805764UL,
                0x86e59036409ea832UL, 0x0b02a556f48773cfUL, 0x3aa9199aec6c1be9UL, 0x67d645f7d414d5e6UL,
                0x270e956ab690544bUL, 0x79121d982651d32aUL, 0x30a85a88878e766aUL, 0x297b4bfbff63a86eUL,
                0x599a999e95486575UL, 0x78ccd51c3bfeebe2UL, 0xd19aa070ecfa2b58UL, 0x700dcaed673c6582UL,
                0xf811021aacbfb063UL, 0x2979accda63cbcdfUL, 0xb7057e1d7ebe2c78UL, 0x60ce866273a877b7UL,
                0x3a2817ad948cfbaeUL, 0x66fca7e7f501f897UL, 0x13eada1887d70c54UL, 0x0c3508267067666fUL,
                0x8da61b612e17a5fbUL, 0x6169d862cae5b719UL, 0x4b7fff60a221c805UL, 0xe54b4d63fbef7242UL
            };

            ulong[] refblock = {
                0x2ddb79ddb9769fadUL, 0x94ffb877a736905eUL, 0xb6fa205f6654c9e5UL, 0x39323edfdbb43e36UL,
                0xa41b384366322385UL, 0x9f5e1e831ab87b5cUL, 0x9c0108c5d00aa4ccUL, 0x2bb3548b2b7f6fc5UL,
                0x412373693ff93d8dUL, 0xdf7bbe6a4e400e83UL, 0xb0293b8a0878d9c7UL, 0x1ad5ae075eb6a1c9UL,
                0xe8354a527a7d39a1UL, 0xbee6b2da30996bceUL, 0x9cece26d5a0ef191UL, 0xff74e3e4b431bfebUL,
                0x85e58a8f0a76788dUL, 0x6732603fc7b605d7UL, 0xe4e8c6bcb762a1ecUL, 0xbb9db1349667d599UL,
                0xc0d487631f7ffd3aUL, 0xc7cf2db05825f003UL, 0xd902a4866eeeabd5UL, 0x42bbf2f718dc2495UL,
                0x404928656e30ec55UL, 0x5a71d0c1bec17054UL, 0x012f70acff86ef92UL, 0x5706805a325eec9cUL,
                0x9e70fceb10ad476eUL, 0x2a38586922ba4cdcUL, 0x21fa90e12ffe2d87UL, 0x01193659de3e607cUL,
                0xbae848235d120419UL, 0x12b21e2230166870UL, 0xbc5924bda0372802UL, 0x86d7a4174dbb7e6bUL,
                0x46495f085a6634f7UL, 0x1a84cad2f9f2735eUL, 0x4ca245191e1fe1b9UL, 0x012cd48912b8cb75UL,
                0xadefd69278f29585UL, 0x2087f5d8398d10efUL, 0x6209f97005e5695eUL, 0xafd3cb17417e30c9UL,
                0x2b0bad06a38129ebUL, 0x250c0f0798696b91UL, 0xcefc5c4b0516cf10UL, 0x5bd9ed5c0a6a9f87UL,
                0xd4d3394b5dba7c2fUL, 0x0596cb22df7f6a42UL, 0x36e9a347fb5dac75UL, 0x60f57b23d2992f11UL,
                0xa79171492a6a55a8UL, 0x5c082da795f5feb4UL, 0x025d04a34a818c64UL, 0x992cb84c73b2fc36UL,
                0xffbe06f09082a330UL, 0xf05a48990f8aec41UL, 0xd2c532d8cfeae9a4UL, 0x1ab3c88f7f809edaUL,
                0x0830b17e518e4cd6UL, 0x7c4865f736080165UL, 0x5804594fe8762ef6UL, 0xe35352da3dc28b36UL,
                0x762a6dfcc59b0596UL, 0x70d082632d05f7edUL, 0x640b44d0d8c0366dUL, 0x665089b721e03665UL,
                0x2ebbae5b98f354b0UL, 0x801072466793dff9UL, 0xd31ce6043304dfb5UL, 0x7b71dc5abfc31997UL,
                0x5310cf60a60a198eUL, 0xf46a7b18966503aaUL, 0xfb87b5d4d0d75157UL, 0x8130f380e4a77408UL,
                0xba09a2742ff9dd98UL, 0x7f4adc03f07a9a1cUL, 0x5353920664e264b0UL, 0x662e20861e18f225UL,
                0xc14c4e0451083cb0UL, 0x5ea999be2c55d646UL, 0xd375592ce15d04c4UL, 0x853d97c7e88d820fUL,
                0xb608887aebd6f6c2UL, 0x4dbffaf4cd361f29UL, 0x795fbb5456b0a631UL, 0xdd64bd6b3af426ffUL,
                0x810f736e1459cc5cUL, 0x8def0b9ad2396487UL, 0x35a56dec89a9bdbaUL, 0xd4af0444efaf597bUL,
                0xf91107f853229769UL, 0x0529c53b6814c1e7UL, 0x6ed4de5670b07096UL, 0x204e657211e8b64fUL,
                0x4897390aded93dc1UL, 0x49b66b31580811cdUL, 0xfbc41995d8ef4c53UL, 0xd783f9bc0fce7480UL,
                0x0c94785d94d90efaUL, 0x1f752e0468afced8UL, 0x39cb5c225383d09aUL, 0x164b133d0c83481cUL,
                0x983064eea046abaeUL, 0xf946e86c6644781bUL, 0xefcc6755b46eba26UL, 0xe971c3e52a0c57cdUL,
                0xfa3929623270cd67UL, 0x4e490475dabffd2aUL, 0xd3f13f46164fc74aUL, 0x67a21193c89795cfUL,
                0xd6caa0beadd7c698UL, 0x02ef383251367248UL, 0x2a0a0052f9c76504UL, 0x4bd87c3cb711eacfUL,
                0xfe95b70fcfdf5f3eUL, 0x28f03415ee047566UL, 0xe706d105a83cd11fUL, 0xcee64b1410e4e069UL,
                0x84a5120b58297942UL, 0xd0b9ffc1132a075bUL, 0xda5e39c19f8d7edeUL, 0x615736febde8f196UL,
                0xd4a7cb983a98adb0UL, 0x71188cf27b22237fUL, 0xfc473063903be46eUL, 0xc485ff035663c61cUL
            };

            ulong[] nextblock = {
                0x5c7a8d6064a38f09UL, 0x2d67f6f6502cec7eUL, 0x3d86c47ec8f95c20UL, 0xe0d495bb52c566f5UL,
                0xf1ac54e8957c42a5UL, 0x6787e714f3296f62UL, 0xcc5ddbe15e0980acUL, 0x06affe40279086f1UL,
                0xe32198030071dc3aUL, 0x6a644b526f80abfeUL, 0x87275917240fe3b4UL, 0x7b5401701515b0feUL,
                0x641469458ccc8c51UL, 0x80e439ae57bb5a71UL, 0xc4264dd18628c374UL, 0x572f4743aa8f4a98UL,
                0x23e92b3ae758d577UL, 0x29561e71e337a9e9UL, 0x421f7d094029cc25UL, 0x7258c85edd202f96UL,
                0x8cf37425c9536f6aUL, 0x091169c7847f4aceUL, 0x5f8bdf0a1faf024fUL, 0xfdd3d822fc5b6d40UL,
                0xcc218073b5914e41UL, 0xe79f1bd3efbdc9e4UL, 0x3cc01d49f01ea94dUL, 0x1638c23cc407ad81UL,
                0x2b62bf15fdceab19UL, 0x12629d5962028012UL, 0x05ec749d63e9b214UL, 0xf84b61605770cc28UL,
                0xde381a384637bc44UL, 0x27a2866c7ec4ea29UL, 0x0695331153612a29UL, 0x1a0e5376e26c6b2aUL,
                0x1412596754c4c444UL, 0x9c564ef16c92b482UL, 0x965b36372a229bdaUL, 0xc1e3ad1ba9df7f31UL,
                0xe0e31b33b30868aaUL, 0x5784570225db0e41UL, 0xcc133d79f8e16009UL, 0x89ad5e0bc204cc54UL,
                0xcdcc6767e106ccc8UL, 0x7eb8545590deed4bUL, 0x7466744b60d50fdbUL, 0x9c6a2a79b437a543UL,
                0x8f700495e7efbf8cUL, 0x0f4842d61f5c24e2UL, 0x37451154a24feca7UL, 0x42bd9ec0bcf98171UL,
                0xd6f74e92b9453de9UL, 0x54a3666e76620cb1UL, 0x0c685f056538c43bUL, 0x95173c8b0e09ea35UL,
                0x2f3b6850125f36b3UL, 0x02afe482071334bbUL, 0xeb0e38a2e7c86b8bUL, 0x960230ce4ec84a6fUL,
                0xd8103d61d38bae42UL, 0x2797bf056f505322UL, 0x6ba7692a36acd731UL, 0xb660352b6068d072UL,
                0x511d854a9db6e30cUL, 0x6abb4f5f03978ee9UL, 0x7cb86538aa503abcUL, 0xf69dfbad145c37ffUL,
                0xbf04e2a0bcc69570UL, 0x8878e18967b2d32fUL, 0xcd03c31850aa29abUL, 0xd5410c6f0d84451dUL,
                0x52a640d98557f7b3UL, 0x1b73d4a6043f2251UL, 0x16d861c36b086183UL, 0x46ae1d725c8955fcUL,
                0x8ebcc22f6c7a7c0aUL, 0x34ad089bcfe41323UL, 0x9fc9646dd9ac177eUL, 0x0fa1a83d5de2d34bUL,
                0xf148137e0d1f42edUL, 0xd9855a2600914f1aUL, 0x6f94d3264f62a1cbUL, 0xf4665aa8109cda81UL,
                0x84e884bf5edf2a6dUL, 0x621fb92006d64a61UL, 0x5d2b28f789adddb8UL, 0x497cbe86b2db0bd3UL,
                0x8c16ef4816d84bbaUL, 0x1978dabf388025e2UL, 0x0d15a8a0af903622UL, 0xb7d98953abba626aUL,
                0x470c087e9680e710UL, 0x7f9a7d67397ab441UL, 0xaabab9d722a0e35cUL, 0x05e0861992320272UL,
                0x1d3d8108b562a824UL, 0x7049e3521c1ee645UL, 0x17accc619251a685UL, 0x4bb194bb17bcd00fUL,
                0xe63d91cea8dfe00fUL, 0xe8a130852e64f425UL, 0xd67e97c025343378UL, 0x93930d4ef92a74e6UL,
                0x902c4ec86aca72ecUL, 0x72b8271ebed4d1e3UL, 0x056ac58bdfcf0b79UL, 0x1386db78b80ddd0eUL,
                0x1b7413806c6b8501UL, 0xbe164f2758e290dbUL, 0xb2ff1c4b3c4fe607UL, 0xdbd139fa0714cfa7UL,
                0x6b5751e87cb47da2UL, 0xd810b9798b267e52UL, 0xe9f70a70bd3b916dUL, 0x860145daac8c3a17UL,
                0xc1883c7c22a58e12UL, 0xf22bfc4a4747260eUL, 0xd743ed106fccfb4cUL, 0x983c7fed6ed857bdUL,
                0x8b4f7b503438a734UL, 0x0cf8f13856ff282cUL, 0xe11dc424ef86ac34UL, 0x24f9e8eab995f682UL,
                0x55163af6d9cf706aUL, 0x100ed57a06d432aeUL, 0x83334d7b9d2813ffUL, 0xdda18d2727daaf45UL
            };

            var expected = new ulong[] {
                0x48f494ad1a95230cUL, 0xfef60ef591a0fa87UL, 0xedfdd76939b0d383UL, 0xbb3f0513d49b2783UL,
                0x0a8c7617962c2c5eUL, 0x61429ce9c27d75feUL, 0x3bcc1c4f6c07e4f7UL, 0xffba7ed30ec0a2c8UL,
                0x07b9936e93bc6d99UL, 0xfbc08995e2ad8834UL, 0xd9a07f199672a1d5UL, 0xaaf11cde9ddba050UL,
                0x74b9e21f02b6ad61UL, 0x17f5403878fccd90UL, 0x4c12172b1c51e7d2UL, 0x49303061a43d7541UL,
                0x3c8797877ad2785bUL, 0x2a9d1a824f7e0b11UL, 0xebfd836f3b36380bUL, 0x611db781b14d1534UL,
                0x0f7fb5ff30a49a16UL, 0x1193210adfef326bUL, 0x37f17f756d05c66fUL, 0x76a5b9618ce2678bUL,
                0x340371e1f18ad599UL, 0x8f10536736ff9e94UL, 0x1229bc260d5f8b5cUL, 0x5af0f58b3fa3eb9aUL,
                0xc58c8537c20c8f16UL, 0x2b5fb9aacb0aa28cUL, 0x32e98f169f7f368eUL, 0xd6ebf3a36d3b0547UL,
                0xb538fbe9aeee9bd7UL, 0xa6e20f73c40b727fUL, 0x8c198d23ee13bcdbUL, 0x36d131865692741bUL,
                0x197099a2684be352UL, 0xd3085489db5fbbf6UL, 0x0e9d0fc61078ea15UL, 0xe162b8f906c2b1ceUL,
                0xe1e2163c2b19b559UL, 0x021205b898ce0237UL, 0x50d0c59965b28be7UL, 0xc89b841f4ddb01bbUL,
                0xf64f1d58668ba114UL, 0x5cfe13439a32545cUL, 0xa1632fe57ade4c91UL, 0x481bc2c889270f12UL,
                0xfb6f8740732e6dbaUL, 0x03a0d93a9f1e20a6UL, 0xc2cea2cf6f9a4057UL, 0x708212871f7cf03aUL,
                0x53810bdff434f534UL, 0xafaf1412906e1a63UL, 0x68b39dfe0325008fUL, 0x318406ac5d124f7cUL,
                0x64c5895b01848ad7UL, 0x243cbda048ee9e44UL, 0x00265c1db3061995UL, 0x7f859ad85d1aeaceUL,
                0x711f4c249d0caa30UL, 0x1066d13f9208fd9cUL, 0xace423b6f74d7af3UL, 0x95b1da505a47f12cUL,
                0x9c2536f4f1e1bb22UL, 0x86c682118c60d541UL, 0x5a8ee1ab4caf8debUL, 0x829838aad3edb6f9UL,
                0x2096affd25ec4195UL, 0x7cd6807260d8d461UL, 0x2bee3a59f729145aUL, 0xab0d552a783fadb8UL,
                0x00bfb640e9590d2bUL, 0x0bc4ab1e36757df1UL, 0x6b9f65529a7137cfUL, 0x382a8d1283298fe9UL,
                0x286088013cf6f08bUL, 0xb2f40af560b0a406UL, 0x5a858b1e826af112UL, 0xfe0c3bba7f9b5b74UL,
                0x74cd6ba6717c75deUL, 0xac5822d987ca84aeUL, 0x6d8dc436112596f3UL, 0x8a3e745951b967ffUL,
                0x77c608878fe23f67UL, 0x724f9d8419734268UL, 0x030f14acc4049ec6UL, 0x1d03d941262b4d37UL,
                0x06b41a911e28a768UL, 0x05aca14ea398a071UL, 0xc2f3940734392c3cUL, 0x7d557bcbd3b60ed4UL,
                0x998fa62f87745c00UL, 0xdf55945f3f786efeUL, 0x9b43df14f302fcf5UL, 0x127cb197a61dd5b2UL,
                0xffe6460360584aceUL, 0x9b26714d0b6957e7UL, 0xe31a6e51c75cb367UL, 0xa581987d2b2f684dUL,
                0x23ebbe78a45878a2UL, 0x5091ccd53040c84cUL, 0xdf2534d6695abe82UL, 0x9d036e62476c7918UL,
                0xfa901d78e3774433UL, 0x52f42766e1add661UL, 0xb9ba2ef54c7200feUL, 0x1ae4a77074790ae4UL,
                0x8f4cebe7f0c481bfUL, 0x4c347c41df2e01abUL, 0xb53a73ccce0e7c8cUL, 0xf5c78e486c5c1ff0UL,
                0xe408d6da34809351UL, 0x026bf430996fd516UL, 0x4dd3b473f21302dfUL, 0xc7937ca3963bd454UL,
                0x567d2b5ede2f42bdUL, 0xcb4c17494b659c2aUL, 0x6633b3d5ce5c6fcdUL, 0x10b74f115f4f0eebUL,
                0x286c3a44932793ffUL, 0x0f0c02f5123acecdUL, 0xa9b5d9a5c8d3151dUL, 0x76ce1f50b45b46cfUL,
                0x9d0a939c6d3bb46cUL, 0xb046a0941c1b092dUL, 0x87c31932d2543161UL, 0x355040650606e96dUL
            };

            Argon2Core.Compress(
                new Argon2Memory(nextblock.AsMemory()),
                new Argon2Memory(refblock.AsMemory()),
                new Argon2Memory(prev.AsMemory()));

            Assert.Equal(expected, nextblock);
        }

                [Fact]
        public void Compress_MatchesArgon2ImplWithZeros()
        {
            var prev = new ulong[128];
            var refblock = new ulong[128];
            refblock[1] = 1;
            refblock[3] = 0x80;
            refblock[4] = 5;
            refblock[5] = 1;
            refblock[6] = 1;

            var nextblock = new ulong[128];

            var expected = new ulong[] {
                0x84fa1423752d03e4UL, 0xd4202fb5e9e8fc76UL, 0xfffa1f74eefd530cUL, 0xff7c0a624b2d77b2UL,
                0xe8a455cbb2592761UL, 0xc49617628179fcb2UL, 0xe10eae8549a5e992UL, 0xb5813d8f4dac273cUL,
                0x067f495a0552af87UL, 0x238c3ed4edd6d758UL, 0x636655eafceb80f7UL, 0x193bea5049153114UL,
                0x4e5b213e432ef97aUL, 0x14c94f0dbc62bc8eUL, 0x09ea35f920abb321UL, 0x0b23e9ece9dda457UL,
                0xec4e388afb66ea39UL, 0x19c17b355dc165b1UL, 0xd0bd510f54632199UL, 0xb40e566edc09c97eUL,
                0x056fdcefacc848d2UL, 0xfd1cc09541f51f4cUL, 0x651ccdb58533ba76UL, 0xa1b455170480831eUL,
                0x535917aaf9d3974aUL, 0x3d0f1bf73415dd8fUL, 0x6fc201d6dbd1712fUL, 0x1dada40b36deec2aUL,
                0xf130f29f1d9766e9UL, 0xb6fefdc5028af788UL, 0xd1c246d907916c1fUL, 0x2244fc5e4feb60e0UL,
                0x4c4f81a45537ab6bUL, 0x440598781ceb86c1UL, 0xab688aa9c4f6f0c2UL, 0x527ea4c76c916baaUL,
                0xd02adede165f21b3UL, 0x8daeee454e611ddbUL, 0xc36f86b4caad1ffaUL, 0x43c6abc4f94980d2UL,
                0x51fa85d61f9c2ef2UL, 0x172251c39600dfe4UL, 0x26ef4b10c5315223UL, 0x0b274be0b3cb37bdUL,
                0x77800a8310362779UL, 0x13411c98fbecc5f2UL, 0x9e86f88b6652fec0UL, 0xd12fee1f085ee874UL,
                0x8a914c5f194d28b2UL, 0xe9a22f089c9d57adUL, 0x951d3bff84abe634UL, 0x71b8260a2a731996UL,
                0xa480b0f5d78daed0UL, 0x10ca5f44f6289690UL, 0x294496482369b61bUL, 0x01ab318471afa3c5UL,
                0x616228e98ae1de52UL, 0x6229b313f3e99a70UL, 0xa25d758741aa72f3UL, 0x79f61170cdf8cafdUL,
                0x5ede754c0ecc0ea5UL, 0xcf7ec86439e3ac88UL, 0xbcac84fb22740928UL, 0xfce402b15f174f4bUL,
                0x189f2f0eb52841efUL, 0x6d65b61521eec372UL, 0xe861420a415aad52UL, 0x3892000405138cd1UL,
                0x0d0af34dd7dc039aUL, 0x8b014f732fdbb82dUL, 0xe5c95577bde46b94UL, 0xaf6618de7b19ef01UL,
                0x624dce2300275a72UL, 0x28664b6858bfb794UL, 0xd339096ebd2d1451UL, 0xb7db8307513e4f2aUL,
                0x968f96ad0166b0adUL, 0xc46a0fa460318d1eUL, 0x2fb04781a81acbbaUL, 0x9d7179cfe284a10fUL,
                0x3954c632392a611eUL, 0x6dfa09128217faefUL, 0x74426d7fee03fbc3UL, 0xc61f567ad86aa8c2UL,
                0x9fa23e4891aad1d6UL, 0x6a58893e968b6a34UL, 0x60b69e60b5da9334UL, 0xe092eca5ed01ec4fUL,
                0xa0f4feb8684bea61UL, 0xc939dc7fe3d71567UL, 0x78643c9bade945f2UL, 0x21c8abe075ff7160UL,
                0xd186a649e5785126UL, 0x9b6f93f964cb318bUL, 0x47492fdca064413fUL, 0x56f4d760f417ba5cUL,
                0x4ed8e92e9edb5fc0UL, 0x4531ddefa01746a7UL, 0xe6f97a66353993a1UL, 0xb58123f2f29d590bUL,
                0xe46280eb5adfdd41UL, 0x8cc4de8d5820a4aeUL, 0x179b347d88b80fd8UL, 0x2f7aa24800d9d845UL,
                0x5f9028aa992ea32fUL, 0x264eab2bf9bf7495UL, 0xd7053aeec01850e5UL, 0xdd7a30e85357db70UL,
                0xbc274baae23b6556UL, 0xdd4003399a66c11fUL, 0x06c21646c45221d5UL, 0x33b7f3e18c8e2444UL,
                0x705c2c573a431472UL, 0x87bfe2e032fdc855UL, 0x21c9934657e023eaUL, 0xe5d4f3356bfa775bUL,
                0x1b3680f9f40d3445UL, 0xcade7f1d6394fc2cUL, 0xd227b3d54ea5ca08UL, 0xc488e6b380c7da2fUL,
                0x920507cb9771205bUL, 0xb847e31a07b63321UL, 0x7a48fa6eac42ada5UL, 0xa51cff427629c751UL,
                0xa69e24c9d96b2caaUL, 0xfa50d0f8d81bfa0cUL, 0x282732bba6f10ad1UL, 0x4de0ea71122db92aUL
            };

            Argon2Core.Compress(
                new Argon2Memory(nextblock.AsMemory()),
                new Argon2Memory(refblock.AsMemory()),
                new Argon2Memory(prev.AsMemory()));

            Assert.Equal(expected, nextblock);
        }
    }
}