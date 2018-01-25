pragma solidity ^0.4.15;

// Based on https://github.com/adriamb/SolRsaVerify/blob/master/SolRsaVerify.sol

contract SolRsaVerify {

    function memcpy(uint dest, uint src, uint len) private {
        // Copy word-length chunks while possible
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }


    uint8[]  SHA256PREFIX = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ];
    
    function join(bytes s, bytes e, bytes m) internal returns (bytes) {
        uint input_len = 0x60+s.length+e.length+m.length;
        
        uint s_len = s.length;
        uint e_len = e.length;
        uint m_len = m.length;
        uint s_ptr;
        uint e_ptr;
        uint m_ptr;
        uint input_ptr;
        
        bytes memory input = new bytes(input_len);
        assembly {
            s_ptr := add(s,0x20)
            e_ptr := add(e,0x20)
            m_ptr := add(m,0x20)
            mstore(add(input,0x20),s_len)
            mstore(add(input,0x40),e_len)
            mstore(add(input,0x60),m_len)
            input_ptr := add(input,0x20)
        }
        memcpy(input_ptr+0x60,s_ptr,s.length);        
        memcpy(input_ptr+0x60+s.length,e_ptr,e.length);        
        memcpy(input_ptr+0x60+s.length+e.length,m_ptr,m.length);

        return input;
    }

    function pkcs1Sha256Verify(bytes32 hash, bytes s, bytes e, bytes m) returns (uint){
        uint i;
        
      	require(m.length >= SHA256PREFIX.length+hash.length+11);

        /// decipher
        bytes memory input = join(s,e,m);
        uint input_len = input.length;

        uint decipherlen = m.length;
        bytes memory decipher=new bytes(decipherlen);
        bool success;
		assembly {
			success := call(sub(gas, 2000), 5, 0, add(input,0x20), input_len, add(decipher,0x20), decipherlen)
			switch success case 0 { invalid }
		}

        /// 0x00 || 0x01 || PS || 0x00 || DigestInfo
        /// PS is padding filled with 0xff
        //  DigestInfo ::= SEQUENCE {
        //     digestAlgorithm AlgorithmIdentifier,
        //     digest OCTET STRING
        //  }
        
        uint paddingLen = decipherlen - 3 - SHA256PREFIX.length - 32;
        
        if (decipher[0] != 0 || decipher[1] != 1) {
            return 1;
        }
        for (i=2;i<2+paddingLen;i++) {
            if (decipher[i] != 0xff) {
                return 2;
            }
        }
        if (decipher[2+paddingLen] != 0) {
            return 3;
        }
        for (i=0;i<SHA256PREFIX.length;i++) {
            if (uint8(decipher[3+paddingLen+i])!=SHA256PREFIX[i]) {
                return 4;
            }
        }
        for (i=0;i<hash.length;i++) {
            if (decipher[3+paddingLen+SHA256PREFIX.length+i]!=hash[i]) {
                return 5;
            }
        }

        return 0;
    }

    function uints2bytes(uint[8] memory v) returns (bytes) {
        bytes memory b = new bytes(8*32);
        uint v_ptr;
        uint b_ptr;
        assembly {
            v_ptr := v
            b_ptr := add(b,0x20)
        }
         memcpy(b_ptr,v_ptr,b.length); 
         return b;
    }
    function uints2bytes(uint[35] memory v) returns (bytes) {
        bytes memory b = new bytes((34*32)+12);
        uint v_ptr;
        uint b_ptr;
        assembly {
            v_ptr := v
            b_ptr := add(b,0x20)
        }
         memcpy(b_ptr,v_ptr,b.length); 
         return b;
    }
    function uints2bytes(uint[4] memory v) returns (bytes) {
        bytes memory b = new bytes(4*32);
        uint v_ptr;
        uint b_ptr;
        assembly {
            v_ptr := v
            b_ptr := add(b,0x20)
        }
         memcpy(b_ptr,v_ptr,b.length); 
         return b;
    }
    function uints2bytes(uint[1] memory v) returns (bytes) {
        bytes memory b = new bytes(32);
        uint v_ptr;
        uint b_ptr;
        assembly {
            v_ptr := v
            b_ptr := add(b,0x20)
        }
        memcpy(b_ptr,v_ptr,b.length); 
        return b;
    }

    function test_certificate() {
        
        uint[16] memory s = [
0x6b42e00be9359b7673a91db812cc077d3e473ebebe6e4ddee6978c5f3cfb3f23,
0xe04d0864fd43a393c7fdba9baabdaceae5ebff400126031397ac8b0065690e0e,
0x3f3410dfbceb7f97781671b19ec44c76310bda98e4b3bba597ae8b657f24e473,
0x9f9f1cb9898a35853cb8e94620dbc3d774be79a939638a58f82ee78d1654c298,
0xada6f55a3513a17f4acefd0f7d6ec1505a760a0afe2f7974538d3654a3ff0dff,
0xb1af4f6e4ab7242275d044f4d46981493aed8ab79dfb3cdc8f6e904f4863410e,
0x4f501eb0576f9b854c7e58dfeb5e22e987f0cfbf2ee083c86b9f89951c160e10,
0xf3e8abba81b17efb72cc3270434a5eb96afa01c0d8b8fc864adb7d0b78a59433,
0x4feea72ce48ecaa308db5aa5efcd5e12b2724b027447d2dd3d0366dcc512fe27,
0xe844f76314659492d051b9eff4dd0ad562dc0504c6888c5fe9f770666ffe36c5,
0xf90bfd31bf5ba1227017062e6b36494e2906dc3e34314c435617c4d250a0d276,
0xbb3c67cc14aa76be5b179a99b61e041e86fe23cb94158ca52280875af303d690,
0x314eef1f0bddfaea592dedca4101188e741d8c377d4940ade7c637907971e2b9,
0xd9bcb704b3369d306c956252245f3596ea1f7c8d7bc65361441db3b84209c661,
0xde965b7b83cd592d960e289f17db9745d7c02f7aac12e6d03ab03fb3e12f6616,
0xba69f0ace1de01946290b1feb8af488f9d7ea1171478878b17448f71e7144cb4
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
        ];
        
        uint[35] memory data = [
0x30820448a003020102020104300d06092a864886f70d01010d0500308197310b,
0x300906035504061302425231133011060355040a0c0a4943502d42726173696c,
0x313d303b060355040b0c34496e7374697475746f204e6163696f6e616c206465,
0x205465636e6f6c6f67696120646120496e666f726d6163616f202d2049544931,
0x34303206035504030c2b4175746f72696461646520436572746966696361646f,
0x7261205261697a2042726173696c65697261207635301e170d31363037323031,
0x33333230345a170d3239303330323132303030345a308190310b300906035504,
0x061302425231133011060355040a0c0a4943502d42726173696c313430320603,
0x55040b0c2b4175746f72696461646520436572746966696361646f7261205261,
0x697a2042726173696c656972612076353136303406035504030c2d4143205365,
0x63726574617269612064612052656365697461204665646572616c20646f2042,
0x726173696c20763430820222300d06092a864886f70d01010105000382020f00,
0x3082020a02820201009d6077aa0fcaf02f602d01e5f508b57154fdcb17db2344,
0x395263aff49eb92bf96c4d2021cfe4523a1854d32e51ef824c163f824a088b04,
0x7baabec3b29f639fc1532e700bae7ea3d6c6db9280f8cad4c8dd61d4ba279fcf,
0xfa00a6ff87e733ecc23dc9a94c9768aedbccde4091cdcf34553345bdfe51bb58,
0x0367d78a70407b0c6ba5989d197d00fa2a02fbea8fab4e803d38a8f525920411,
0x8466098b3801e991d1e135401a3fd3095d1710f64e248a53addee7b044fec428,
0xcc8c183c8d3dea83b5609608489feef6622d272b292637976e67096f7054df2a,
0x4341bc989c0c4c5867b597c6ef4f7c9113747c8540b2dc93e0ab32548396823f,
0x2bda967dd77c897e86cc44eca5f3d5f995e476f7c833c0384dd942895c799fed,
0x7173a8e4e0d0797874ae4bcd2834ed1cb60eaa2817076fc630579567405644dd,
0x668e653391501abe6e3431722f60d0c03b66a4cad0ed0ad5038b1a5dfc01b0c5,
0x8c7a5db4b225fcb766ce1485c77351e2503c444e0090c38e78da9c0eb453e3f3,
0xe5056a0fb2a5987293cbe801a5d08f0dea1ae6d623af2314d653acd5e3413848,
0x949588f373968dcbe622be123e06dff612081f3ce749dcea3d75dd01944d4bd7,
0xf1af19a0a13706e08edcbb5859801bfd1c721a50aaf63305c074d8aaa1eef5c0,
0x390b08a531f3f7d526786cc2a1c11d8023f8a8c1c32a095b526588bf7540e4f7,
0x063cf67a98fb923eed0203010001a381bb3081b8301d0603551d0e041604141a,
0x98e643ca1cdd929e9963455a2ae91f8720cd35300f0603551d130101ff040530,
0x030101ff300e0603551d0f0101ff04040302010630140603551d20040d300b30,
0x090605604c0101083000303f0603551d1f043830363034a032a030862e687474,
0x703a2f2f61637261697a2e69637062726173696c2e676f762e62722f4c435261,
0x637261697a76352e63726c301f0603551d2304183016801469a8be75d9c4ef6c,
0xe71345e4616ee568f8b6405e0000000000000000000000000000000000000000
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha512(datab),sb,eb,mb)==0);

    }

    function test_fips_sha256_256_success() returns(uint) {
        
        uint[8] memory s = [
0xf4e5cf168fe6094c6c5e40be38cc9f56b1346ee89e2c72ee401b5b7759633e86,
0xb32efffc1463f10e808b1cf76805d98248b1fe4988f672997f204b5b747c0d07,
0x4ca68d9e5d74f9802640745e96d650e6e6b3fa782d5b5e74d43cc46cd755af9c,
0x6899a03936fd1b1de68dfda41701ff2de80188432c6a10220d3cc90d22e701e6,
0x785ba874f9361807dd849398917c28a1ee77e5b1b2c086b6a271882fcd4b98df,
0x8885dfddaed6419fab5fd22bc05006122df0915406f311c071bc68c7280aaf68,
0xf2cbe8dc3ace20356fc37e57eaeb9c268be86c70c7e35d35916e76a3b6fb3ed6,
0x6276fa298438a377d66b28602251d13f7646963fe346c5df367b727ea033ba0e
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[8] memory m = [
0xF7A5C3804350E1F03527FEE027095671CC619D89780D24E5E63D231544658D91,
0xC964436EE41569CDAF3FF194D4EA13F02A1EC3B2AB159502680B103B0B02B597,
0xF4701221FF5F57C084424AA2346155EF8E65B3FDBB701673AFB6408297EF1931,
0x5678E139DF46DBE57966E0055B9CA76C7BC1B77F1210070BAA130B2BBAA2B585,
0xF7E1C4341C332D9F0EECC61E2E600A8C9349F8E13E451107AD1146A2218ED1A8,
0xB76A04296779279B0C43F2432A29B38E6A10E226139E1D39870D80E937CAE970,
0xD36B89D659C730BFBA2395C10CEB5213D5C6418C7422327D50BF8D18474A83FF,
0x74DD406875CBE2AD9B62708F9C927CF746296F21D54A720A4B31318B9163A223
        ];
        
        uint[4] memory data = [
            0xf56379c42e3ba856585ca28f7fb768f65d273a5fc546156142857b0afb7c72d2,
            0xd97ecfceec71b4260bdc58c9bb42065f53af69805d9006233ec70a591aff463b,
            0xf23d78200fb8cc14a4eba286afe8924120efad9e3d3f06f7452c725e53728b8f,
            0x86c9fb245fbaf7086ab0092e215213830d1091212efc1ec59ddc3a83707d4ab8
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        return pkcs1Sha256Verify(sha256(datab),sb,eb,mb);

    }
    function test_fips_sha256_success() {
        
        uint[4] memory s = [
            0x5f49d8dc4519d9520d6542eca08cafb2d99cdb97c5a8685df2476b40505a2f9e,
            0x8d63d76516b83481e2d961a7e8dc5f9f46887e394776711b0f85e4303065c06d,
            0x362456bc219fc6eb343ede6733f779f75853533bc9ab876188da8ad98f9ea2f3,
            0x35d2ceec34ef9cb2782bb0f79cad309608ddc222e00ebcff9d14f6e6ed39638b
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0xf56379c42e3ba856585ca28f7fb768f65d273a5fc546156142857b0afb7c72d2,
            0xd97ecfceec71b4260bdc58c9bb42065f53af69805d9006233ec70a591aff463b,
            0xf23d78200fb8cc14a4eba286afe8924120efad9e3d3f06f7452c725e53728b8f,
            0x86c9fb245fbaf7086ab0092e215213830d1091212efc1ec59ddc3a83707d4ab8
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==0);

    }

    function test_fips_sha256_em_00_end_pad_removed() {
        
        uint[4] memory s = [
            0x06317d3df0fa7ae350729ae2096b050dcec8909d36681ccca09a7a527b90767f,
            0x8c2318c49e09483b48df77ddb632d6ca721155165389f7795d3ede7046567864,
            0x9399242aed6d984ca74fc6c2eb4dd4bb2cd7bf2125ec853f2bf757d665b29487,
            0xbc5b63df0d0b03b18608d3d9a7576ea0954aef3d3303f7d8fd7e7f9725c114e2
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0xb8518b80a55b365eb1850e18f88da2941c99543c2f865df3d37d114d9fc764ff,
            0xc5e2ae94f2d4ab6276bfc6bda5b6976a7dcfaa56897982880410dd5542af3ad3,
            0x4c469990cbec828327764842ef488f767c6b0c8cd1e08caec63438f2665517d1,
            0x95a4d4daf64bc2a70bd11d119eec93a060960245d162844c5f11a98cd26003e1
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==3);

    }

    function test_fips_sha256_em_moved_left() {
        
        uint[4] memory s = [
            0xa62e4b688bb3c4c2e11a3a0b1ef81ff4bbaa110c9b830d02bda2d364dadb2345,
            0xa8c5dca58c611515f0c09732ee6a6642d5c5c339460a9d15022f48c36e9bc2fb,
            0x8b2b0ff99005273287b8c3bed87993baf52f0e9d079281bc25a8694ed9692446,
            0x127c26c34f21e610a84f3617247ecfb3b5337fe59d1239dfb7fdac8694dbef0b
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0x399b54f756514628f32ce8f1cf391d77047af55f3d43804923e5e09a188aa27f,
            0x28604f2f3cfa3d7091f3ab5c69d40d650137a597c22d531dbbdeae074f6f534a,
            0x2b297e087cd7d7125e6f8eac97f5a990859d9d3555301c5076b02f9c4d3f84d6,
            0x2b3d090c7cb1ba1841eab668c066990079f206c15d1383eb3ba58ae17bc2dc2c
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==2);

    }

    function test_fips_sha256_e_changed() {
        
        uint[4] memory s = [
            0x0ac6e41252383ee5d07f4fb08a22204f56440a8f3c8568d6e6bae46cfc9d39b6,
            0x5b2eae827164d716e9e465301d08fca7356ef447e0699feabbfac16ed19dc923,
            0x3b457fe64d6fab38aca4464e5cd3eae3f43bab17856cdcc942e2cc848b7bf390,
            0xfc53b3ed2e6f63c5d961bc83475ac200708f6e1d5be30cbe24fe4d3dad754269
        ];
        
        uint[1] memory e = [
            uint(0x3)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0x9be28a4763c6665880c1c2a8a74494622be46de3c20e5b118cf70fee51d33b6d,
            0x0b473e84a4200382004526a33eea59e13b07070e580937207ec7b2cc5fb76856,
            0xfe6210a771150fa0e5da9baee4a6209ed3d4e2b3bfd2e5f6591b0ace3e657ad0,
            0x7c1b47d8520d5159386767f11fdfaf41fa3348fb7dd32d3c25da5d1d78433985
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==1);

    }
    
    function test_fips_sha256_signature_changed() {
        
        uint[4] memory s = [
            0x750e59f29d2dfeedab2a3a09034904715957149126c63e6a2dc7a633a32c4c05,
            0x61d54eeb1479cb65274bac37cac4751f4dffdfb7530171599b61d94862845f6c,
            0xd12a5e0bd6adabc36f06d216a00b1942349710540555106aeb87f5cf3f78df91,
            0x8f36cf63291ef2a7064e31b84075d1c8b551225a25f59c721a3d77046078557f
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0xa6ce108ff3100b953781496c3d081fe32b8cedaf6d14aab2ef2dc37d8f8d2613,
            0xd2f599efd55c51498749c0961681ae4ea7e28bf14a8f044c2d4dd4f9102ddd25,
            0xf86c7795289708eb4df2d526f91b176952eb52fd0c9de2989432d6e08e13022b,
            0x82f95089d20a5704f0452f26cd1f83bc956ee7da99876c1f8da3723af388bead
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==1);

    }    
 
    function test_fips_sha256_message_changed() {
        
        uint[4] memory s = [
            0x8b5a3675f397841c53a9021dad71a1efab91451c71ad7060ce85d75b306d6403,
            0xba23d3370b0695be87485cf6680204c68424bc7e442ef90ac01c4df420ef5742,
            0x94823250a000d56a5d00947800dcb2f4947f5b4eb18fa1dbdc6ab16be4b71311,
            0x02d4dff98ddeac38554473964d29cdc521ee690cde5a8cd16889aa090c32c53e
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0xff23e00f819bae424e41d6b762ea6b88801e651c831c964af31de0c1d6dda4a7,
            0xc8587d804ed12f526819da06650e7412fb627555979ed442f2663341e5fe5752,
            0x7e0ddaf453a124451674976a6a6e0a31f56a79f5b73dfac39af4f3ba4a5e8bb8,
            0x46cb5e333812756482d975ab1910162f96bfd7c58a02f113125189f5ac05291f
        ];
        
        bytes memory sb = uints2bytes(s);
        bytes memory eb = uints2bytes(e);
        bytes memory mb = uints2bytes(m);
        bytes memory datab = uints2bytes(data);
        
        assert(pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==5);

    }  
    
    function alltests() {
        test_fips_sha256_success();
        test_fips_sha256_em_00_end_pad_removed();
        test_fips_sha256_em_moved_left();
        test_fips_sha256_e_changed();
        test_fips_sha256_signature_changed();
        test_fips_sha256_message_changed();
    }
}

