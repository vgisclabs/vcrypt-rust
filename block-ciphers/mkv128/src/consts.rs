/// The algorithm supports key sizes of 128, 192, and 256 bits.
pub const MKV128_ROUNDS_128: usize = 6;
pub const MKV128_ROUNDS_192: usize = 7;
pub const MKV128_ROUNDS_256: usize = 8;

// MKV129 Sboxes
pub const MKV128_L0: [u32; 256] = [
    0x0103040D, 0x113344DD, 0x919812A7, 0xE108F9C1, 0xD158399A, 0xB1F8922C, 0x7193EF6B, 0x61A3AFBB,
    0xF138B911, 0x21638486, 0xC168794A, 0x51F36FE0, 0xA1C8D2FC, 0x41C32F30, 0x3153C456, 0x81A85277,
    0x00000000, 0x103040D0, 0xE30EF1DB, 0x929D1EB0, 0xB5F48218, 0xD4572DA3, 0x7799F745, 0x66AAB398,
    0x89B0721F, 0x3848E033, 0xABD6FA8E, 0x4ADE034F, 0xCD7C4916, 0x5CE45BB1, 0x2F71BCC0, 0xFE29855A,
    0x08182068, 0x5FE157A6, 0x3E42F81D, 0xB0FB9621, 0x1C24708C, 0xC26D755D, 0x83AE5A6D, 0xDD4C09C6,
    0xE813DDA4, 0xF631A532, 0x47C9371E, 0x798BCF03, 0x95940293, 0x2B7DACF4, 0xAAD5FE83, 0x64ACBB82,
    0x0F113C4B, 0x48D80B55, 0xD05B3D97, 0x297BA4EE, 0xA3CEDAE6, 0x1A2E68A2, 0xF23DB506, 0xBBE6BA5E,
    0x65AFBF8F, 0xCC7F4D1B, 0xE407EDF8, 0x3D47F40A, 0x57F977CE, 0x7E82D320, 0x86A14E54, 0x9F8A2AE1,
    0x0C14305C, 0x2A7EA8F9, 0xF437AD28, 0x1F217C9B, 0x5BED4792, 0x909B16AA, 0xEE19C58A, 0xC564697E,
    0x365AD875, 0x6DB79FE7, 0x7395E771, 0x88B37612, 0xBCEFA67D, 0xA7C2CAD2, 0x49DB0F58, 0xD25D358D,
    0x0A1E2872, 0x3C44F007, 0x182860B8, 0x85A44243, 0xE00BFDCC, 0x4DD71F6C, 0x998032CF, 0xA4C7C6C5,
    0xB3FE9A36, 0x5EE253AB, 0xDA4515E5, 0xC7626164, 0x7296E37C, 0xFF2A8157, 0x6BBD87C9, 0x266A98A5,
    0x060A182E, 0x769AF348, 0xCF7A410C, 0xA8D3F699, 0x4ED2137B, 0x59EB4F88, 0x60A0ABB6, 0x17395CF3,
    0xDC4F0DCB, 0x9B863AD5, 0x3256C841, 0xF534A925, 0x23658C9C, 0x84A7464E, 0xED1CC99D, 0xBAE5BE53,
    0x07091C23, 0x67A9B795, 0x2D77B4DA, 0x3B4DEC24, 0xFA25956E, 0x8CBF6626, 0x163A58FE, 0x7090EB66,
    0x54FC7BD9, 0xA2CDDEEB, 0x988336C2, 0xBEE9AE67, 0xEF1AC187, 0xD94019F2, 0xC36E7150, 0x45CF3F04,
    0x0E123846, 0xA9D0F294, 0x62A6A3AC, 0x5AEE439F, 0x27699CA8, 0xBFEAAA6A, 0x345CD06F, 0x9C8F26F6,
    0xFD2C894D, 0xD55429AE, 0x8EB96E3C, 0xE601E5E2, 0x1B2D6CAF, 0x43C5272A, 0x7888CB0E, 0xC06B7D47,
    0x03050C17, 0xB2FD9E3B, 0x87A24A59, 0xC4676D73, 0x9D8C22FB, 0x6EB293F0, 0x4BDD0742, 0xF8239D74,
    0x7A8EC314, 0xE910D9A9, 0x2C74B0D7, 0xAFDAEABA, 0xD65125B9, 0x153F54E9, 0x50F06BED, 0x3355CC4C,
    0x0D173451, 0xFB269163, 0x56FA73C3, 0xEC1FCD90, 0x3F41FC10, 0x759FFF5F, 0xB8E3B649, 0x42C62327,
    0x1E227896, 0x246C90BF, 0xC9705922, 0x939E1ABD, 0x80AB567A, 0x6ABE83C4, 0xD75221B4, 0xADDCE2A0,
    0x040C1034, 0xE504E9F5, 0xB9E0B244, 0x7D87DF37, 0x82AD5E60, 0xA6C1CEDF, 0xCA755535, 0x2E72B8CD,
    0x97920A89, 0x13354CC7, 0x6FB197FD, 0xDB4611E8, 0x44CC3B09, 0x3050C05B, 0xFC2F8D40, 0x58E84B85,
    0x0B1D2C7F, 0x8DBC622B, 0x9A853ED8, 0x46CA3313, 0x749CFB52, 0x2878A0E3, 0xDF4A01DC, 0x53F567FA,
    0xCB765138, 0xB7F28A02, 0xF03BBD1C, 0x6CB49BEA, 0xAED9EEB7, 0xE20DF5D6, 0x355FD462, 0x192B64B5,
    0x050F1439, 0x9497069E, 0x7B8DC719, 0xDE4905D1, 0xC6616569, 0xF33EB10B, 0xACDFE6AD, 0x394BE43E,
    0x4FD11776, 0x8AB57E08, 0x55FF7FD4, 0x2060808B, 0x68B88BDE, 0xBDECA270, 0x123648CA, 0xE702E1EF,
    0x0206081A, 0xD35E3180, 0xA5C4C2C8, 0xF732A13F, 0x69BB8FD3, 0xEB16D1B3, 0x5DE75FBC, 0x8FBA6A31,
    0x22668891, 0x40C02B3D, 0xB6F18E0F, 0x143C50E4, 0x3A4EE829, 0xC8735D2F, 0x9E892EEC, 0x7C84DB3A,
    0x091B2465, 0xCE794501, 0x4CD41B61, 0x63A5A7A1, 0xD8431DFF, 0x3759DC78, 0x256F94B2, 0xEA15D5BE,
    0xA0CBD6F1, 0x7F81D72D, 0x1D277481, 0x52F663F7, 0xF9209979, 0x96910E84, 0xB4F78615, 0x8BB67A05,
];

pub const MKV128_L1: [u32; 256] = [
    0x02070B1E, 0x2277BBD5, 0x098ABC77, 0xE9F1D150, 0x89612A26, 0x496AF7CA, 0xE27C6639, 0xC20CD6F2,
    0xC981619B, 0x42E740A3, 0xA9119AED, 0xA29C2D84, 0x691A4701, 0x82EC9D4F, 0x6297F068, 0x29FA0CBC,
    0x00000000, 0x2070B0CB, 0xEDFFC76C, 0x0F83A155, 0x4176DBB2, 0x837A0D40, 0xEE6E5C7D, 0xCC19E7A8,
    0x39C2544C, 0x70A8A386, 0x7D2C09CD, 0x94DDD89D, 0xB135EE65, 0xB8BF5212, 0x5ECD2217, 0xD7AC0831,
    0x103858F0, 0xBEB64F30, 0x7CBA99C2, 0x4B6DFCD4, 0x3854C443, 0xAF1887CF, 0x2DF41A80, 0x91455EAE,
    0xFBCE82BE, 0xC79450C1, 0x8EFEA70B, 0xF2443EC9, 0x0196900F, 0x56D10E6F, 0x7F2B02D3, 0xC817F194,
    0x1E2D69AA, 0x90D3CEA1, 0x8B662138, 0x52DF1853, 0x6D14513D, 0x3446FE07, 0xCF887CB9, 0x5D5CB906,
    0xCA10FA8A, 0xB332E57B, 0xE3EAF636, 0x7AB384E0, 0xAE8E17C0, 0xFC510F93, 0x27EF3DE6, 0x15A0DEC3,
    0x18247488, 0x54D60571, 0xC39A46FD, 0x3E5DD961, 0xB6AA6348, 0x0B8DB769, 0xF7DCB8FA, 0xA10DB695,
    0x6C82C132, 0xDA28A27A, 0xE6727005, 0x3BC55F52, 0x5349885C, 0x65087D45, 0x92D4C5BF, 0x8F683704,
    0x14364ECC, 0x78B48FFE, 0x3048E83B, 0x21E620C4, 0xEBF6DA4E, 0x9AC8E9C7, 0x19B2E487, 0x63016067,
    0x4D64E1F6, 0xBCB1442E, 0x9F506FF4, 0xA503A0A9, 0xE4757B1B, 0xD5AB032F, 0xD63A983E, 0x4CF271F9,
    0x0C123A44, 0xEC695763, 0xB53BF859, 0x7B2514EF, 0x9CC1F4E5, 0xB2A47574, 0xC00BDDEC, 0x2E658191,
    0x934255B0, 0x1DBCF2BB, 0x649EED4A, 0xC19D4DE3, 0x46E9569F, 0x23E12BDA, 0xF1D5A5D8, 0x5F5BB218,
    0x0E15315A, 0xCE1EECB6, 0x5AC3342B, 0x76A1BEA4, 0xDFB02449, 0x33D9732A, 0x2C628A8F, 0xE07B6D27,
    0xA8870AE2, 0x6F135A23, 0x1BB5EF99, 0x57479E60, 0xF5DBB3E4, 0x995972D6, 0xAD1F8CD1, 0x8AF0B137,
    0x1C2A62B4, 0x79221FF1, 0xC405CBD0, 0xB4AD6856, 0x4EF57AE7, 0x5540957E, 0x688CD70E, 0x13A9C3E1,
    0xD1A51513, 0x817D065E, 0x37D76516, 0xE7E4E00A, 0x3641F519, 0x86E28B73, 0xF04335D7, 0xAB1691F3,
    0x06091D22, 0x4F63EAE8, 0x25E836F8, 0xA30ABD8B, 0x11AEC8FF, 0xDC21BF58, 0x96DAD383, 0xDBBE3275,
    0xF44D23EB, 0xF9C989A0, 0x58C43F35, 0x753025B5, 0x87741B7C, 0x2A6B97AD, 0xA09B269A, 0x6699E654,
    0x1A237F96, 0xDDB72F57, 0xAC891CDE, 0xF3D2AEC6, 0x7EBD92DC, 0xEA604A41, 0x5B55A424, 0x84E5806D,
    0x3C5AD27F, 0x48FC67C5, 0xB929C21D, 0x0D84AA4B, 0x2BFD07A2, 0xD43D9320, 0x85731062, 0x713E3389,
    0x081C2C78, 0xE1EDFD28, 0x5952AF3A, 0xFA5812B1, 0x2FF3119E, 0x670F765B, 0xBF20DF3F, 0x5CCA2909,
    0x05988633, 0x2679ADE9, 0xDE26B446, 0x9D5764EA, 0x88F7BA29, 0x6090FB76, 0xD3A21E0D, 0xB0A37E6A,
    0x163145D2, 0x31DE7834, 0x1FBBF9A5, 0x8CF9AC15, 0xE867415F, 0x50D8134D, 0x954B4892, 0xA6923BB8,
    0xBD27D421, 0x4578CD8E, 0xCB866A85, 0xD82FA964, 0x77372EAB, 0xEFF8CC72, 0x6A8BDC10, 0x324FE325,
    0x0A1B2766, 0x03919B11, 0xF64A28F5, 0x974C438C, 0xA704ABB7, 0xCD8F77A7, 0x73393897, 0x72AFA898,
    0x9EC6FFFB, 0x3FCB496E, 0xAA8001FC, 0x40E04BBD, 0xD033851C, 0x514E8342, 0x247EA6F7, 0xE5E3EB14,
    0x040E163C, 0x8D6F3C1A, 0x61066B79, 0xC5935BDF, 0xD2348E02, 0xFDC79F9C, 0xBAB8590C, 0x35D06E08,
    0x44EE5D81, 0x80EB9651, 0x477FC690, 0x286C9CB3, 0x74A6B5BA, 0xBB2EC903, 0x17A7D5DD, 0xF85F19AF,
    0x123F53EE, 0xB73CF347, 0x98CFE2D9, 0xC602C0CE, 0x9B5E79C8, 0x6E85CA2C, 0x4AFB6CDB, 0xFFC09482,
    0x6B1D4C1F, 0xFE56048D, 0x3A53CF5D, 0xA49530A6, 0xD9B9396B, 0x079F8D2D, 0x4371D0AC, 0x3DCC4270,
];

pub const MKV128_L2: [u32; 256] = [
    0x01010306, 0x11113366, 0x9191981B, 0xE1E10810, 0xD1D158B0, 0xB1B1F8DB, 0x7171930D, 0x6161A36D,
    0xF1F13870, 0x212163C6, 0xC1C168D0, 0x5151F3CD, 0xA1A1C8BB, 0x4141C3AD, 0x313153A6, 0x8181A87B,
    0x00000000, 0x10103060, 0xE3E30E1C, 0x92929D11, 0xB5B5F4C3, 0xD4D457AE, 0x77779919, 0x6666AA7F,
    0x8989B04B, 0x38384890, 0xABABD687, 0x4A4ADE97, 0xCDCD7CF8, 0x5C5CE4E3, 0x2F2F71E2, 0xFEFE2952,
    0x08081830, 0x5F5FE1E9, 0x3E3E4284, 0xB0B0FBDD, 0x1C1C2448, 0xC2C26DDA, 0x8383AE77, 0xDDDD4C98,
    0xE8E81326, 0xF6F63162, 0x4747C9B9, 0x79798B3D, 0x95959403, 0x2B2B7DFA, 0xAAAAD581, 0x6464AC73,
    0x0F0F1122, 0x4848D89B, 0xD0D05BB6, 0x29297BF6, 0xA3A3CEB7, 0x1A1A2E5C, 0xF2F23D7A, 0xBBBBE6E7,
    0x6565AF75, 0xCCCC7FFE, 0xE4E4070E, 0x3D3D478E, 0x5757F9D9, 0x7E7E822F, 0x8686A169, 0x9F9F8A3F,
    0x0C0C1428, 0x2A2A7EFC, 0xF4F4376E, 0x1F1F2142, 0x5B5BEDF1, 0x90909B1D, 0xEEEE1932, 0xC5C564C8,
    0x36365AB4, 0x6D6DB745, 0x73739501, 0x8888B34D, 0xBCBCEFF5, 0xA7A7C2AF, 0x4949DB9D, 0xD2D25DBA,
    0x0A0A1E3C, 0x3C3C4488, 0x18182850, 0x8585A463, 0xE0E00B16, 0x4D4DD785, 0x9999802B, 0xA4A4C7A5,
    0xB3B3FED7, 0x5E5EE2EF, 0xDADA458A, 0xC7C762C4, 0x72729607, 0xFFFF2A54, 0x6B6BBD51, 0x26266AD4,
    0x06060A14, 0x76769A1F, 0xCFCF7AF4, 0xA8A8D38D, 0x4E4ED28F, 0x5959EBFD, 0x6060A06B, 0x17173972,
    0xDCDC4F9E, 0x9B9B8627, 0x323256AC, 0xF5F53468, 0x232365CA, 0x8484A765, 0xEDED1C38, 0xBABAE5E1,
    0x07070912, 0x6767A979, 0x2D2D77EE, 0x3B3B4D9A, 0xFAFA254A, 0x8C8CBF55, 0x16163A74, 0x7070900B,
    0x5454FCD3, 0xA2A2CDB1, 0x9898832D, 0xBEBEE9F9, 0xEFEF1A34, 0xD9D94080, 0xC3C36EDC, 0x4545CFB5,
    0x0E0E1224, 0xA9A9D08B, 0x6262A667, 0x5A5AEEF7, 0x272769D2, 0xBFBFEAFF, 0x34345CB8, 0x9C9C8F35,
    0xFDFD2C58, 0xD5D554A8, 0x8E8EB959, 0xE6E60102, 0x1B1B2D5A, 0x4343C5A1, 0x7878883B, 0xC0C06BD6,
    0x0303050A, 0xB2B2FDD1, 0x8787A26F, 0xC4C467CE, 0x9D9D8C33, 0x6E6EB24F, 0x4B4BDD91, 0xF8F82346,
    0x7A7A8E37, 0xE9E91020, 0x2C2C74E8, 0xAFAFDA9F, 0xD6D651A2, 0x15153F7E, 0x5050F0CB, 0x333355AA,
    0x0D0D172E, 0xFBFB264C, 0x5656FADF, 0xECEC1F3E, 0x3F3F4182, 0x75759F15, 0xB8B8E3ED, 0x4242C6A7,
    0x1E1E2244, 0x24246CD8, 0xC9C970E0, 0x93939E17, 0x8080AB7D, 0x6A6ABE57, 0xD7D752A4, 0xADADDC93,
    0x04040C18, 0xE5E50408, 0xB9B9E0EB, 0x7D7D8725, 0x8282AD71, 0xA6A6C1A9, 0xCACA75EA, 0x2E2E72E4,
    0x9797920F, 0x1313356A, 0x6F6FB149, 0xDBDB468C, 0x4444CCB3, 0x303050A0, 0xFCFC2F5E, 0x5858E8FB,
    0x0B0B1D3A, 0x8D8DBC53, 0x9A9A8521, 0x4646CABF, 0x74749C13, 0x282878F0, 0xDFDF4A94, 0x5353F5C1,
    0xCBCB76EC, 0xB7B7F2CF, 0xF0F03B76, 0x6C6CB443, 0xAEAED999, 0xE2E20D1A, 0x35355FBE, 0x19192B56,
    0x05050F1E, 0x94949705, 0x7B7B8D31, 0xDEDE4992, 0xC6C661C2, 0xF3F33E7C, 0xACACDF95, 0x39394B96,
    0x4F4FD189, 0x8A8AB541, 0x5555FFD5, 0x202060C0, 0x6868B85B, 0xBDBDECF3, 0x1212366C, 0xE7E70204,
    0x0202060C, 0xD3D35EBC, 0xA5A5C4A3, 0xF7F73264, 0x6969BB5D, 0xEBEB162C, 0x5D5DE7E5, 0x8F8FBA5F,
    0x222266CC, 0x4040C0AB, 0xB6B6F1C9, 0x14143C78, 0x3A3A4E9C, 0xC8C873E6, 0x9E9E8939, 0x7C7C8423,
    0x09091B36, 0xCECE79F2, 0x4C4CD483, 0x6363A561, 0xD8D84386, 0x373759B2, 0x25256FDE, 0xEAEA152A,
    0xA0A0CBBD, 0x7F7F8129, 0x1D1D274E, 0x5252F6C7, 0xF9F92040, 0x96969109, 0xB4B4F7C5, 0x8B8BB647,
];

pub const MKV128_L3: [u32; 256] = [
    0x03040D14, 0x3344DD7F, 0x9812A75A, 0x08F9C160, 0x58399ADD, 0xF8922C8C, 0x93EF6B2E, 0xA3AFBB45,
    0x38B9110B, 0x638486C2, 0x68794AB6, 0xF36FE0F8, 0xC8D2FCE7, 0xC32F3093, 0x53C456A9, 0xA8527731,
    0x00000000, 0x3040D06B, 0x0EF1DB48, 0x9D1EB066, 0xF48218DC, 0x572DA399, 0x99F74556, 0xAAB39829,
    0xB0721F91, 0x48E0331D, 0xD6FA8E6F, 0xDE034F0F, 0x7C491646, 0xE45BB11C, 0x71BCC01A, 0x29855AC7,
    0x182068A0, 0xE157A620, 0x42F81D65, 0xFB962198, 0x24708C9B, 0x6D755D8A, 0xAE5A6D19, 0x4C09C62D,
    0x13DDA4D4, 0x31A53267, 0xC9371EEB, 0x8BCF038E, 0x9402930A, 0x7DACF44A, 0xD5FE837B, 0xACBB8201,
    0x113C4BCC, 0xD80B5527, 0x5B3D97C9, 0x7BA4EE62, 0xCEDAE6CF, 0x2E68A2E3, 0x3DB50637, 0xE6BA5E04,
    0xAFBF8F15, 0x7F4D1B52, 0x07EDF824, 0x47F40A59, 0xF977CE80, 0x82D320E2, 0xA14E545D, 0x8A2AE182,
    0x14305CF0, 0x7EA8F95E, 0x37AD284F, 0x217C9BA7, 0xED479270, 0x9B16AA4E, 0x19C58AAC, 0x64697EE6,
    0x5AD875C5, 0xB79FE7B5, 0x95E77106, 0xB3761285, 0xEFA67D68, 0xC2CAD29F, 0xDB0F5833, 0x5D358DE1,
    0x1E287288, 0x44F0074D, 0x2860B8CB, 0xA4424361, 0x0BFDCC74, 0xD71F6C63, 0x8032CFFA, 0xC7C6C5A3,
    0xFE9A36A4, 0xE253AB34, 0x4515E541, 0x626164CE, 0x96E37C12, 0x2A8157D3, 0xBD87C9CD, 0x6A98A5AE,
    0x0A182E78, 0x9AF34842, 0x7A410C6E, 0xD3F69953, 0xD2137B5F, 0xEB4F8858, 0xA0ABB651, 0x395CF307,
    0x4F0DCB39, 0x863AD5D2, 0x56C84195, 0x34A9255B, 0x658C9CEA, 0xA7464E75, 0x1CC99D90, 0xE5BE5310,
    0x091C236C, 0xA9B7953D, 0x77B4DA32, 0x4DEC2421, 0x25956E97, 0xBF6626D5, 0x3A58FE13, 0x90EB663A,
    0xFC7BD9BC, 0xCDDEEBDB, 0x8336C2EE, 0xE9AE6740, 0x1AC187B8, 0x4019F27D, 0x6E71509E, 0xCF3F04C3,
    0x123846D8, 0xD0F29447, 0xA6A3AC79, 0xEE439F64, 0x699CA8BA, 0xEAAA6A54, 0x5CD06FED, 0x8F26F6BE,
    0x2C894DFB, 0x5429AE8D, 0xB96E3CFD, 0x01E5E20C, 0x2D6CAFF7, 0xC5272ABB, 0x88CB0E9A, 0x6B7D47A2,
    0x050C173C, 0xFD9E3BB0, 0xA24A5949, 0x676D73F2, 0x8C22FBAA, 0xB293F089, 0xDD07421B, 0x239D74BF,
    0x8EC314B2, 0x10D9A9C0, 0x74B0D726, 0xDAEABA3F, 0x5125B9B1, 0x3F54E92F, 0xF06BEDEC, 0x55CC4C81,
    0x173451E4, 0x26916383, 0xFA73C394, 0x1FCD9084, 0x41FC1071, 0x9FFF5F7E, 0xE3B64938, 0xC62327AF,
    0x227896B3, 0x6C90BF86, 0x70592216, 0x9E1ABD72, 0xAB567A25, 0xBE83C4D9, 0x5221B4A5, 0xDCE2A017,
    0x0C103450, 0x04E9F530, 0xE0B2442C, 0x87DF37DE, 0xAD5E600D, 0xC1CEDF8B, 0x7555352A, 0x72B8CD0E,
    0x920A8922, 0x354CC757, 0xB197FD9D, 0x4611E855, 0xCC3B09D7, 0x50C05BBD, 0x2F8D40EF, 0xE84B854C,
    0x1D2C7F9C, 0xBC622BC1, 0x853ED8C6, 0xCA3313FF, 0x9CFB526A, 0x78A0E376, 0x4A01DC05, 0xF567FAD0,
    0x7651383E, 0xF28A02F4, 0x3BBD1C1F, 0xB49BEAA1, 0xD9EEB72B, 0x0DF5D65C, 0x5FD462F9, 0x2B64B5DF,
    0x0F143944, 0x97069E1E, 0x8DC719A6, 0x4905D111, 0x616569DA, 0x3EB10B23, 0xDFE6AD03, 0x4BE43E09,
    0xD117764B, 0xB57E08AD, 0xFF7FD4A8, 0x60808BD6, 0xB88BDEF1, 0xECA2707C, 0x3648CA43, 0x02E1EF18,
    0x06081A28, 0x5E3180F5, 0xC4C2C8B7, 0x32A13F73, 0xBB8FD3E5, 0x16D1B3E8, 0xE75FBC08, 0xBA6A31E9,
    0x668891FE, 0xC02B3D87, 0xF18E0FE0, 0x3C50E43B, 0x4EE82935, 0x735D2F02, 0x892EEC96, 0x84DB3ACA,
    0x1B2465B4, 0x7945017A, 0xD41B6177, 0xA5A7A16D, 0x431DFF69, 0x59DC78D1, 0x6F94B292, 0x15D5BEFC,
    0xCBD6F1F3, 0x81D72DF6, 0x2774818F, 0xF663F7C4, 0x209979AB, 0x910E8436, 0xF78615C8, 0xB67A05B9,
];

pub const MKV128_L4: [u32; 256] = [
    0x01000000, 0x11000000, 0x91000000, 0xE1000000, 0xD1000000, 0xB1000000, 0x71000000, 0x61000000,
    0xF1000000, 0x21000000, 0xC1000000, 0x51000000, 0xA1000000, 0x41000000, 0x31000000, 0x81000000,
    0x00000000, 0x10000000, 0xE3000000, 0x92000000, 0xB5000000, 0xD4000000, 0x77000000, 0x66000000,
    0x89000000, 0x38000000, 0xAB000000, 0x4A000000, 0xCD000000, 0x5C000000, 0x2F000000, 0xFE000000,
    0x08000000, 0x5F000000, 0x3E000000, 0xB0000000, 0x1C000000, 0xC2000000, 0x83000000, 0xDD000000,
    0xE8000000, 0xF6000000, 0x47000000, 0x79000000, 0x95000000, 0x2B000000, 0xAA000000, 0x64000000,
    0x0F000000, 0x48000000, 0xD0000000, 0x29000000, 0xA3000000, 0x1A000000, 0xF2000000, 0xBB000000,
    0x65000000, 0xCC000000, 0xE4000000, 0x3D000000, 0x57000000, 0x7E000000, 0x86000000, 0x9F000000,
    0x0C000000, 0x2A000000, 0xF4000000, 0x1F000000, 0x5B000000, 0x90000000, 0xEE000000, 0xC5000000,
    0x36000000, 0x6D000000, 0x73000000, 0x88000000, 0xBC000000, 0xA7000000, 0x49000000, 0xD2000000,
    0x0A000000, 0x3C000000, 0x18000000, 0x85000000, 0xE0000000, 0x4D000000, 0x99000000, 0xA4000000,
    0xB3000000, 0x5E000000, 0xDA000000, 0xC7000000, 0x72000000, 0xFF000000, 0x6B000000, 0x26000000,
    0x06000000, 0x76000000, 0xCF000000, 0xA8000000, 0x4E000000, 0x59000000, 0x60000000, 0x17000000,
    0xDC000000, 0x9B000000, 0x32000000, 0xF5000000, 0x23000000, 0x84000000, 0xED000000, 0xBA000000,
    0x07000000, 0x67000000, 0x2D000000, 0x3B000000, 0xFA000000, 0x8C000000, 0x16000000, 0x70000000,
    0x54000000, 0xA2000000, 0x98000000, 0xBE000000, 0xEF000000, 0xD9000000, 0xC3000000, 0x45000000,
    0x0E000000, 0xA9000000, 0x62000000, 0x5A000000, 0x27000000, 0xBF000000, 0x34000000, 0x9C000000,
    0xFD000000, 0xD5000000, 0x8E000000, 0xE6000000, 0x1B000000, 0x43000000, 0x78000000, 0xC0000000,
    0x03000000, 0xB2000000, 0x87000000, 0xC4000000, 0x9D000000, 0x6E000000, 0x4B000000, 0xF8000000,
    0x7A000000, 0xE9000000, 0x2C000000, 0xAF000000, 0xD6000000, 0x15000000, 0x50000000, 0x33000000,
    0x0D000000, 0xFB000000, 0x56000000, 0xEC000000, 0x3F000000, 0x75000000, 0xB8000000, 0x42000000,
    0x1E000000, 0x24000000, 0xC9000000, 0x93000000, 0x80000000, 0x6A000000, 0xD7000000, 0xAD000000,
    0x04000000, 0xE5000000, 0xB9000000, 0x7D000000, 0x82000000, 0xA6000000, 0xCA000000, 0x2E000000,
    0x97000000, 0x13000000, 0x6F000000, 0xDB000000, 0x44000000, 0x30000000, 0xFC000000, 0x58000000,
    0x0B000000, 0x8D000000, 0x9A000000, 0x46000000, 0x74000000, 0x28000000, 0xDF000000, 0x53000000,
    0xCB000000, 0xB7000000, 0xF0000000, 0x6C000000, 0xAE000000, 0xE2000000, 0x35000000, 0x19000000,
    0x05000000, 0x94000000, 0x7B000000, 0xDE000000, 0xC6000000, 0xF3000000, 0xAC000000, 0x39000000,
    0x4F000000, 0x8A000000, 0x55000000, 0x20000000, 0x68000000, 0xBD000000, 0x12000000, 0xE7000000,
    0x02000000, 0xD3000000, 0xA5000000, 0xF7000000, 0x69000000, 0xEB000000, 0x5D000000, 0x8F000000,
    0x22000000, 0x40000000, 0xB6000000, 0x14000000, 0x3A000000, 0xC8000000, 0x9E000000, 0x7C000000,
    0x09000000, 0xCE000000, 0x4C000000, 0x63000000, 0xD8000000, 0x37000000, 0x25000000, 0xEA000000,
    0xA0000000, 0x7F000000, 0x1D000000, 0x52000000, 0xF9000000, 0x96000000, 0xB4000000, 0x8B000000,
];

pub const MKV128_IL0: [u32; 256] = [
    0x6BB05020, 0x00000000, 0x74DA1DEB, 0x4EB7860B, 0x98FC264B, 0xC921ED8B, 0x51DDCBC0, 0x3A6D9BE0,
    0xD64BA040, 0x1F6A4DCB, 0xEC263BA0, 0xA291BDAB, 0x87966B80, 0xF34C766B, 0x2507D62B, 0xBDFBF060,
    0x7FBB5522, 0x140B0502, 0x1143DB97, 0x2CAF0B59, 0xE89F3AFD, 0xAAC8BF11, 0x425785EC, 0x3DECD0CE,
    0xC43031A4, 0x6EF88EB5, 0xF9DCE16A, 0xD573EA33, 0x8667B448, 0x97246FDF, 0x53145E7B, 0xBB8B6486,
    0x5564CA9D, 0xB4532D12, 0xD48235FB, 0xA1A9F7D8, 0x471F5B79, 0x675053C7, 0x204F08BE, 0x752BC223,
    0xE6B6ACA1, 0x81E6FF66, 0x939D6E82, 0x3234995A, 0xC6F9A41F, 0x127B91E4, 0xF4CD3D45, 0xB3D2663C,
    0x7C831F51, 0xD862361C, 0xD993E9D4, 0x82DEB515, 0x5D3DC827, 0x7AF38BB7, 0x27CE4390, 0x5B4D5CC1,
    0xDFE37D32, 0xA510F685, 0x84AE21F3, 0x067094E6, 0xF82D3EA2, 0x21BED776, 0xFE5DAA44, 0xA3606263,
    0xC08930F9, 0xE47F391A, 0x9F7D6D65, 0xC178EF31, 0x68881A53, 0xF604A8FE, 0x9E8CB2AD, 0x5E058254,
    0xA9F0F562, 0x5FF45D9C, 0xF7F57736, 0x368D9807, 0x377C47CF, 0xA8012AAA, 0x01F1DFC8, 0x6979C59B,
    0x96D5B017, 0x9C452716, 0x832F6ADD, 0xCEA0A6A5, 0x9A35B3F0, 0x416FCF9F, 0xDB5A7C6F, 0x4D8FCC78,
    0x54951555, 0x15FADACA, 0x191AD92D, 0xD7BA7F88, 0x8FCF693A, 0x0CE003E7, 0x587516B2, 0xC240A542,
    0x29E7D5CC, 0x6C311B0E, 0x0D11DC2F, 0x237742CD, 0x1A22935E, 0x1DA3D870, 0x07814B2E, 0x2E669EE2,
    0x3955D193, 0x24F609E3, 0x17334F71, 0x34440DBC, 0x3ED49ABD, 0x33C54692, 0x0A909701, 0x10B2045F,
    0x565C80EE, 0x783A1E0C, 0x1C5207B8, 0x0FD84994, 0xF2BDA9A3, 0xB76B6761, 0x45D6CEC2, 0x138A4E2C,
    0xFD65E037, 0x4A0E8756, 0xEEEFAE1B, 0xE137E78F, 0xB8B32EF5, 0xA4E1294D, 0x5984C97A, 0xAB3960D9,
    0x03384A73, 0xCC69331E, 0xC8D03243, 0xAE71BE4C, 0xB5A2F2DA, 0xD03B34A6, 0x6599C67C, 0x66A18C0F,
    0x1BD34C96, 0xCBE87830, 0x7D72C099, 0xD3037ED5, 0x7E4A8AEA, 0xB69AB8A9, 0xAD49F43F, 0x18EB06E5,
    0xC3B17A8A, 0x28160A04, 0x57AD5F26, 0x6F09517D, 0xDD2AE889, 0x263F9C58, 0xFB1574D1, 0x38A40E5B,
    0xB223B9F4, 0x941C25AC, 0x8A87B7AF, 0xE58EE6D2, 0x4936CD25, 0x1E9B9203, 0xACB82BF7, 0x7192C37E,
    0xBF3265DB, 0xF0743C18, 0x8E3EB6F2, 0xEDD7E468, 0x801720AE, 0x5CCC17EF, 0xDCDB3741, 0x63E9529A,
    0x6DC0C4C6, 0x310CD329, 0x0E29965C, 0xE3FE7234, 0xB11BF387, 0x3F254575, 0x52E581B3, 0xD2F2A11D,
    0xEA56AF46, 0x4427110A, 0x5ABC8309, 0x4C7E13B0, 0xC7087BD7, 0x3B9C4428, 0xFC943FFF, 0x16C290B9,
    0x8B766867, 0xB0EA2C4F, 0x9DB4F8DE, 0xD1CAEB6E, 0x77E25798, 0x2D5ED491, 0xA628BCF6, 0x6120C721,
    0xE96EE535, 0x884E2214, 0x926CB14A, 0xE20FADFC, 0x72AA890D, 0xEBA7708E, 0x990DF983, 0x70631CB6,
    0x90A524F1, 0x7B02547F, 0xE0C63847, 0x02C995BB, 0x09A8DD72, 0x9BC46C38, 0x0B6148C9, 0x79CBC1C4,
    0x95EDFA64, 0x502C1408, 0x4BFF589E, 0x60D118E9, 0x2F97412A, 0x9154FB39, 0xBEC3BA13, 0x2B2E4077,
    0x4F4659C3, 0xDE12A2FA, 0x646819B4, 0x04B9015D, 0xF185E3D0, 0xBA7ABB4E, 0xF53CE28D, 0xDAABA3A7,
    0xBC0A2FA8, 0x3C1D0F06, 0x46EE84B1, 0x43A65A24, 0x35B5D274, 0x8CF72349, 0xB942F13D, 0x0548DE95,
    0x76138850, 0xFAE4AB19, 0x735B56C5, 0x30FD0CE1, 0xCF51796D, 0x89BFFDDC, 0xFFAC758C, 0xCA19A7F8,
    0x2ADF9FBF, 0xA0582810, 0xC5C1EE6C, 0x8D06FC81, 0xAF806184, 0xCD98ECD6, 0x62188D52, 0x48C712ED,
    0x22869D05, 0xEF1E71D3, 0x6A418FE8, 0xE7477369, 0x409E1057, 0x855FFE3B, 0xA7D9633E, 0x085902BA,
];

pub const MKV128_IL1: [u32; 256] = [
    0x60201010, 0x00000000, 0x16EBE0E0, 0x1D0B9090, 0xDD4BB0B0, 0xB68BD0D0, 0x6BC06060, 0x0BE07070,
    0xC0402020, 0x76CBF0F0, 0xCBA05050, 0xD6ABC0C0, 0xAB804040, 0xBD6BA0A0, 0x7D2B8080, 0xA0603030,
    0x66221111, 0x06020101, 0x9297DEDE, 0xEB59B9B9, 0x2CFDEBEB, 0x33119D9D, 0x1FEC7676, 0x79CE6767,
    0xC7A45252, 0xF4B5CFCF, 0xBE6A3535, 0x55338C8C, 0xD8482424, 0x4ADFFAFA, 0x8D7BA8A8, 0xA1864343,
    0x8C9DDBDB, 0x36120909, 0x26FBE8E8, 0x43D86C6C, 0x8B79A9A9, 0x62C7F6F6, 0xE9BE5F5F, 0x65238484,
    0xC8A1C5C5, 0xAA663333, 0xAD824141, 0xEE5A2D2D, 0x211F9A9A, 0x07E47272, 0xCF45B7B7, 0x443C1E1E,
    0xF351BDBD, 0x241C0E0E, 0x57D46A6A, 0x3F159F9F, 0x69278686, 0xF2B7CECE, 0x9B904848, 0x68C1F5F5,
    0x56321919, 0xA485D7D7, 0x3EF3ECEC, 0x01E67373, 0xCDA25151, 0x9A763B3B, 0xCC442222, 0xA563A4A4,
    0x20F9E9E9, 0x2E1A0D0D, 0xAF65A7A7, 0x53318D8D, 0xF553BCBC, 0x29FE7F7F, 0xDCADC3C3, 0xFC542A2A,
    0xA6623131, 0x8F9C4E4E, 0x5A361B1B, 0x09079696, 0x7ACFF2F2, 0xD5AA5555, 0x73C86464, 0x869BD8D8,
    0x39179E9E, 0x3A160B0B, 0x4CDDFBFB, 0xC4A5C7C7, 0x3BF07878, 0x8A9FDADA, 0xB16FA2A2, 0x88783C3C,
    0xFF55BFBF, 0x75CA6565, 0x772D8383, 0xB3884444, 0x4E3A1D1D, 0x02E7E6E6, 0xFDB25959, 0xC6422121,
    0x7FCC6666, 0x120E0707, 0x712F8282, 0x7CCDF3F3, 0xE25E2F2F, 0x90703838, 0x722E1717, 0x0DE27171,
    0x9E93DCDC, 0x0EE3E4E4, 0x9371ADAD, 0xEFBC5E5E, 0xECBDCBCB, 0x9D924949, 0x03019595, 0xE15FBABA,
    0x19EE7777, 0x140C0606, 0xE3B85C5C, 0x97944A4A, 0xCEA3C4C4, 0xA361A5A5, 0x6DC26161, 0x742C1616,
    0x59378E8E, 0xFA562B2B, 0x2D1B9898, 0xBA8FD2D2, 0x34F5EFEF, 0xD74DB3B3, 0x8E7A3D3D, 0x40D9F9F9,
    0x9573ACAC, 0x221E0F0F, 0xC543B4B4, 0xD44C2626, 0x45DA6D6D, 0xC1A65353, 0x847C3E3E, 0x110F9292,
    0x91964B4B, 0x50301818, 0x8099D9D9, 0x54D5FFFF, 0x15EA7575, 0xD0A9C1C1, 0x413F8A8A, 0x04E5E7E7,
    0xB58A4545, 0x0C040202, 0x6A261313, 0x877DABAB, 0xB089D1D1, 0xE8582C2C, 0x58D1FDFD, 0xED5BB8B8,
    0x37F47A7A, 0xDFAC5656, 0xDAAFC2C2, 0x5DD26969, 0x6F258787, 0x05039494, 0x32F7EEEE, 0x827E3F3F,
    0x46DBF8F8, 0x28180C0C, 0x3DF27979, 0xB8683434, 0xD9AE5757, 0x1AEFE2E2, 0xC341B5B5, 0x859A4D4D,
    0x61C66363, 0x7B298181, 0xE45C2E2E, 0x5C341A1A, 0xA287D6D6, 0x9F75AFAF, 0xFEB3CCCC, 0x271D9B9B,
    0xCA462323, 0x1E0A0505, 0x1B099191, 0xFBB05858, 0x52D7FEFE, 0x78281414, 0x2AFFEAEA, 0xE0B9C9C9,
    0xA967A6A6, 0xD14FB2B2, 0x49DE6F6F, 0xB26E3737, 0x83984C4C, 0x9891DDDD, 0x31F67B7B, 0x63218585,
    0x5F358F8F, 0x3C140A0A, 0xDE4A2525, 0x2FFC7E7E, 0x170D9393, 0xB98E4747, 0xAE83D4D4, 0xF1B65B5B,
    0x38F1EDED, 0x817FAAAA, 0xC947B6B6, 0xE6BBC8C8, 0x96723939, 0x48381C1C, 0x70C9F1F1, 0x67C46262,
    0xAC643232, 0x18080404, 0x899E4F4F, 0x10E9E1E1, 0x7E2A1515, 0x4B398989, 0x35139C9C, 0x9977AEAE,
    0x6EC3F4F4, 0x25FA7D7D, 0xF7B45A5A, 0xE75DBBBB, 0x5BD06868, 0xD24E2727, 0xBC8DD3D3, 0xC2A7C6C6,
    0xD3A85454, 0x0A060303, 0xF8B1CDCD, 0x6C241212, 0x9C743A3A, 0xDB49B1B1, 0x473D8B8B, 0x9495DFDF,
    0xF0502828, 0x2B199999, 0x64C5F7F7, 0x08E1E5E5, 0xB76DA3A3, 0x4FDC6E6E, 0xBF8C4646, 0x23F87C7C,
    0xEABFCACA, 0x30100808, 0xB46C3636, 0xA881D5D5, 0xA7844242, 0x51D66B6B, 0xF6522929, 0x1CEDE3E3,
    0x0F059797, 0x5ED3FCFC, 0x13E87474, 0xBB69A1A1, 0xF957BEBE, 0x4D3B8888, 0x423E1F1F, 0xE5BA5D5D,
];

pub const MKV128_IL2: [u32; 256] = [
    0xABD07030, 0x00000000, 0x58CCF60B, 0x74AA8D9B, 0x09216DFB, 0x8E97665B, 0x87B60BA0, 0x2C667B90,
    0x7D8BE060, 0xF31C863B, 0x51ED9BF0, 0x2547166B, 0xFA3DEBC0, 0xA2F11DCB, 0xDF7AFDAB, 0xD65B9050,
    0xB3DD7733, 0x180D0703, 0x1ED14C49, 0xD14452E0, 0xB0B3C716, 0xCCFBAE8C, 0x7C48699A, 0xCF951EA9,
    0x61F795F6, 0xAD0C3B7A, 0xAE628B5F, 0x7F26D9BF, 0x1DBFFC6C, 0x036EB025, 0x629925D3, 0xD22AE2C5,
    0x66E85746, 0xD8653F1B, 0x98A4CE13, 0x27EA2FB4, 0x7A9422D0, 0xA3329431, 0xD9A6B6E1, 0xBF4EE1A7,
    0x5D7E0D64, 0xFE4C9955, 0xE230ECC3, 0xC5DAC377, 0x84D8BB85, 0x1C7C7596, 0x410278F2, 0x3B965A22,
    0xB1704EEC, 0x90462A12, 0x77C43DBE, 0xFCE1A08A, 0x8F54EFA1, 0xB5013C79, 0x3A55D3D8, 0x8B259D34,
    0x73B54F2B, 0xC6B47352, 0xF890D21F, 0x04717295, 0x49E09CF3, 0x3E24A14D, 0x4D91EE66, 0xC2C501C7,
    0x80A9C910, 0xB8512317, 0xEAD208C2, 0x672BDEBC, 0xA97D49EF, 0xA42D5681, 0x0D501F6E, 0x8DF9D67E,
    0xCE569753, 0x6A7BC1D2, 0x43AF412D, 0x24849F91, 0xC306883D, 0x29D480FF, 0xE78217AC, 0x4EFF5E43,
    0xE4ECA789, 0xE87F311D, 0x1B63B726, 0x6D640362, 0xEC0E4388, 0x7EE55045, 0x92EB13CD, 0x7607B444,
    0x816A40EA, 0xFF8F10AF, 0xF76DF4AE, 0x9A09F7CC, 0x13815327, 0x08E2E401, 0x8988A4EB, 0x6586E763,
    0xD79819AA, 0x48231509, 0xEF60F3AD, 0xDB0B8F3E, 0xF5C0CD71, 0x1633A848, 0xE3F36539, 0x346B7C93,
    0x2ECB424F, 0x38F8EA07, 0x1AA03EDC, 0xC1ABB1E2, 0xCD382776, 0x2258D4DB, 0x0C939694, 0xF9535BE5,
    0x64456E99, 0x502E120A, 0xF1B1BFE4, 0x0A4FDDDE, 0x45730A67, 0xDAC806C4, 0x9FBB0CA3, 0xFBFE623A,
    0x4F3CD7B9, 0x95F4D17D, 0xB4C2B583, 0xBE8D685D, 0xD087DB1A, 0x213664FE, 0x6E0AB347, 0x2B79B920,
    0x02AD39DF, 0x884B2D11, 0x691571F7, 0x2DA5F26A, 0x3FE728B7, 0x79FA92F5, 0x461DBA42, 0x44B0839D,
    0x1242DADD, 0x6BB84828, 0x56F25940, 0x7B57AB2A, 0x545F609F, 0x3D4A1168, 0x2F08CBB5, 0x10EFE302,
    0x8204F0CF, 0x301A0E06, 0x83C77935, 0x4A8E2CD6, 0x969A6158, 0xDDD7C474, 0x4B4DA52C, 0xC94955E3,
    0xDC144D8E, 0x01C389FA, 0x155D186D, 0x5FD334BB, 0x9759E8A2, 0x149E9197, 0xC88ADC19, 0x5E10BD41,
    0x3374BE23, 0xA05C2414, 0xF403448B, 0xB66F8C5C, 0x19CE8EF9, 0x68D6F80D, 0x711876F4, 0x426CC8D7,
    0xAFA102A5, 0xC777FAA8, 0xEDCDCA72, 0x5BA2462E, 0xDEB97451, 0x2ABA30DA, 0x851B327F, 0x9CD5BC86,
    0x559CE965, 0x78391B0F, 0x6CA78A98, 0x9185A3E8, 0x635AAC29, 0xCBE46C3C, 0xA8BEC015, 0xFD222970,
    0xF2DF0FC1, 0x393B63FD, 0x0FFD26B1, 0x9E788559, 0x5A61CFD4, 0x36C6454C, 0xC4194A8D, 0xA743E6A4,
    0x5731D0BA, 0xF072361E, 0x05B2FB6F, 0xBC205182, 0x5CBD849E, 0xB21EFEC9, 0xEEA37A57, 0xB992AAED,
    0xE09DD51C, 0x52832BD5, 0x590F7FF1, 0xE52F2E73, 0x0E3EAF4B, 0x0B8C5424, 0xEB118138, 0xB7AC05A6,
    0xE6419E56, 0x60341C0C, 0x7276C6D1, 0x40C1F108, 0xD3E96B3F, 0x071FC2B0, 0xD4F6A98F, 0x32B737D9,
    0x93289A37, 0x94375887, 0xA19FADEE, 0xE15E5CE6, 0x47DE33B8, 0x35A8F569, 0xA6806F5E, 0x75690461,
    0x31D987FC, 0x28170905, 0x9D16357C, 0x9BCA7E36, 0x2629A64E, 0x112C6AF8, 0x3705CCB6, 0x06DC4B4A,
    0xBDE3D878, 0xACCFB280, 0xBB3F9332, 0x20F5ED04, 0x8AE614CE, 0x17F021B2, 0xAA13F9CA, 0x8C3A5F84,
    0xD5352075, 0xC0683818, 0x8675825A, 0xF6AE7D54, 0xCA27E5C6, 0x6FC93ABD, 0xA5EEDF7B, 0x70DBFF0E,
    0x3C899892, 0x5340A22F, 0x4C52679C, 0xBAFC1AC8, 0x996747E9, 0x1F12C5B3, 0x239B5D21, 0xE9BCB8E7,
];

pub const MKV128_IL3: [u32; 256] = [
    0xB0502010, 0x00000000, 0xDA1DEBE0, 0xB7860B90, 0xFC264BB0, 0x21ED8BD0, 0xDDCBC060, 0x6D9BE070,
    0x4BA04020, 0x6A4DCBF0, 0x263BA050, 0x91BDABC0, 0x966B8040, 0x4C766BA0, 0x07D62B80, 0xFBF06030,
    0xBB552211, 0x0B050201, 0x43DB97DE, 0xAF0B59B9, 0x9F3AFDEB, 0xC8BF119D, 0x5785EC76, 0xECD0CE67,
    0x3031A452, 0xF88EB5CF, 0xDCE16A35, 0x73EA338C, 0x67B44824, 0x246FDFFA, 0x145E7BA8, 0x8B648643,
    0x64CA9DDB, 0x532D1209, 0x8235FBE8, 0xA9F7D86C, 0x1F5B79A9, 0x5053C7F6, 0x4F08BE5F, 0x2BC22384,
    0xB6ACA1C5, 0xE6FF6633, 0x9D6E8241, 0x34995A2D, 0xF9A41F9A, 0x7B91E472, 0xCD3D45B7, 0xD2663C1E,
    0x831F51BD, 0x62361C0E, 0x93E9D46A, 0xDEB5159F, 0x3DC82786, 0xF38BB7CE, 0xCE439048, 0x4D5CC1F5,
    0xE37D3219, 0x10F685D7, 0xAE21F3EC, 0x7094E673, 0x2D3EA251, 0xBED7763B, 0x5DAA4422, 0x606263A4,
    0x8930F9E9, 0x7F391A0D, 0x7D6D65A7, 0x78EF318D, 0x881A53BC, 0x04A8FE7F, 0x8CB2ADC3, 0x0582542A,
    0xF0F56231, 0xF45D9C4E, 0xF577361B, 0x8D980796, 0x7C47CFF2, 0x012AAA55, 0xF1DFC864, 0x79C59BD8,
    0xD5B0179E, 0x4527160B, 0x2F6ADDFB, 0xA0A6A5C7, 0x35B3F078, 0x6FCF9FDA, 0x5A7C6FA2, 0x8FCC783C,
    0x951555BF, 0xFADACA65, 0x1AD92D83, 0xBA7F8844, 0xCF693A1D, 0xE003E7E6, 0x7516B259, 0x40A54221,
    0xE7D5CC66, 0x311B0E07, 0x11DC2F82, 0x7742CDF3, 0x22935E2F, 0xA3D87038, 0x814B2E17, 0x669EE271,
    0x55D193DC, 0xF609E3E4, 0x334F71AD, 0x440DBC5E, 0xD49ABDCB, 0xC5469249, 0x90970195, 0xB2045FBA,
    0x5C80EE77, 0x3A1E0C06, 0x5207B85C, 0xD849944A, 0xBDA9A3C4, 0x6B6761A5, 0xD6CEC261, 0x8A4E2C16,
    0x65E0378E, 0x0E87562B, 0xEFAE1B98, 0x37E78FD2, 0xB32EF5EF, 0xE1294DB3, 0x84C97A3D, 0x3960D9F9,
    0x384A73AC, 0x69331E0F, 0xD03243B4, 0x71BE4C26, 0xA2F2DA6D, 0x3B34A653, 0x99C67C3E, 0xA18C0F92,
    0xD34C964B, 0xE8783018, 0x72C099D9, 0x037ED5FF, 0x4A8AEA75, 0x9AB8A9C1, 0x49F43F8A, 0xEB06E5E7,
    0xB17A8A45, 0x160A0402, 0xAD5F2613, 0x09517DAB, 0x2AE889D1, 0x3F9C582C, 0x1574D1FD, 0xA40E5BB8,
    0x23B9F47A, 0x1C25AC56, 0x87B7AFC2, 0x8EE6D269, 0x36CD2587, 0x9B920394, 0xB82BF7EE, 0x92C37E3F,
    0x3265DBF8, 0x743C180C, 0x3EB6F279, 0xD7E46834, 0x1720AE57, 0xCC17EFE2, 0xDB3741B5, 0xE9529A4D,
    0xC0C4C663, 0x0CD32981, 0x29965C2E, 0xFE72341A, 0x1BF387D6, 0x254575AF, 0xE581B3CC, 0xF2A11D9B,
    0x56AF4623, 0x27110A05, 0xBC830991, 0x7E13B058, 0x087BD7FE, 0x9C442814, 0x943FFFEA, 0xC290B9C9,
    0x766867A6, 0xEA2C4FB2, 0xB4F8DE6F, 0xCAEB6E37, 0xE257984C, 0x5ED491DD, 0x28BCF67B, 0x20C72185,
    0x6EE5358F, 0x4E22140A, 0x6CB14A25, 0x0FADFC7E, 0xAA890D93, 0xA7708E47, 0x0DF983D4, 0x631CB65B,
    0xA524F1ED, 0x02547FAA, 0xC63847B6, 0xC995BBC8, 0xA8DD7239, 0xC46C381C, 0x6148C9F1, 0xCBC1C462,
    0xEDFA6432, 0x2C140804, 0xFF589E4F, 0xD118E9E1, 0x97412A15, 0x54FB3989, 0xC3BA139C, 0x2E4077AE,
    0x4659C3F4, 0x12A2FA7D, 0x6819B45A, 0xB9015DBB, 0x85E3D068, 0x7ABB4E27, 0x3CE28DD3, 0xABA3A7C6,
    0x0A2FA854, 0x1D0F0603, 0xEE84B1CD, 0xA65A2412, 0xB5D2743A, 0xF72349B1, 0x42F13D8B, 0x48DE95DF,
    0x13885028, 0xE4AB1999, 0x5B56C5F7, 0xFD0CE1E5, 0x51796DA3, 0xBFFDDC6E, 0xAC758C46, 0x19A7F87C,
    0xDF9FBFCA, 0x58281008, 0xC1EE6C36, 0x06FC81D5, 0x80618442, 0x98ECD66B, 0x188D5229, 0xC712EDE3,
    0x869D0597, 0x1E71D3FC, 0x418FE874, 0x477369A1, 0x9E1057BE, 0x5FFE3B88, 0xD9633E1F, 0x5902BA5D,
];

pub const MKV128_IL4: [u32; 256] = [
    0x10000000, 0x00000000, 0xE0000000, 0x90000000, 0xB0000000, 0xD0000000, 0x60000000, 0x70000000,
    0x20000000, 0xF0000000, 0x50000000, 0xC0000000, 0x40000000, 0xA0000000, 0x80000000, 0x30000000,
    0x11000000, 0x01000000, 0xDE000000, 0xB9000000, 0xEB000000, 0x9D000000, 0x76000000, 0x67000000,
    0x52000000, 0xCF000000, 0x35000000, 0x8C000000, 0x24000000, 0xFA000000, 0xA8000000, 0x43000000,
    0xDB000000, 0x09000000, 0xE8000000, 0x6C000000, 0xA9000000, 0xF6000000, 0x5F000000, 0x84000000,
    0xC5000000, 0x33000000, 0x41000000, 0x2D000000, 0x9A000000, 0x72000000, 0xB7000000, 0x1E000000,
    0xBD000000, 0x0E000000, 0x6A000000, 0x9F000000, 0x86000000, 0xCE000000, 0x48000000, 0xF5000000,
    0x19000000, 0xD7000000, 0xEC000000, 0x73000000, 0x51000000, 0x3B000000, 0x22000000, 0xA4000000,
    0xE9000000, 0x0D000000, 0xA7000000, 0x8D000000, 0xBC000000, 0x7F000000, 0xC3000000, 0x2A000000,
    0x31000000, 0x4E000000, 0x1B000000, 0x96000000, 0xF2000000, 0x55000000, 0x64000000, 0xD8000000,
    0x9E000000, 0x0B000000, 0xFB000000, 0xC7000000, 0x78000000, 0xDA000000, 0xA2000000, 0x3C000000,
    0xBF000000, 0x65000000, 0x83000000, 0x44000000, 0x1D000000, 0xE6000000, 0x59000000, 0x21000000,
    0x66000000, 0x07000000, 0x82000000, 0xF3000000, 0x2F000000, 0x38000000, 0x17000000, 0x71000000,
    0xDC000000, 0xE4000000, 0xAD000000, 0x5E000000, 0xCB000000, 0x49000000, 0x95000000, 0xBA000000,
    0x77000000, 0x06000000, 0x5C000000, 0x4A000000, 0xC4000000, 0xA5000000, 0x61000000, 0x16000000,
    0x8E000000, 0x2B000000, 0x98000000, 0xD2000000, 0xEF000000, 0xB3000000, 0x3D000000, 0xF9000000,
    0xAC000000, 0x0F000000, 0xB4000000, 0x26000000, 0x6D000000, 0x53000000, 0x3E000000, 0x92000000,
    0x4B000000, 0x18000000, 0xD9000000, 0xFF000000, 0x75000000, 0xC1000000, 0x8A000000, 0xE7000000,
    0x45000000, 0x02000000, 0x13000000, 0xAB000000, 0xD1000000, 0x2C000000, 0xFD000000, 0xB8000000,
    0x7A000000, 0x56000000, 0xC2000000, 0x69000000, 0x87000000, 0x94000000, 0xEE000000, 0x3F000000,
    0xF8000000, 0x0C000000, 0x79000000, 0x34000000, 0x57000000, 0xE2000000, 0xB5000000, 0x4D000000,
    0x63000000, 0x81000000, 0x2E000000, 0x1A000000, 0xD6000000, 0xAF000000, 0xCC000000, 0x9B000000,
    0x23000000, 0x05000000, 0x91000000, 0x58000000, 0xFE000000, 0x14000000, 0xEA000000, 0xC9000000,
    0xA6000000, 0xB2000000, 0x6F000000, 0x37000000, 0x4C000000, 0xDD000000, 0x7B000000, 0x85000000,
    0x8F000000, 0x0A000000, 0x25000000, 0x7E000000, 0x93000000, 0x47000000, 0xD4000000, 0x5B000000,
    0xED000000, 0xAA000000, 0xB6000000, 0xC8000000, 0x39000000, 0x1C000000, 0xF1000000, 0x62000000,
    0x32000000, 0x04000000, 0x4F000000, 0xE1000000, 0x15000000, 0x89000000, 0x9C000000, 0xAE000000,
    0xF4000000, 0x7D000000, 0x5A000000, 0xBB000000, 0x68000000, 0x27000000, 0xD3000000, 0xC6000000,
    0x54000000, 0x03000000, 0xCD000000, 0x12000000, 0x3A000000, 0xB1000000, 0x8B000000, 0xDF000000,
    0x28000000, 0x99000000, 0xF7000000, 0xE5000000, 0xA3000000, 0x6E000000, 0x46000000, 0x7C000000,
    0xCA000000, 0x08000000, 0x36000000, 0xD5000000, 0x42000000, 0x6B000000, 0x29000000, 0xE3000000,
    0x97000000, 0xFC000000, 0x74000000, 0xA1000000, 0xBE000000, 0x88000000, 0x1F000000, 0x5D000000,
];
