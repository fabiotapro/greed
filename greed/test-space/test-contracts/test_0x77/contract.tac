function __function_selector__() public {
    Begin block 0x0
    prev=[], succ=[0xc, 0x10]
    =================================
    0x0: v0(0x80) = CONST 
    0x2: v2(0x40) = CONST 
    0x4: MSTORE v2(0x40), v0(0x80)
    0x5: v5 = CALLVALUE 
    0x7: v7 = ISZERO v5
    0x8: v8(0x10) = CONST 
    0xb: JUMPI v8(0x10), v7

    Begin block 0xc
    prev=[0x0], succ=[]
    =================================
    0xc: vc(0x0) = CONST 
    0xf: REVERT vc(0x0), vc(0x0)

    Begin block 0x10
    prev=[0x0], succ=[0x1a, 0x3af0]
    =================================
    0x12: v12(0x4) = CONST 
    0x14: v14 = CALLDATASIZE 
    0x15: v15 = LT v14, v12(0x4)
    0x3a71: v3a71(0x3af0) = CONST 
    0x3a72: JUMPI v3a71(0x3af0), v15

    Begin block 0x1a
    prev=[0x10], succ=[0x2b, 0xde]
    =================================
    0x1a: v1a(0x0) = CONST 
    0x1c: v1c = CALLDATALOAD v1a(0x0)
    0x1d: v1d(0xe0) = CONST 
    0x1f: v1f = SHR v1d(0xe0), v1c
    0x21: v21(0x7866c6c1) = CONST 
    0x26: v26 = GT v21(0x7866c6c1), v1f
    0x27: v27(0xde) = CONST 
    0x2a: JUMPI v27(0xde), v26

    Begin block 0x2b
    prev=[0x1a], succ=[0x36, 0x97]
    =================================
    0x2c: v2c(0x995363d3) = CONST 
    0x31: v31 = GT v2c(0x995363d3), v1f
    0x32: v32(0x97) = CONST 
    0x35: JUMPI v32(0x97), v31

    Begin block 0x36
    prev=[0x2b], succ=[0x41, 0x71]
    =================================
    0x37: v37(0xdd62ed3e) = CONST 
    0x3c: v3c = GT v37(0xdd62ed3e), v1f
    0x3d: v3d(0x71) = CONST 
    0x40: JUMPI v3d(0x71), v3c

    Begin block 0x41
    prev=[0x36], succ=[0x4c, 0x3ae4]
    =================================
    0x42: v42(0xdd62ed3e) = CONST 
    0x47: v47 = EQ v42(0xdd62ed3e), v1f
    0x3a73: v3a73(0x3ae4) = CONST 
    0x3a74: JUMPI v3a73(0x3ae4), v47

    Begin block 0x4c
    prev=[0x41], succ=[0x57, 0x3ae7]
    =================================
    0x4d: v4d(0xf2fde38b) = CONST 
    0x52: v52 = EQ v4d(0xf2fde38b), v1f
    0x3a75: v3a75(0x3ae7) = CONST 
    0x3a76: JUMPI v3a75(0x3ae7), v52

    Begin block 0x57
    prev=[0x4c], succ=[0x62, 0x3aea]
    =================================
    0x58: v58(0xfbd9574d) = CONST 
    0x5d: v5d = EQ v58(0xfbd9574d), v1f
    0x3a77: v3a77(0x3aea) = CONST 
    0x3a78: JUMPI v3a77(0x3aea), v5d

    Begin block 0x62
    prev=[0x57], succ=[0x6d, 0x3aed]
    =================================
    0x63: v63(0xfe056342) = CONST 
    0x68: v68 = EQ v63(0xfe056342), v1f
    0x3a79: v3a79(0x3aed) = CONST 
    0x3a7a: JUMPI v3a79(0x3aed), v68

    Begin block 0x6d
    prev=[0x62], succ=[0x1c7a]
    =================================
    0x6d: v6d(0x1c7a) = CONST 
    0x70: JUMP v6d(0x1c7a)

    Begin block 0x1c7a
    prev=[0x6d], succ=[]
    =================================
    0x1c7b: v1c7b(0x0) = CONST 
    0x1c7e: REVERT v1c7b(0x0), v1c7b(0x0)

    Begin block 0x3aed
    prev=[0x62], succ=[]
    =================================
    0x3aee: v3aee(0x80d) = CONST 
    0x3aef: CALLPRIVATE v3aee(0x80d)

    Begin block 0x3aea
    prev=[0x57], succ=[]
    =================================
    0x3aeb: v3aeb(0x7aa) = CONST 
    0x3aec: CALLPRIVATE v3aeb(0x7aa)

    Begin block 0x3ae7
    prev=[0x4c], succ=[]
    =================================
    0x3ae8: v3ae8(0x766) = CONST 
    0x3ae9: CALLPRIVATE v3ae8(0x766)

    Begin block 0x3ae4
    prev=[0x41], succ=[]
    =================================
    0x3ae5: v3ae5(0x6ee) = CONST 
    0x3ae6: CALLPRIVATE v3ae5(0x6ee)

    Begin block 0x71
    prev=[0x36], succ=[0x7d, 0x3adb]
    =================================
    0x73: v73(0x995363d3) = CONST 
    0x78: v78 = EQ v73(0x995363d3), v1f
    0x3a7b: v3a7b(0x3adb) = CONST 
    0x3a7c: JUMPI v3a7b(0x3adb), v78

    Begin block 0x7d
    prev=[0x71], succ=[0x88, 0x3ade]
    =================================
    0x7e: v7e(0x9b3a54d1) = CONST 
    0x83: v83 = EQ v7e(0x9b3a54d1), v1f
    0x3a7d: v3a7d(0x3ade) = CONST 
    0x3a7e: JUMPI v3a7d(0x3ade), v83

    Begin block 0x88
    prev=[0x7d], succ=[0x93, 0x3ae1]
    =================================
    0x89: v89(0xd84d2a47) = CONST 
    0x8e: v8e = EQ v89(0xd84d2a47), v1f
    0x3a7f: v3a7f(0x3ae1) = CONST 
    0x3a80: JUMPI v3a7f(0x3ae1), v8e

    Begin block 0x93
    prev=[0x88], succ=[0x1c9e]
    =================================
    0x93: v93(0x1c9e) = CONST 
    0x96: JUMP v93(0x1c9e)

    Begin block 0x1c9e
    prev=[0x93], succ=[]
    =================================
    0x1c9f: v1c9f(0x0) = CONST 
    0x1ca2: REVERT v1c9f(0x0), v1c9f(0x0)

    Begin block 0x3ae1
    prev=[0x88], succ=[]
    =================================
    0x3ae2: v3ae2(0x6d0) = CONST 
    0x3ae3: CALLPRIVATE v3ae2(0x6d0)

    Begin block 0x3ade
    prev=[0x7d], succ=[]
    =================================
    0x3adf: v3adf(0x68e) = CONST 
    0x3ae0: CALLPRIVATE v3adf(0x68e)

    Begin block 0x3adb
    prev=[0x71], succ=[]
    =================================
    0x3adc: v3adc(0x644) = CONST 
    0x3add: CALLPRIVATE v3adc(0x644)

    Begin block 0x97
    prev=[0x2b], succ=[0xa3, 0x3ac9]
    =================================
    0x99: v99(0x7866c6c1) = CONST 
    0x9e: v9e = EQ v99(0x7866c6c1), v1f
    0x3a81: v3a81(0x3ac9) = CONST 
    0x3a82: JUMPI v3a81(0x3ac9), v9e

    Begin block 0xa3
    prev=[0x97], succ=[0xae, 0x3acc]
    =================================
    0xa4: va4(0x797bf385) = CONST 
    0xa9: va9 = EQ va4(0x797bf385), v1f
    0x3a83: v3a83(0x3acc) = CONST 
    0x3a84: JUMPI v3a83(0x3acc), va9

    Begin block 0xae
    prev=[0xa3], succ=[0xb9, 0x3acf]
    =================================
    0xaf: vaf(0x894ca308) = CONST 
    0xb4: vb4 = EQ vaf(0x894ca308), v1f
    0x3a85: v3a85(0x3acf) = CONST 
    0x3a86: JUMPI v3a85(0x3acf), vb4

    Begin block 0xb9
    prev=[0xae], succ=[0xc4, 0x3ad2]
    =================================
    0xba: vba(0x8da5cb5b) = CONST 
    0xbf: vbf = EQ vba(0x8da5cb5b), v1f
    0x3a87: v3a87(0x3ad2) = CONST 
    0x3a88: JUMPI v3a87(0x3ad2), vbf

    Begin block 0xc4
    prev=[0xb9], succ=[0xcf, 0x3ad5]
    =================================
    0xc5: vc5(0x95d89b41) = CONST 
    0xca: vca = EQ vc5(0x95d89b41), v1f
    0x3a89: v3a89(0x3ad5) = CONST 
    0x3a8a: JUMPI v3a89(0x3ad5), vca

    Begin block 0xcf
    prev=[0xc4], succ=[0xda, 0x3ad8]
    =================================
    0xd0: vd0(0x96c7871b) = CONST 
    0xd5: vd5 = EQ vd0(0x96c7871b), v1f
    0x3a8b: v3a8b(0x3ad8) = CONST 
    0x3a8c: JUMPI v3a8b(0x3ad8), vd5

    Begin block 0xda
    prev=[0xcf], succ=[0x1cc2]
    =================================
    0xda: vda(0x1cc2) = CONST 
    0xdd: JUMP vda(0x1cc2)

    Begin block 0x1cc2
    prev=[0xda], succ=[]
    =================================
    0x1cc3: v1cc3(0x0) = CONST 
    0x1cc6: REVERT v1cc3(0x0), v1cc3(0x0)

    Begin block 0x3ad8
    prev=[0xcf], succ=[]
    =================================
    0x3ad9: v3ad9(0x5fa) = CONST 
    0x3ada: CALLPRIVATE v3ad9(0x5fa)

    Begin block 0x3ad5
    prev=[0xc4], succ=[]
    =================================
    0x3ad6: v3ad6(0x577) = CONST 
    0x3ad7: CALLPRIVATE v3ad6(0x577)

    Begin block 0x3ad2
    prev=[0xb9], succ=[]
    =================================
    0x3ad3: v3ad3(0x52d) = CONST 
    0x3ad4: CALLPRIVATE v3ad3(0x52d)

    Begin block 0x3acf
    prev=[0xae], succ=[]
    =================================
    0x3ad0: v3ad0(0x4e3) = CONST 
    0x3ad1: CALLPRIVATE v3ad0(0x4e3)

    Begin block 0x3acc
    prev=[0xa3], succ=[]
    =================================
    0x3acd: v3acd(0x499) = CONST 
    0x3ace: CALLPRIVATE v3acd(0x499)

    Begin block 0x3ac9
    prev=[0x97], succ=[]
    =================================
    0x3aca: v3aca(0x424) = CONST 
    0x3acb: CALLPRIVATE v3aca(0x424)

    Begin block 0xde
    prev=[0x1a], succ=[0xea, 0x130]
    =================================
    0xe0: ve0(0x2515aacd) = CONST 
    0xe5: ve5 = GT ve0(0x2515aacd), v1f
    0xe6: ve6(0x130) = CONST 
    0xe9: JUMPI ve6(0x130), ve5

    Begin block 0xea
    prev=[0xde], succ=[0xf5, 0x3ab7]
    =================================
    0xeb: veb(0x2515aacd) = CONST 
    0xf0: vf0 = EQ veb(0x2515aacd), v1f
    0x3a8d: v3a8d(0x3ab7) = CONST 
    0x3a8e: JUMPI v3a8d(0x3ab7), vf0

    Begin block 0xf5
    prev=[0xea], succ=[0x100, 0x3aba]
    =================================
    0xf6: vf6(0x313ce567) = CONST 
    0xfb: vfb = EQ vf6(0x313ce567), v1f
    0x3a8f: v3a8f(0x3aba) = CONST 
    0x3a90: JUMPI v3a8f(0x3aba), vfb

    Begin block 0x100
    prev=[0xf5], succ=[0x10b, 0x3abd]
    =================================
    0x101: v101(0x330691ac) = CONST 
    0x106: v106 = EQ v101(0x330691ac), v1f
    0x3a91: v3a91(0x3abd) = CONST 
    0x3a92: JUMPI v3a91(0x3abd), v106

    Begin block 0x10b
    prev=[0x100], succ=[0x116, 0x3ac0]
    =================================
    0x10c: v10c(0x4780eac1) = CONST 
    0x111: v111 = EQ v10c(0x4780eac1), v1f
    0x3a93: v3a93(0x3ac0) = CONST 
    0x3a94: JUMPI v3a93(0x3ac0), v111

    Begin block 0x116
    prev=[0x10b], succ=[0x121, 0x3ac3]
    =================================
    0x117: v117(0x70a08231) = CONST 
    0x11c: v11c = EQ v117(0x70a08231), v1f
    0x3a95: v3a95(0x3ac3) = CONST 
    0x3a96: JUMPI v3a95(0x3ac3), v11c

    Begin block 0x121
    prev=[0x116], succ=[0x12c, 0x3ac6]
    =================================
    0x122: v122(0x736ee3d3) = CONST 
    0x127: v127 = EQ v122(0x736ee3d3), v1f
    0x3a97: v3a97(0x3ac6) = CONST 
    0x3a98: JUMPI v3a97(0x3ac6), v127

    Begin block 0x12c
    prev=[0x121], succ=[0x1ce6]
    =================================
    0x12c: v12c(0x1ce6) = CONST 
    0x12f: JUMP v12c(0x1ce6)

    Begin block 0x1ce6
    prev=[0x12c], succ=[]
    =================================
    0x1ce7: v1ce7(0x0) = CONST 
    0x1cea: REVERT v1ce7(0x0), v1ce7(0x0)

    Begin block 0x3ac6
    prev=[0x121], succ=[]
    =================================
    0x3ac7: v3ac7(0x3da) = CONST 
    0x3ac8: CALLPRIVATE v3ac7(0x3da)

    Begin block 0x3ac3
    prev=[0x116], succ=[]
    =================================
    0x3ac4: v3ac4(0x382) = CONST 
    0x3ac5: CALLPRIVATE v3ac4(0x382)

    Begin block 0x3ac0
    prev=[0x10b], succ=[]
    =================================
    0x3ac1: v3ac1(0x338) = CONST 
    0x3ac2: CALLPRIVATE v3ac1(0x338)

    Begin block 0x3abd
    prev=[0x100], succ=[]
    =================================
    0x3abe: v3abe(0x31a) = CONST 
    0x3abf: CALLPRIVATE v3abe(0x31a)

    Begin block 0x3aba
    prev=[0xf5], succ=[]
    =================================
    0x3abb: v3abb(0x2f6) = CONST 
    0x3abc: CALLPRIVATE v3abb(0x2f6)

    Begin block 0x3ab7
    prev=[0xea], succ=[]
    =================================
    0x3ab8: v3ab8(0x291) = CONST 
    0x3ab9: CALLPRIVATE v3ab8(0x291)

    Begin block 0x130
    prev=[0xde], succ=[0x13c, 0x3aa5]
    =================================
    0x132: v132(0x6fdde03) = CONST 
    0x137: v137 = EQ v132(0x6fdde03), v1f
    0x3a99: v3a99(0x3aa5) = CONST 
    0x3a9a: JUMPI v3a99(0x3aa5), v137

    Begin block 0x13c
    prev=[0x130], succ=[0x147, 0x3aa8]
    =================================
    0x13d: v13d(0xc4925fd) = CONST 
    0x142: v142 = EQ v13d(0xc4925fd), v1f
    0x3a9b: v3a9b(0x3aa8) = CONST 
    0x3a9c: JUMPI v3a9b(0x3aa8), v142

    Begin block 0x147
    prev=[0x13c], succ=[0x152, 0x3aab]
    =================================
    0x148: v148(0x18160ddd) = CONST 
    0x14d: v14d = EQ v148(0x18160ddd), v1f
    0x3a9d: v3a9d(0x3aab) = CONST 
    0x3a9e: JUMPI v3a9d(0x3aab), v14d

    Begin block 0x152
    prev=[0x147], succ=[0x15d, 0x3aae]
    =================================
    0x153: v153(0x1d0806ae) = CONST 
    0x158: v158 = EQ v153(0x1d0806ae), v1f
    0x3a9f: v3a9f(0x3aae) = CONST 
    0x3aa0: JUMPI v3a9f(0x3aae), v158

    Begin block 0x15d
    prev=[0x152], succ=[0x168, 0x3ab1]
    =================================
    0x15e: v15e(0x1f68f20a) = CONST 
    0x163: v163 = EQ v15e(0x1f68f20a), v1f
    0x3aa1: v3aa1(0x3ab1) = CONST 
    0x3aa2: JUMPI v3aa1(0x3ab1), v163

    Begin block 0x168
    prev=[0x15d], succ=[0x173, 0x3ab4]
    =================================
    0x169: v169(0x20f6d07c) = CONST 
    0x16e: v16e = EQ v169(0x20f6d07c), v1f
    0x3aa3: v3aa3(0x3ab4) = CONST 
    0x3aa4: JUMPI v3aa3(0x3ab4), v16e

    Begin block 0x173
    prev=[0x168], succ=[]
    =================================
    0x174: v174(0x0) = CONST 
    0x177: REVERT v174(0x0), v174(0x0)

    Begin block 0x3ab4
    prev=[0x168], succ=[]
    =================================
    0x3ab5: v3ab5(0x273) = CONST 
    0x3ab6: CALLPRIVATE v3ab5(0x273)

    Begin block 0x3ab1
    prev=[0x15d], succ=[]
    =================================
    0x3ab2: v3ab2(0x255) = CONST 
    0x3ab3: CALLPRIVATE v3ab2(0x255)

    Begin block 0x3aae
    prev=[0x152], succ=[]
    =================================
    0x3aaf: v3aaf(0x237) = CONST 
    0x3ab0: CALLPRIVATE v3aaf(0x237)

    Begin block 0x3aab
    prev=[0x147], succ=[]
    =================================
    0x3aac: v3aac(0x219) = CONST 
    0x3aad: CALLPRIVATE v3aac(0x219)

    Begin block 0x3aa8
    prev=[0x13c], succ=[]
    =================================
    0x3aa9: v3aa9(0x1fb) = CONST 
    0x3aaa: CALLPRIVATE v3aa9(0x1fb)

    Begin block 0x3aa5
    prev=[0x130], succ=[]
    =================================
    0x3aa6: v3aa6(0x178) = CONST 
    0x3aa7: CALLPRIVATE v3aa6(0x178)

    Begin block 0x3af0
    prev=[0x10], succ=[]
    =================================
    0x3af1: v3af1(0x1c56) = CONST 
    0x3af2: CALLPRIVATE v3af1(0x1c56)

}

function name()() public {
    Begin block 0x178
    prev=[], succ=[0x180]
    =================================
    0x179: v179(0x180) = CONST 
    0x17c: v17c(0x84f) = CONST 
    0x17f: v17f_0, v17f_1 = CALLPRIVATE v17c(0x84f), v179(0x180)

    Begin block 0x180
    prev=[0x178], succ=[0x1a5]
    =================================
    0x181: v181(0x40) = CONST 
    0x183: v183 = MLOAD v181(0x40)
    0x186: v186(0x20) = CONST 
    0x188: v188 = ADD v186(0x20), v183
    0x18b: v18b = SUB v188, v183
    0x18d: MSTORE v183, v18b
    0x191: v191 = MLOAD v17f_0
    0x193: MSTORE v188, v191
    0x194: v194(0x20) = CONST 
    0x196: v196 = ADD v194(0x20), v188
    0x19a: v19a = MLOAD v17f_0
    0x19c: v19c(0x20) = CONST 
    0x19e: v19e = ADD v19c(0x20), v17f_0
    0x1a3: v1a3(0x0) = CONST 

    Begin block 0x1a5
    prev=[0x180, 0x1ae], succ=[0x1ae, 0x1c0]
    =================================
    0x1a5_0x0: v1a5_0 = PHI v1a3(0x0), v1b9
    0x1a8: v1a8 = LT v1a5_0, v19a
    0x1a9: v1a9 = ISZERO v1a8
    0x1aa: v1aa(0x1c0) = CONST 
    0x1ad: JUMPI v1aa(0x1c0), v1a9

    Begin block 0x1ae
    prev=[0x1a5], succ=[0x1a5]
    =================================
    0x1ae_0x0: v1ae_0 = PHI v1a3(0x0), v1b9
    0x1b0: v1b0 = ADD v19e, v1ae_0
    0x1b1: v1b1 = MLOAD v1b0
    0x1b4: v1b4 = ADD v196, v1ae_0
    0x1b5: MSTORE v1b4, v1b1
    0x1b6: v1b6(0x20) = CONST 
    0x1b9: v1b9 = ADD v1ae_0, v1b6(0x20)
    0x1bc: v1bc(0x1a5) = CONST 
    0x1bf: JUMP v1bc(0x1a5)

    Begin block 0x1c0
    prev=[0x1a5], succ=[0x1d4, 0x1ed]
    =================================
    0x1c9: v1c9 = ADD v19a, v196
    0x1cb: v1cb(0x1f) = CONST 
    0x1cd: v1cd = AND v1cb(0x1f), v19a
    0x1cf: v1cf = ISZERO v1cd
    0x1d0: v1d0(0x1ed) = CONST 
    0x1d3: JUMPI v1d0(0x1ed), v1cf

    Begin block 0x1d4
    prev=[0x1c0], succ=[0x1ed]
    =================================
    0x1d6: v1d6 = SUB v1c9, v1cd
    0x1d8: v1d8 = MLOAD v1d6
    0x1d9: v1d9(0x1) = CONST 
    0x1dc: v1dc(0x20) = CONST 
    0x1de: v1de = SUB v1dc(0x20), v1cd
    0x1df: v1df(0x100) = CONST 
    0x1e2: v1e2 = EXP v1df(0x100), v1de
    0x1e3: v1e3 = SUB v1e2, v1d9(0x1)
    0x1e4: v1e4 = NOT v1e3
    0x1e5: v1e5 = AND v1e4, v1d8
    0x1e7: MSTORE v1d6, v1e5
    0x1e8: v1e8(0x20) = CONST 
    0x1ea: v1ea = ADD v1e8(0x20), v1d6

    Begin block 0x1ed
    prev=[0x1c0, 0x1d4], succ=[]
    =================================
    0x1ed_0x1: v1ed_1 = PHI v1c9, v1ea
    0x1f3: v1f3(0x40) = CONST 
    0x1f5: v1f5 = MLOAD v1f3(0x40)
    0x1f8: v1f8 = SUB v1ed_1, v1f5
    0x1fa: RETURN v1f5, v1f8

}

function fallback()() public {
    Begin block 0x1c56
    prev=[], succ=[]
    =================================
    0x1c57: v1c57(0x0) = CONST 
    0x1c5a: REVERT v1c57(0x0), v1c57(0x0)

}

function burntTokenReserved()() public {
    Begin block 0x1fb
    prev=[], succ=[0x8ed]
    =================================
    0x1fc: v1fc(0x203) = CONST 
    0x1ff: v1ff(0x8ed) = CONST 
    0x202: JUMP v1ff(0x8ed)

    Begin block 0x8ed
    prev=[0x1fb], succ=[0x203]
    =================================
    0x8ee: v8ee(0x13) = CONST 
    0x8f0: v8f0 = SLOAD v8ee(0x13)
    0x8f2: JUMP v1fc(0x203)

    Begin block 0x203
    prev=[0x8ed], succ=[]
    =================================
    0x204: v204(0x40) = CONST 
    0x206: v206 = MLOAD v204(0x40)
    0x20a: MSTORE v206, v8f0
    0x20b: v20b(0x20) = CONST 
    0x20d: v20d = ADD v20b(0x20), v206
    0x211: v211(0x40) = CONST 
    0x213: v213 = MLOAD v211(0x40)
    0x216: v216 = SUB v20d, v213
    0x218: RETURN v213, v216

}

function totalSupply()() public {
    Begin block 0x219
    prev=[], succ=[0x8f3]
    =================================
    0x21a: v21a(0x221) = CONST 
    0x21d: v21d(0x8f3) = CONST 
    0x220: JUMP v21d(0x8f3)

    Begin block 0x8f3
    prev=[0x219], succ=[0x221]
    =================================
    0x8f4: v8f4(0x0) = CONST 
    0x8f6: v8f6(0x1b) = CONST 
    0x8f8: v8f8 = SLOAD v8f6(0x1b)
    0x8fc: JUMP v21a(0x221)

    Begin block 0x221
    prev=[0x8f3], succ=[]
    =================================
    0x222: v222(0x40) = CONST 
    0x224: v224 = MLOAD v222(0x40)
    0x228: MSTORE v224, v8f8
    0x229: v229(0x20) = CONST 
    0x22b: v22b = ADD v229(0x20), v224
    0x22f: v22f(0x40) = CONST 
    0x231: v231 = MLOAD v22f(0x40)
    0x234: v234 = SUB v22b, v231
    0x236: RETURN v231, v234

}

function initialPrice()() public {
    Begin block 0x237
    prev=[], succ=[0x8fd]
    =================================
    0x238: v238(0x23f) = CONST 
    0x23b: v23b(0x8fd) = CONST 
    0x23e: JUMP v23b(0x8fd)

    Begin block 0x8fd
    prev=[0x237], succ=[0x23f]
    =================================
    0x8fe: v8fe(0x18) = CONST 
    0x900: v900 = SLOAD v8fe(0x18)
    0x902: JUMP v238(0x23f)

    Begin block 0x23f
    prev=[0x8fd], succ=[]
    =================================
    0x240: v240(0x40) = CONST 
    0x242: v242 = MLOAD v240(0x40)
    0x246: MSTORE v242, v900
    0x247: v247(0x20) = CONST 
    0x249: v249 = ADD v247(0x20), v242
    0x24d: v24d(0x40) = CONST 
    0x24f: v24f = MLOAD v24d(0x40)
    0x252: v252 = SUB v249, v24f
    0x254: RETURN v24f, v252

}

function baseRate()() public {
    Begin block 0x255
    prev=[], succ=[0x903]
    =================================
    0x256: v256(0x25d) = CONST 
    0x259: v259(0x903) = CONST 
    0x25c: JUMP v259(0x903)

    Begin block 0x903
    prev=[0x255], succ=[0x25d]
    =================================
    0x904: v904(0xb) = CONST 
    0x906: v906 = SLOAD v904(0xb)
    0x908: JUMP v256(0x25d)

    Begin block 0x25d
    prev=[0x903], succ=[]
    =================================
    0x25e: v25e(0x40) = CONST 
    0x260: v260 = MLOAD v25e(0x40)
    0x264: MSTORE v260, v906
    0x265: v265(0x20) = CONST 
    0x267: v267 = ADD v265(0x20), v260
    0x26b: v26b(0x40) = CONST 
    0x26d: v26d = MLOAD v26b(0x40)
    0x270: v270 = SUB v267, v26d
    0x272: RETURN v26d, v270

}

function totalAssetBorrow()() public {
    Begin block 0x273
    prev=[], succ=[0x909]
    =================================
    0x274: v274(0x27b) = CONST 
    0x277: v277(0x909) = CONST 
    0x27a: JUMP v277(0x909)

    Begin block 0x909
    prev=[0x273], succ=[0x27b]
    =================================
    0x90a: v90a(0x15) = CONST 
    0x90c: v90c = SLOAD v90a(0x15)
    0x90e: JUMP v274(0x27b)

    Begin block 0x27b
    prev=[0x909], succ=[]
    =================================
    0x27c: v27c(0x40) = CONST 
    0x27e: v27e = MLOAD v27c(0x40)
    0x282: MSTORE v27e, v90c
    0x283: v283(0x20) = CONST 
    0x285: v285 = ADD v283(0x20), v27e
    0x289: v289(0x40) = CONST 
    0x28b: v28b = MLOAD v289(0x40)
    0x28e: v28e = SUB v285, v28b
    0x290: RETURN v28b, v28e

}

function loanOrderData(bytes32)() public {
    Begin block 0x291
    prev=[], succ=[0x2a3, 0x2a7]
    =================================
    0x292: v292(0x2bd) = CONST 
    0x295: v295(0x4) = CONST 
    0x298: v298 = CALLDATASIZE 
    0x299: v299 = SUB v298, v295(0x4)
    0x29a: v29a(0x20) = CONST 
    0x29d: v29d = LT v299, v29a(0x20)
    0x29e: v29e = ISZERO v29d
    0x29f: v29f(0x2a7) = CONST 
    0x2a2: JUMPI v29f(0x2a7), v29e

    Begin block 0x2a3
    prev=[0x291], succ=[]
    =================================
    0x2a3: v2a3(0x0) = CONST 
    0x2a6: REVERT v2a3(0x0), v2a3(0x0)

    Begin block 0x2a7
    prev=[0x291], succ=[0x90f]
    =================================
    0x2a9: v2a9 = ADD v295(0x4), v299
    0x2ad: v2ad = CALLDATALOAD v295(0x4)
    0x2af: v2af(0x20) = CONST 
    0x2b1: v2b1 = ADD v2af(0x20), v295(0x4)
    0x2b9: v2b9(0x90f) = CONST 
    0x2bc: JUMP v2b9(0x90f)

    Begin block 0x90f
    prev=[0x2a7], succ=[0x2bd]
    =================================
    0x910: v910(0xf) = CONST 
    0x912: v912(0x20) = CONST 
    0x914: MSTORE v912(0x20), v910(0xf)
    0x916: v916(0x0) = CONST 
    0x918: MSTORE v916(0x0), v2ad
    0x919: v919(0x40) = CONST 
    0x91b: v91b(0x0) = CONST 
    0x91d: v91d = SHA3 v91b(0x0), v919(0x40)
    0x91e: v91e(0x0) = CONST 
    0x925: v925(0x0) = CONST 
    0x927: v927 = ADD v925(0x0), v91d
    0x928: v928 = SLOAD v927
    0x92b: v92b(0x1) = CONST 
    0x92d: v92d = ADD v92b(0x1), v91d
    0x92e: v92e = SLOAD v92d
    0x931: v931(0x2) = CONST 
    0x933: v933 = ADD v931(0x2), v91d
    0x934: v934 = SLOAD v933
    0x937: v937(0x3) = CONST 
    0x939: v939 = ADD v937(0x3), v91d
    0x93a: v93a = SLOAD v939
    0x93d: v93d(0x4) = CONST 
    0x93f: v93f = ADD v93d(0x4), v91d
    0x940: v940 = SLOAD v93f
    0x943: v943(0x5) = CONST 
    0x945: v945 = ADD v943(0x5), v91d
    0x946: v946 = SLOAD v945
    0x94a: JUMP v292(0x2bd)

    Begin block 0x2bd
    prev=[0x90f], succ=[]
    =================================
    0x2be: v2be(0x40) = CONST 
    0x2c0: v2c0 = MLOAD v2be(0x40)
    0x2c4: MSTORE v2c0, v928
    0x2c5: v2c5(0x20) = CONST 
    0x2c7: v2c7 = ADD v2c5(0x20), v2c0
    0x2ca: MSTORE v2c7, v92e
    0x2cb: v2cb(0x20) = CONST 
    0x2cd: v2cd = ADD v2cb(0x20), v2c7
    0x2d0: MSTORE v2cd, v934
    0x2d1: v2d1(0x20) = CONST 
    0x2d3: v2d3 = ADD v2d1(0x20), v2cd
    0x2d6: MSTORE v2d3, v93a
    0x2d7: v2d7(0x20) = CONST 
    0x2d9: v2d9 = ADD v2d7(0x20), v2d3
    0x2dc: MSTORE v2d9, v940
    0x2dd: v2dd(0x20) = CONST 
    0x2df: v2df = ADD v2dd(0x20), v2d9
    0x2e2: MSTORE v2df, v946
    0x2e3: v2e3(0x20) = CONST 
    0x2e5: v2e5 = ADD v2e3(0x20), v2df
    0x2ee: v2ee(0x40) = CONST 
    0x2f0: v2f0 = MLOAD v2ee(0x40)
    0x2f3: v2f3 = SUB v2e5, v2f0
    0x2f5: RETURN v2f0, v2f3

}

function decimals()() public {
    Begin block 0x2f6
    prev=[], succ=[0x94b]
    =================================
    0x2f7: v2f7(0x2fe) = CONST 
    0x2fa: v2fa(0x94b) = CONST 
    0x2fd: JUMP v2fa(0x94b)

    Begin block 0x94b
    prev=[0x2f6], succ=[0x2fe]
    =================================
    0x94c: v94c(0x4) = CONST 
    0x94e: v94e(0x0) = CONST 
    0x951: v951 = SLOAD v94c(0x4)
    0x953: v953(0x100) = CONST 
    0x956: v956(0x1) = EXP v953(0x100), v94e(0x0)
    0x958: v958 = DIV v951, v956(0x1)
    0x959: v959(0xff) = CONST 
    0x95b: v95b = AND v959(0xff), v958
    0x95d: JUMP v2f7(0x2fe)

    Begin block 0x2fe
    prev=[0x94b], succ=[]
    =================================
    0x2ff: v2ff(0x40) = CONST 
    0x301: v301 = MLOAD v2ff(0x40)
    0x304: v304(0xff) = CONST 
    0x306: v306 = AND v304(0xff), v95b
    0x307: v307(0xff) = CONST 
    0x309: v309 = AND v307(0xff), v306
    0x30b: MSTORE v301, v309
    0x30c: v30c(0x20) = CONST 
    0x30e: v30e = ADD v30c(0x20), v301
    0x312: v312(0x40) = CONST 
    0x314: v314 = MLOAD v312(0x40)
    0x317: v317 = SUB v30e, v314
    0x319: RETURN v314, v317

}

function rateMultiplier()() public {
    Begin block 0x31a
    prev=[], succ=[0x95e]
    =================================
    0x31b: v31b(0x322) = CONST 
    0x31e: v31e(0x95e) = CONST 
    0x321: JUMP v31e(0x95e)

    Begin block 0x95e
    prev=[0x31a], succ=[0x322]
    =================================
    0x95f: v95f(0xc) = CONST 
    0x961: v961 = SLOAD v95f(0xc)
    0x963: JUMP v31b(0x322)

    Begin block 0x322
    prev=[0x95e], succ=[]
    =================================
    0x323: v323(0x40) = CONST 
    0x325: v325 = MLOAD v323(0x40)
    0x329: MSTORE v325, v961
    0x32a: v32a(0x20) = CONST 
    0x32c: v32c = ADD v32a(0x20), v325
    0x330: v330(0x40) = CONST 
    0x332: v332 = MLOAD v330(0x40)
    0x335: v335 = SUB v32c, v332
    0x337: RETURN v332, v335

}

function wethContract()() public {
    Begin block 0x338
    prev=[], succ=[0x964]
    =================================
    0x339: v339(0x340) = CONST 
    0x33c: v33c(0x964) = CONST 
    0x33f: JUMP v33c(0x964)

    Begin block 0x964
    prev=[0x338], succ=[0x340]
    =================================
    0x965: v965(0x7) = CONST 
    0x967: v967(0x0) = CONST 
    0x96a: v96a = SLOAD v965(0x7)
    0x96c: v96c(0x100) = CONST 
    0x96f: v96f(0x1) = EXP v96c(0x100), v967(0x0)
    0x971: v971 = DIV v96a, v96f(0x1)
    0x972: v972(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x987: v987 = AND v972(0xffffffffffffffffffffffffffffffffffffffff), v971
    0x989: JUMP v339(0x340)

    Begin block 0x340
    prev=[0x964], succ=[]
    =================================
    0x341: v341(0x40) = CONST 
    0x343: v343 = MLOAD v341(0x40)
    0x346: v346(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x35b: v35b = AND v346(0xffffffffffffffffffffffffffffffffffffffff), v987
    0x35c: v35c(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x371: v371 = AND v35c(0xffffffffffffffffffffffffffffffffffffffff), v35b
    0x373: MSTORE v343, v371
    0x374: v374(0x20) = CONST 
    0x376: v376 = ADD v374(0x20), v343
    0x37a: v37a(0x40) = CONST 
    0x37c: v37c = MLOAD v37a(0x40)
    0x37f: v37f = SUB v376, v37c
    0x381: RETURN v37c, v37f

}

function balanceOf(address)() public {
    Begin block 0x382
    prev=[], succ=[0x394, 0x398]
    =================================
    0x383: v383(0x3c4) = CONST 
    0x386: v386(0x4) = CONST 
    0x389: v389 = CALLDATASIZE 
    0x38a: v38a = SUB v389, v386(0x4)
    0x38b: v38b(0x20) = CONST 
    0x38e: v38e = LT v38a, v38b(0x20)
    0x38f: v38f = ISZERO v38e
    0x390: v390(0x398) = CONST 
    0x393: JUMPI v390(0x398), v38f

    Begin block 0x394
    prev=[0x382], succ=[]
    =================================
    0x394: v394(0x0) = CONST 
    0x397: REVERT v394(0x0), v394(0x0)

    Begin block 0x398
    prev=[0x382], succ=[0x98a]
    =================================
    0x39a: v39a = ADD v386(0x4), v38a
    0x39e: v39e = CALLDATALOAD v386(0x4)
    0x39f: v39f(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x3b4: v3b4 = AND v39f(0xffffffffffffffffffffffffffffffffffffffff), v39e
    0x3b6: v3b6(0x20) = CONST 
    0x3b8: v3b8 = ADD v3b6(0x20), v386(0x4)
    0x3c0: v3c0(0x98a) = CONST 
    0x3c3: JUMP v3c0(0x98a)

    Begin block 0x98a
    prev=[0x398], succ=[0x3c4]
    =================================
    0x98b: v98b(0x0) = CONST 
    0x98d: v98d(0x19) = CONST 
    0x98f: v98f(0x0) = CONST 
    0x992: v992(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x9a7: v9a7 = AND v992(0xffffffffffffffffffffffffffffffffffffffff), v3b4
    0x9a8: v9a8(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x9bd: v9bd = AND v9a8(0xffffffffffffffffffffffffffffffffffffffff), v9a7
    0x9bf: MSTORE v98f(0x0), v9bd
    0x9c0: v9c0(0x20) = CONST 
    0x9c2: v9c2(0x20) = ADD v9c0(0x20), v98f(0x0)
    0x9c5: MSTORE v9c2(0x20), v98d(0x19)
    0x9c6: v9c6(0x20) = CONST 
    0x9c8: v9c8(0x40) = ADD v9c6(0x20), v9c2(0x20)
    0x9c9: v9c9(0x0) = CONST 
    0x9cb: v9cb = SHA3 v9c9(0x0), v9c8(0x40)
    0x9cc: v9cc = SLOAD v9cb
    0x9d2: JUMP v383(0x3c4)

    Begin block 0x3c4
    prev=[0x98a], succ=[]
    =================================
    0x3c5: v3c5(0x40) = CONST 
    0x3c7: v3c7 = MLOAD v3c5(0x40)
    0x3cb: MSTORE v3c7, v9cc
    0x3cc: v3cc(0x20) = CONST 
    0x3ce: v3ce = ADD v3cc(0x20), v3c7
    0x3d2: v3d2(0x40) = CONST 
    0x3d4: v3d4 = MLOAD v3d2(0x40)
    0x3d7: v3d7 = SUB v3ce, v3d4
    0x3d9: RETURN v3d4, v3d7

}

function tokenizedRegistry()() public {
    Begin block 0x3da
    prev=[], succ=[0x9d3]
    =================================
    0x3db: v3db(0x3e2) = CONST 
    0x3de: v3de(0x9d3) = CONST 
    0x3e1: JUMP v3de(0x9d3)

    Begin block 0x9d3
    prev=[0x3da], succ=[0x3e2]
    =================================
    0x9d4: v9d4(0xa) = CONST 
    0x9d6: v9d6(0x1) = CONST 
    0x9d9: v9d9 = SLOAD v9d4(0xa)
    0x9db: v9db(0x100) = CONST 
    0x9de: v9de(0x100) = EXP v9db(0x100), v9d6(0x1)
    0x9e0: v9e0 = DIV v9d9, v9de(0x100)
    0x9e1: v9e1(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x9f6: v9f6 = AND v9e1(0xffffffffffffffffffffffffffffffffffffffff), v9e0
    0x9f8: JUMP v3db(0x3e2)

    Begin block 0x3e2
    prev=[0x9d3], succ=[]
    =================================
    0x3e3: v3e3(0x40) = CONST 
    0x3e5: v3e5 = MLOAD v3e3(0x40)
    0x3e8: v3e8(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x3fd: v3fd = AND v3e8(0xffffffffffffffffffffffffffffffffffffffff), v9f6
    0x3fe: v3fe(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x413: v413 = AND v3fe(0xffffffffffffffffffffffffffffffffffffffff), v3fd
    0x415: MSTORE v3e5, v413
    0x416: v416(0x20) = CONST 
    0x418: v418 = ADD v416(0x20), v3e5
    0x41c: v41c(0x40) = CONST 
    0x41e: v41e = MLOAD v41c(0x40)
    0x421: v421 = SUB v418, v41e
    0x423: RETURN v41e, v421

}

function burntTokenReserveList(uint256)() public {
    Begin block 0x424
    prev=[], succ=[0x436, 0x43a]
    =================================
    0x425: v425(0x450) = CONST 
    0x428: v428(0x4) = CONST 
    0x42b: v42b = CALLDATASIZE 
    0x42c: v42c = SUB v42b, v428(0x4)
    0x42d: v42d(0x20) = CONST 
    0x430: v430 = LT v42c, v42d(0x20)
    0x431: v431 = ISZERO v430
    0x432: v432(0x43a) = CONST 
    0x435: JUMPI v432(0x43a), v431

    Begin block 0x436
    prev=[0x424], succ=[]
    =================================
    0x436: v436(0x0) = CONST 
    0x439: REVERT v436(0x0), v436(0x0)

    Begin block 0x43a
    prev=[0x424], succ=[0x9f9]
    =================================
    0x43c: v43c = ADD v428(0x4), v42c
    0x440: v440 = CALLDATALOAD v428(0x4)
    0x442: v442(0x20) = CONST 
    0x444: v444 = ADD v442(0x20), v428(0x4)
    0x44c: v44c(0x9f9) = CONST 
    0x44f: JUMP v44c(0x9f9)

    Begin block 0x9f9
    prev=[0x43a], succ=[0xa05, 0xa06]
    =================================
    0x9fa: v9fa(0x11) = CONST 
    0x9fe: v9fe = SLOAD v9fa(0x11)
    0xa00: va00 = LT v440, v9fe
    0xa01: va01(0xa06) = CONST 
    0xa04: JUMPI va01(0xa06), va00

    Begin block 0xa05
    prev=[0x9f9], succ=[]
    =================================
    0xa05: THROW 

    Begin block 0xa06
    prev=[0x9f9], succ=[0x450]
    =================================
    0xa08: va08(0x0) = CONST 
    0xa0a: MSTORE va08(0x0), v9fa(0x11)
    0xa0b: va0b(0x20) = CONST 
    0xa0d: va0d(0x0) = CONST 
    0xa0f: va0f = SHA3 va0d(0x0), va0b(0x20)
    0xa11: va11(0x2) = CONST 
    0xa13: va13 = MUL va11(0x2), v440
    0xa14: va14 = ADD va13, va0f
    0xa15: va15(0x0) = CONST 
    0xa1c: va1c(0x0) = CONST 
    0xa1e: va1e = ADD va1c(0x0), va14
    0xa1f: va1f(0x0) = CONST 
    0xa22: va22 = SLOAD va1e
    0xa24: va24(0x100) = CONST 
    0xa27: va27(0x1) = EXP va24(0x100), va1f(0x0)
    0xa29: va29 = DIV va22, va27(0x1)
    0xa2a: va2a(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xa3f: va3f = AND va2a(0xffffffffffffffffffffffffffffffffffffffff), va29
    0xa42: va42(0x1) = CONST 
    0xa44: va44 = ADD va42(0x1), va14
    0xa45: va45 = SLOAD va44
    0xa49: JUMP v425(0x450)

    Begin block 0x450
    prev=[0xa06], succ=[]
    =================================
    0x451: v451(0x40) = CONST 
    0x453: v453 = MLOAD v451(0x40)
    0x456: v456(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x46b: v46b = AND v456(0xffffffffffffffffffffffffffffffffffffffff), va3f
    0x46c: v46c(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x481: v481 = AND v46c(0xffffffffffffffffffffffffffffffffffffffff), v46b
    0x483: MSTORE v453, v481
    0x484: v484(0x20) = CONST 
    0x486: v486 = ADD v484(0x20), v453
    0x489: MSTORE v486, va45
    0x48a: v48a(0x20) = CONST 
    0x48c: v48c = ADD v48a(0x20), v486
    0x491: v491(0x40) = CONST 
    0x493: v493 = MLOAD v491(0x40)
    0x496: v496 = SUB v48c, v493
    0x498: RETURN v493, v496

}

function loanTokenAddress()() public {
    Begin block 0x499
    prev=[], succ=[0xa4a]
    =================================
    0x49a: v49a(0x4a1) = CONST 
    0x49d: v49d(0xa4a) = CONST 
    0x4a0: JUMP v49d(0xa4a)

    Begin block 0xa4a
    prev=[0x499], succ=[0x4a1]
    =================================
    0xa4b: va4b(0x8) = CONST 
    0xa4d: va4d(0x0) = CONST 
    0xa50: va50 = SLOAD va4b(0x8)
    0xa52: va52(0x100) = CONST 
    0xa55: va55(0x1) = EXP va52(0x100), va4d(0x0)
    0xa57: va57 = DIV va50, va55(0x1)
    0xa58: va58(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xa6d: va6d = AND va58(0xffffffffffffffffffffffffffffffffffffffff), va57
    0xa6f: JUMP v49a(0x4a1)

    Begin block 0x4a1
    prev=[0xa4a], succ=[]
    =================================
    0x4a2: v4a2(0x40) = CONST 
    0x4a4: v4a4 = MLOAD v4a2(0x40)
    0x4a7: v4a7(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x4bc: v4bc = AND v4a7(0xffffffffffffffffffffffffffffffffffffffff), va6d
    0x4bd: v4bd(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x4d2: v4d2 = AND v4bd(0xffffffffffffffffffffffffffffffffffffffff), v4bc
    0x4d4: MSTORE v4a4, v4d2
    0x4d5: v4d5(0x20) = CONST 
    0x4d7: v4d7 = ADD v4d5(0x20), v4a4
    0x4db: v4db(0x40) = CONST 
    0x4dd: v4dd = MLOAD v4db(0x40)
    0x4e0: v4e0 = SUB v4d7, v4dd
    0x4e2: RETURN v4dd, v4e0

}

function bZxVault()() public {
    Begin block 0x4e3
    prev=[], succ=[0xa70]
    =================================
    0x4e4: v4e4(0x4eb) = CONST 
    0x4e7: v4e7(0xa70) = CONST 
    0x4ea: JUMP v4e7(0xa70)

    Begin block 0xa70
    prev=[0x4e3], succ=[0x4eb]
    =================================
    0xa71: va71(0x5) = CONST 
    0xa73: va73(0x0) = CONST 
    0xa76: va76 = SLOAD va71(0x5)
    0xa78: va78(0x100) = CONST 
    0xa7b: va7b(0x1) = EXP va78(0x100), va73(0x0)
    0xa7d: va7d = DIV va76, va7b(0x1)
    0xa7e: va7e(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xa93: va93 = AND va7e(0xffffffffffffffffffffffffffffffffffffffff), va7d
    0xa95: JUMP v4e4(0x4eb)

    Begin block 0x4eb
    prev=[0xa70], succ=[]
    =================================
    0x4ec: v4ec(0x40) = CONST 
    0x4ee: v4ee = MLOAD v4ec(0x40)
    0x4f1: v4f1(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x506: v506 = AND v4f1(0xffffffffffffffffffffffffffffffffffffffff), va93
    0x507: v507(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x51c: v51c = AND v507(0xffffffffffffffffffffffffffffffffffffffff), v506
    0x51e: MSTORE v4ee, v51c
    0x51f: v51f(0x20) = CONST 
    0x521: v521 = ADD v51f(0x20), v4ee
    0x525: v525(0x40) = CONST 
    0x527: v527 = MLOAD v525(0x40)
    0x52a: v52a = SUB v521, v527
    0x52c: RETURN v527, v52a

}

function owner()() public {
    Begin block 0x52d
    prev=[], succ=[0xa96]
    =================================
    0x52e: v52e(0x535) = CONST 
    0x531: v531(0xa96) = CONST 
    0x534: JUMP v531(0xa96)

    Begin block 0xa96
    prev=[0x52d], succ=[0x535]
    =================================
    0xa97: va97(0x1) = CONST 
    0xa99: va99(0x0) = CONST 
    0xa9c: va9c = SLOAD va97(0x1)
    0xa9e: va9e(0x100) = CONST 
    0xaa1: vaa1(0x1) = EXP va9e(0x100), va99(0x0)
    0xaa3: vaa3 = DIV va9c, vaa1(0x1)
    0xaa4: vaa4(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xab9: vab9 = AND vaa4(0xffffffffffffffffffffffffffffffffffffffff), vaa3
    0xabb: JUMP v52e(0x535)

    Begin block 0x535
    prev=[0xa96], succ=[]
    =================================
    0x536: v536(0x40) = CONST 
    0x538: v538 = MLOAD v536(0x40)
    0x53b: v53b(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x550: v550 = AND v53b(0xffffffffffffffffffffffffffffffffffffffff), vab9
    0x551: v551(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x566: v566 = AND v551(0xffffffffffffffffffffffffffffffffffffffff), v550
    0x568: MSTORE v538, v566
    0x569: v569(0x20) = CONST 
    0x56b: v56b = ADD v569(0x20), v538
    0x56f: v56f(0x40) = CONST 
    0x571: v571 = MLOAD v56f(0x40)
    0x574: v574 = SUB v56b, v571
    0x576: RETURN v571, v574

}

function symbol()() public {
    Begin block 0x577
    prev=[], succ=[0x57f]
    =================================
    0x578: v578(0x57f) = CONST 
    0x57b: v57b(0xabc) = CONST 
    0x57e: v57e_0, v57e_1 = CALLPRIVATE v57b(0xabc), v578(0x57f)

    Begin block 0x57f
    prev=[0x577], succ=[0x5a4]
    =================================
    0x580: v580(0x40) = CONST 
    0x582: v582 = MLOAD v580(0x40)
    0x585: v585(0x20) = CONST 
    0x587: v587 = ADD v585(0x20), v582
    0x58a: v58a = SUB v587, v582
    0x58c: MSTORE v582, v58a
    0x590: v590 = MLOAD v57e_0
    0x592: MSTORE v587, v590
    0x593: v593(0x20) = CONST 
    0x595: v595 = ADD v593(0x20), v587
    0x599: v599 = MLOAD v57e_0
    0x59b: v59b(0x20) = CONST 
    0x59d: v59d = ADD v59b(0x20), v57e_0
    0x5a2: v5a2(0x0) = CONST 

    Begin block 0x5a4
    prev=[0x57f, 0x5ad], succ=[0x5ad, 0x5bf]
    =================================
    0x5a4_0x0: v5a4_0 = PHI v5a2(0x0), v5b8
    0x5a7: v5a7 = LT v5a4_0, v599
    0x5a8: v5a8 = ISZERO v5a7
    0x5a9: v5a9(0x5bf) = CONST 
    0x5ac: JUMPI v5a9(0x5bf), v5a8

    Begin block 0x5ad
    prev=[0x5a4], succ=[0x5a4]
    =================================
    0x5ad_0x0: v5ad_0 = PHI v5a2(0x0), v5b8
    0x5af: v5af = ADD v59d, v5ad_0
    0x5b0: v5b0 = MLOAD v5af
    0x5b3: v5b3 = ADD v595, v5ad_0
    0x5b4: MSTORE v5b3, v5b0
    0x5b5: v5b5(0x20) = CONST 
    0x5b8: v5b8 = ADD v5ad_0, v5b5(0x20)
    0x5bb: v5bb(0x5a4) = CONST 
    0x5be: JUMP v5bb(0x5a4)

    Begin block 0x5bf
    prev=[0x5a4], succ=[0x5d3, 0x5ec]
    =================================
    0x5c8: v5c8 = ADD v599, v595
    0x5ca: v5ca(0x1f) = CONST 
    0x5cc: v5cc = AND v5ca(0x1f), v599
    0x5ce: v5ce = ISZERO v5cc
    0x5cf: v5cf(0x5ec) = CONST 
    0x5d2: JUMPI v5cf(0x5ec), v5ce

    Begin block 0x5d3
    prev=[0x5bf], succ=[0x5ec]
    =================================
    0x5d5: v5d5 = SUB v5c8, v5cc
    0x5d7: v5d7 = MLOAD v5d5
    0x5d8: v5d8(0x1) = CONST 
    0x5db: v5db(0x20) = CONST 
    0x5dd: v5dd = SUB v5db(0x20), v5cc
    0x5de: v5de(0x100) = CONST 
    0x5e1: v5e1 = EXP v5de(0x100), v5dd
    0x5e2: v5e2 = SUB v5e1, v5d8(0x1)
    0x5e3: v5e3 = NOT v5e2
    0x5e4: v5e4 = AND v5e3, v5d7
    0x5e6: MSTORE v5d5, v5e4
    0x5e7: v5e7(0x20) = CONST 
    0x5e9: v5e9 = ADD v5e7(0x20), v5d5

    Begin block 0x5ec
    prev=[0x5bf, 0x5d3], succ=[]
    =================================
    0x5ec_0x1: v5ec_1 = PHI v5c8, v5e9
    0x5f2: v5f2(0x40) = CONST 
    0x5f4: v5f4 = MLOAD v5f2(0x40)
    0x5f7: v5f7 = SUB v5ec_1, v5f4
    0x5f9: RETURN v5f4, v5f7

}

function bZxOracle()() public {
    Begin block 0x5fa
    prev=[], succ=[0xb5a]
    =================================
    0x5fb: v5fb(0x602) = CONST 
    0x5fe: v5fe(0xb5a) = CONST 
    0x601: JUMP v5fe(0xb5a)

    Begin block 0xb5a
    prev=[0x5fa], succ=[0x602]
    =================================
    0xb5b: vb5b(0x6) = CONST 
    0xb5d: vb5d(0x0) = CONST 
    0xb60: vb60 = SLOAD vb5b(0x6)
    0xb62: vb62(0x100) = CONST 
    0xb65: vb65(0x1) = EXP vb62(0x100), vb5d(0x0)
    0xb67: vb67 = DIV vb60, vb65(0x1)
    0xb68: vb68(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xb7d: vb7d = AND vb68(0xffffffffffffffffffffffffffffffffffffffff), vb67
    0xb7f: JUMP v5fb(0x602)

    Begin block 0x602
    prev=[0xb5a], succ=[]
    =================================
    0x603: v603(0x40) = CONST 
    0x605: v605 = MLOAD v603(0x40)
    0x608: v608(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x61d: v61d = AND v608(0xffffffffffffffffffffffffffffffffffffffff), vb7d
    0x61e: v61e(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x633: v633 = AND v61e(0xffffffffffffffffffffffffffffffffffffffff), v61d
    0x635: MSTORE v605, v633
    0x636: v636(0x20) = CONST 
    0x638: v638 = ADD v636(0x20), v605
    0x63c: v63c(0x40) = CONST 
    0x63e: v63e = MLOAD v63c(0x40)
    0x641: v641 = SUB v638, v63e
    0x643: RETURN v63e, v641

}

function bZxContract()() public {
    Begin block 0x644
    prev=[], succ=[0xb80]
    =================================
    0x645: v645(0x64c) = CONST 
    0x648: v648(0xb80) = CONST 
    0x64b: JUMP v648(0xb80)

    Begin block 0xb80
    prev=[0x644], succ=[0x64c]
    =================================
    0xb81: vb81(0x4) = CONST 
    0xb83: vb83(0x1) = CONST 
    0xb86: vb86 = SLOAD vb81(0x4)
    0xb88: vb88(0x100) = CONST 
    0xb8b: vb8b(0x100) = EXP vb88(0x100), vb83(0x1)
    0xb8d: vb8d = DIV vb86, vb8b(0x100)
    0xb8e: vb8e(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xba3: vba3 = AND vb8e(0xffffffffffffffffffffffffffffffffffffffff), vb8d
    0xba5: JUMP v645(0x64c)

    Begin block 0x64c
    prev=[0xb80], succ=[]
    =================================
    0x64d: v64d(0x40) = CONST 
    0x64f: v64f = MLOAD v64d(0x40)
    0x652: v652(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x667: v667 = AND v652(0xffffffffffffffffffffffffffffffffffffffff), vba3
    0x668: v668(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x67d: v67d = AND v668(0xffffffffffffffffffffffffffffffffffffffff), v667
    0x67f: MSTORE v64f, v67d
    0x680: v680(0x20) = CONST 
    0x682: v682 = ADD v680(0x20), v64f
    0x686: v686(0x40) = CONST 
    0x688: v688 = MLOAD v686(0x40)
    0x68b: v68b = SUB v682, v688
    0x68d: RETURN v688, v68b

}

function leverageList(uint256)() public {
    Begin block 0x68e
    prev=[], succ=[0x6a0, 0x6a4]
    =================================
    0x68f: v68f(0x6ba) = CONST 
    0x692: v692(0x4) = CONST 
    0x695: v695 = CALLDATASIZE 
    0x696: v696 = SUB v695, v692(0x4)
    0x697: v697(0x20) = CONST 
    0x69a: v69a = LT v696, v697(0x20)
    0x69b: v69b = ISZERO v69a
    0x69c: v69c(0x6a4) = CONST 
    0x69f: JUMPI v69c(0x6a4), v69b

    Begin block 0x6a0
    prev=[0x68e], succ=[]
    =================================
    0x6a0: v6a0(0x0) = CONST 
    0x6a3: REVERT v6a0(0x0), v6a0(0x0)

    Begin block 0x6a4
    prev=[0x68e], succ=[0xba6]
    =================================
    0x6a6: v6a6 = ADD v692(0x4), v696
    0x6aa: v6aa = CALLDATALOAD v692(0x4)
    0x6ac: v6ac(0x20) = CONST 
    0x6ae: v6ae = ADD v6ac(0x20), v692(0x4)
    0x6b6: v6b6(0xba6) = CONST 
    0x6b9: JUMP v6b6(0xba6)

    Begin block 0xba6
    prev=[0x6a4], succ=[0xbb2, 0xbb3]
    =================================
    0xba7: vba7(0x10) = CONST 
    0xbab: vbab = SLOAD vba7(0x10)
    0xbad: vbad = LT v6aa, vbab
    0xbae: vbae(0xbb3) = CONST 
    0xbb1: JUMPI vbae(0xbb3), vbad

    Begin block 0xbb2
    prev=[0xba6], succ=[]
    =================================
    0xbb2: THROW 

    Begin block 0xbb3
    prev=[0xba6], succ=[0x6ba]
    =================================
    0xbb5: vbb5(0x0) = CONST 
    0xbb7: MSTORE vbb5(0x0), vba7(0x10)
    0xbb8: vbb8(0x20) = CONST 
    0xbba: vbba(0x0) = CONST 
    0xbbc: vbbc = SHA3 vbba(0x0), vbb8(0x20)
    0xbbd: vbbd = ADD vbbc, v6aa
    0xbbe: vbbe(0x0) = CONST 
    0xbc4: vbc4 = SLOAD vbbd
    0xbc6: JUMP v68f(0x6ba)

    Begin block 0x6ba
    prev=[0xbb3], succ=[]
    =================================
    0x6bb: v6bb(0x40) = CONST 
    0x6bd: v6bd = MLOAD v6bb(0x40)
    0x6c1: MSTORE v6bd, vbc4
    0x6c2: v6c2(0x20) = CONST 
    0x6c4: v6c4 = ADD v6c2(0x20), v6bd
    0x6c8: v6c8(0x40) = CONST 
    0x6ca: v6ca = MLOAD v6c8(0x40)
    0x6cd: v6cd = SUB v6c4, v6ca
    0x6cf: RETURN v6ca, v6cd

}

function spreadMultiplier()() public {
    Begin block 0x6d0
    prev=[], succ=[0xbc7]
    =================================
    0x6d1: v6d1(0x6d8) = CONST 
    0x6d4: v6d4(0xbc7) = CONST 
    0x6d7: JUMP v6d4(0xbc7)

    Begin block 0xbc7
    prev=[0x6d0], succ=[0x6d8]
    =================================
    0xbc8: vbc8(0xd) = CONST 
    0xbca: vbca = SLOAD vbc8(0xd)
    0xbcc: JUMP v6d1(0x6d8)

    Begin block 0x6d8
    prev=[0xbc7], succ=[]
    =================================
    0x6d9: v6d9(0x40) = CONST 
    0x6db: v6db = MLOAD v6d9(0x40)
    0x6df: MSTORE v6db, vbca
    0x6e0: v6e0(0x20) = CONST 
    0x6e2: v6e2 = ADD v6e0(0x20), v6db
    0x6e6: v6e6(0x40) = CONST 
    0x6e8: v6e8 = MLOAD v6e6(0x40)
    0x6eb: v6eb = SUB v6e2, v6e8
    0x6ed: RETURN v6e8, v6eb

}

function allowance(address,address)() public {
    Begin block 0x6ee
    prev=[], succ=[0x700, 0x704]
    =================================
    0x6ef: v6ef(0x750) = CONST 
    0x6f2: v6f2(0x4) = CONST 
    0x6f5: v6f5 = CALLDATASIZE 
    0x6f6: v6f6 = SUB v6f5, v6f2(0x4)
    0x6f7: v6f7(0x40) = CONST 
    0x6fa: v6fa = LT v6f6, v6f7(0x40)
    0x6fb: v6fb = ISZERO v6fa
    0x6fc: v6fc(0x704) = CONST 
    0x6ff: JUMPI v6fc(0x704), v6fb

    Begin block 0x700
    prev=[0x6ee], succ=[]
    =================================
    0x700: v700(0x0) = CONST 
    0x703: REVERT v700(0x0), v700(0x0)

    Begin block 0x704
    prev=[0x6ee], succ=[0xbcd]
    =================================
    0x706: v706 = ADD v6f2(0x4), v6f6
    0x70a: v70a = CALLDATALOAD v6f2(0x4)
    0x70b: v70b(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x720: v720 = AND v70b(0xffffffffffffffffffffffffffffffffffffffff), v70a
    0x722: v722(0x20) = CONST 
    0x724: v724 = ADD v722(0x20), v6f2(0x4)
    0x72a: v72a = CALLDATALOAD v724
    0x72b: v72b(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x740: v740 = AND v72b(0xffffffffffffffffffffffffffffffffffffffff), v72a
    0x742: v742(0x20) = CONST 
    0x744: v744 = ADD v742(0x20), v724
    0x74c: v74c(0xbcd) = CONST 
    0x74f: JUMP v74c(0xbcd)

    Begin block 0xbcd
    prev=[0x704], succ=[0x750]
    =================================
    0xbce: vbce(0x0) = CONST 
    0xbd0: vbd0(0x1a) = CONST 
    0xbd2: vbd2(0x0) = CONST 
    0xbd5: vbd5(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xbea: vbea = AND vbd5(0xffffffffffffffffffffffffffffffffffffffff), v720
    0xbeb: vbeb(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xc00: vc00 = AND vbeb(0xffffffffffffffffffffffffffffffffffffffff), vbea
    0xc02: MSTORE vbd2(0x0), vc00
    0xc03: vc03(0x20) = CONST 
    0xc05: vc05(0x20) = ADD vc03(0x20), vbd2(0x0)
    0xc08: MSTORE vc05(0x20), vbd0(0x1a)
    0xc09: vc09(0x20) = CONST 
    0xc0b: vc0b(0x40) = ADD vc09(0x20), vc05(0x20)
    0xc0c: vc0c(0x0) = CONST 
    0xc0e: vc0e = SHA3 vc0c(0x0), vc0b(0x40)
    0xc0f: vc0f(0x0) = CONST 
    0xc12: vc12(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xc27: vc27 = AND vc12(0xffffffffffffffffffffffffffffffffffffffff), v740
    0xc28: vc28(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xc3d: vc3d = AND vc28(0xffffffffffffffffffffffffffffffffffffffff), vc27
    0xc3f: MSTORE vc0f(0x0), vc3d
    0xc40: vc40(0x20) = CONST 
    0xc42: vc42(0x20) = ADD vc40(0x20), vc0f(0x0)
    0xc45: MSTORE vc42(0x20), vc0e
    0xc46: vc46(0x20) = CONST 
    0xc48: vc48(0x40) = ADD vc46(0x20), vc42(0x20)
    0xc49: vc49(0x0) = CONST 
    0xc4b: vc4b = SHA3 vc49(0x0), vc48(0x40)
    0xc4c: vc4c = SLOAD vc4b
    0xc53: JUMP v6ef(0x750)

    Begin block 0x750
    prev=[0xbcd], succ=[]
    =================================
    0x751: v751(0x40) = CONST 
    0x753: v753 = MLOAD v751(0x40)
    0x757: MSTORE v753, vc4c
    0x758: v758(0x20) = CONST 
    0x75a: v75a = ADD v758(0x20), v753
    0x75e: v75e(0x40) = CONST 
    0x760: v760 = MLOAD v75e(0x40)
    0x763: v763 = SUB v75a, v760
    0x765: RETURN v760, v763

}

function transferOwnership(address)() public {
    Begin block 0x766
    prev=[], succ=[0x778, 0x77c]
    =================================
    0x767: v767(0x7a8) = CONST 
    0x76a: v76a(0x4) = CONST 
    0x76d: v76d = CALLDATASIZE 
    0x76e: v76e = SUB v76d, v76a(0x4)
    0x76f: v76f(0x20) = CONST 
    0x772: v772 = LT v76e, v76f(0x20)
    0x773: v773 = ISZERO v772
    0x774: v774(0x77c) = CONST 
    0x777: JUMPI v774(0x77c), v773

    Begin block 0x778
    prev=[0x766], succ=[]
    =================================
    0x778: v778(0x0) = CONST 
    0x77b: REVERT v778(0x0), v778(0x0)

    Begin block 0x77c
    prev=[0x766], succ=[0x7a8]
    =================================
    0x77e: v77e = ADD v76a(0x4), v76e
    0x782: v782 = CALLDATALOAD v76a(0x4)
    0x783: v783(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x798: v798 = AND v783(0xffffffffffffffffffffffffffffffffffffffff), v782
    0x79a: v79a(0x20) = CONST 
    0x79c: v79c = ADD v79a(0x20), v76a(0x4)
    0x7a4: v7a4(0xc54) = CONST 
    0x7a7: CALLPRIVATE v7a4(0xc54), v798, v767(0x7a8)

    Begin block 0x7a8
    prev=[0x77c], succ=[]
    =================================
    0x7a9: STOP 

}

function burntTokenReserveListIndex(address)() public {
    Begin block 0x7aa
    prev=[], succ=[0x7bc, 0x7c0]
    =================================
    0x7ab: v7ab(0x7ec) = CONST 
    0x7ae: v7ae(0x4) = CONST 
    0x7b1: v7b1 = CALLDATASIZE 
    0x7b2: v7b2 = SUB v7b1, v7ae(0x4)
    0x7b3: v7b3(0x20) = CONST 
    0x7b6: v7b6 = LT v7b2, v7b3(0x20)
    0x7b7: v7b7 = ISZERO v7b6
    0x7b8: v7b8(0x7c0) = CONST 
    0x7bb: JUMPI v7b8(0x7c0), v7b7

    Begin block 0x7bc
    prev=[0x7aa], succ=[]
    =================================
    0x7bc: v7bc(0x0) = CONST 
    0x7bf: REVERT v7bc(0x0), v7bc(0x0)

    Begin block 0x7c0
    prev=[0x7aa], succ=[0xcba]
    =================================
    0x7c2: v7c2 = ADD v7ae(0x4), v7b2
    0x7c6: v7c6 = CALLDATALOAD v7ae(0x4)
    0x7c7: v7c7(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0x7dc: v7dc = AND v7c7(0xffffffffffffffffffffffffffffffffffffffff), v7c6
    0x7de: v7de(0x20) = CONST 
    0x7e0: v7e0 = ADD v7de(0x20), v7ae(0x4)
    0x7e8: v7e8(0xcba) = CONST 
    0x7eb: JUMP v7e8(0xcba)

    Begin block 0xcba
    prev=[0x7c0], succ=[0x7ec]
    =================================
    0xcbb: vcbb(0x12) = CONST 
    0xcbd: vcbd(0x20) = CONST 
    0xcbf: MSTORE vcbd(0x20), vcbb(0x12)
    0xcc1: vcc1(0x0) = CONST 
    0xcc3: MSTORE vcc1(0x0), v7dc
    0xcc4: vcc4(0x40) = CONST 
    0xcc6: vcc6(0x0) = CONST 
    0xcc8: vcc8 = SHA3 vcc6(0x0), vcc4(0x40)
    0xcc9: vcc9(0x0) = CONST 
    0xcd0: vcd0(0x0) = CONST 
    0xcd2: vcd2 = ADD vcd0(0x0), vcc8
    0xcd3: vcd3 = SLOAD vcd2
    0xcd6: vcd6(0x1) = CONST 
    0xcd8: vcd8 = ADD vcd6(0x1), vcc8
    0xcd9: vcd9(0x0) = CONST 
    0xcdc: vcdc = SLOAD vcd8
    0xcde: vcde(0x100) = CONST 
    0xce1: vce1(0x1) = EXP vcde(0x100), vcd9(0x0)
    0xce3: vce3 = DIV vcdc, vce1(0x1)
    0xce4: vce4(0xff) = CONST 
    0xce6: vce6 = AND vce4(0xff), vce3
    0xcea: JUMP v7ab(0x7ec)

    Begin block 0x7ec
    prev=[0xcba], succ=[]
    =================================
    0x7ed: v7ed(0x40) = CONST 
    0x7ef: v7ef = MLOAD v7ed(0x40)
    0x7f3: MSTORE v7ef, vcd3
    0x7f4: v7f4(0x20) = CONST 
    0x7f6: v7f6 = ADD v7f4(0x20), v7ef
    0x7f8: v7f8 = ISZERO vce6
    0x7f9: v7f9 = ISZERO v7f8
    0x7fa: v7fa = ISZERO v7f9
    0x7fb: v7fb = ISZERO v7fa
    0x7fd: MSTORE v7f6, v7fb
    0x7fe: v7fe(0x20) = CONST 
    0x800: v800 = ADD v7fe(0x20), v7f6
    0x805: v805(0x40) = CONST 
    0x807: v807 = MLOAD v805(0x40)
    0x80a: v80a = SUB v800, v807
    0x80c: RETURN v807, v80a

}

function loanOrderHashes(uint256)() public {
    Begin block 0x80d
    prev=[], succ=[0x81f, 0x823]
    =================================
    0x80e: v80e(0x839) = CONST 
    0x811: v811(0x4) = CONST 
    0x814: v814 = CALLDATASIZE 
    0x815: v815 = SUB v814, v811(0x4)
    0x816: v816(0x20) = CONST 
    0x819: v819 = LT v815, v816(0x20)
    0x81a: v81a = ISZERO v819
    0x81b: v81b(0x823) = CONST 
    0x81e: JUMPI v81b(0x823), v81a

    Begin block 0x81f
    prev=[0x80d], succ=[]
    =================================
    0x81f: v81f(0x0) = CONST 
    0x822: REVERT v81f(0x0), v81f(0x0)

    Begin block 0x823
    prev=[0x80d], succ=[0xceb]
    =================================
    0x825: v825 = ADD v811(0x4), v815
    0x829: v829 = CALLDATALOAD v811(0x4)
    0x82b: v82b(0x20) = CONST 
    0x82d: v82d = ADD v82b(0x20), v811(0x4)
    0x835: v835(0xceb) = CONST 
    0x838: JUMP v835(0xceb)

    Begin block 0xceb
    prev=[0x823], succ=[0x839]
    =================================
    0xcec: vcec(0xe) = CONST 
    0xcee: vcee(0x20) = CONST 
    0xcf0: MSTORE vcee(0x20), vcec(0xe)
    0xcf2: vcf2(0x0) = CONST 
    0xcf4: MSTORE vcf2(0x0), v829
    0xcf5: vcf5(0x40) = CONST 
    0xcf7: vcf7(0x0) = CONST 
    0xcf9: vcf9 = SHA3 vcf7(0x0), vcf5(0x40)
    0xcfa: vcfa(0x0) = CONST 
    0xd00: vd00 = SLOAD vcf9
    0xd02: JUMP v80e(0x839)

    Begin block 0x839
    prev=[0xceb], succ=[]
    =================================
    0x83a: v83a(0x40) = CONST 
    0x83c: v83c = MLOAD v83a(0x40)
    0x840: MSTORE v83c, vd00
    0x841: v841(0x20) = CONST 
    0x843: v843 = ADD v841(0x20), v83c
    0x847: v847(0x40) = CONST 
    0x849: v849 = MLOAD v847(0x40)
    0x84c: v84c = SUB v843, v849
    0x84e: RETURN v849, v84c

}

function 0x84f(0x84farg0x0) private {
    Begin block 0x84f
    prev=[], succ=[0x89f, 0x39f4]
    =================================
    0x850: v850(0x2) = CONST 
    0x853: v853 = SLOAD v850(0x2)
    0x854: v854(0x1) = CONST 
    0x857: v857(0x1) = CONST 
    0x859: v859 = AND v857(0x1), v853
    0x85a: v85a = ISZERO v859
    0x85b: v85b(0x100) = CONST 
    0x85e: v85e = MUL v85b(0x100), v85a
    0x85f: v85f = SUB v85e, v854(0x1)
    0x860: v860 = AND v85f, v853
    0x861: v861(0x2) = CONST 
    0x864: v864 = DIV v860, v861(0x2)
    0x866: v866(0x1f) = CONST 
    0x868: v868 = ADD v866(0x1f), v864
    0x869: v869(0x20) = CONST 
    0x86d: v86d = DIV v868, v869(0x20)
    0x86e: v86e = MUL v86d, v869(0x20)
    0x86f: v86f(0x20) = CONST 
    0x871: v871 = ADD v86f(0x20), v86e
    0x872: v872(0x40) = CONST 
    0x874: v874 = MLOAD v872(0x40)
    0x877: v877 = ADD v874, v871
    0x878: v878(0x40) = CONST 
    0x87a: MSTORE v878(0x40), v877
    0x881: MSTORE v874, v864
    0x882: v882(0x20) = CONST 
    0x884: v884 = ADD v882(0x20), v874
    0x887: v887 = SLOAD v850(0x2)
    0x888: v888(0x1) = CONST 
    0x88b: v88b(0x1) = CONST 
    0x88d: v88d = AND v88b(0x1), v887
    0x88e: v88e = ISZERO v88d
    0x88f: v88f(0x100) = CONST 
    0x892: v892 = MUL v88f(0x100), v88e
    0x893: v893 = SUB v892, v888(0x1)
    0x894: v894 = AND v893, v887
    0x895: v895(0x2) = CONST 
    0x898: v898 = DIV v894, v895(0x2)
    0x89a: v89a = ISZERO v898
    0x89b: v89b(0x39f4) = CONST 
    0x89e: JUMPI v89b(0x39f4), v89a

    Begin block 0x89f
    prev=[0x84f], succ=[0x8a7, 0x8ba]
    =================================
    0x8a0: v8a0(0x1f) = CONST 
    0x8a2: v8a2 = LT v8a0(0x1f), v898
    0x8a3: v8a3(0x8ba) = CONST 
    0x8a6: JUMPI v8a3(0x8ba), v8a2

    Begin block 0x8a7
    prev=[0x89f], succ=[0x3a1b]
    =================================
    0x8a7: v8a7(0x100) = CONST 
    0x8ac: v8ac = SLOAD v850(0x2)
    0x8ad: v8ad = DIV v8ac, v8a7(0x100)
    0x8ae: v8ae = MUL v8ad, v8a7(0x100)
    0x8b0: MSTORE v884, v8ae
    0x8b2: v8b2(0x20) = CONST 
    0x8b4: v8b4 = ADD v8b2(0x20), v884
    0x8b6: v8b6(0x3a1b) = CONST 
    0x8b9: JUMP v8b6(0x3a1b)

    Begin block 0x3a1b
    prev=[0x8a7], succ=[]
    =================================
    0x3a22: RETURNPRIVATE v84farg0, v874, v84farg0

    Begin block 0x8ba
    prev=[0x89f], succ=[0x8c8]
    =================================
    0x8bc: v8bc = ADD v884, v898
    0x8bf: v8bf(0x0) = CONST 
    0x8c1: MSTORE v8bf(0x0), v850(0x2)
    0x8c2: v8c2(0x20) = CONST 
    0x8c4: v8c4(0x0) = CONST 
    0x8c6: v8c6 = SHA3 v8c4(0x0), v8c2(0x20)

    Begin block 0x8c8
    prev=[0x8ba, 0x8c8], succ=[0x8c8, 0x8dc]
    =================================
    0x8c8_0x0: v8c8_0 = PHI v884, v8d4
    0x8c8_0x1: v8c8_1 = PHI v8c6, v8d0
    0x8ca: v8ca = SLOAD v8c8_1
    0x8cc: MSTORE v8c8_0, v8ca
    0x8ce: v8ce(0x1) = CONST 
    0x8d0: v8d0 = ADD v8ce(0x1), v8c8_1
    0x8d2: v8d2(0x20) = CONST 
    0x8d4: v8d4 = ADD v8d2(0x20), v8c8_0
    0x8d7: v8d7 = GT v8bc, v8d4
    0x8d8: v8d8(0x8c8) = CONST 
    0x8db: JUMPI v8d8(0x8c8), v8d7

    Begin block 0x8dc
    prev=[0x8c8], succ=[0x8e5]
    =================================
    0x8de: v8de = SUB v8d4, v8bc
    0x8df: v8df(0x1f) = CONST 
    0x8e1: v8e1 = AND v8df(0x1f), v8de
    0x8e3: v8e3 = ADD v8bc, v8e1

    Begin block 0x8e5
    prev=[0x8dc], succ=[]
    =================================
    0x8ec: RETURNPRIVATE v84farg0, v874, v84farg0

    Begin block 0x39f4
    prev=[0x84f], succ=[]
    =================================
    0x39fb: RETURNPRIVATE v84farg0, v874, v84farg0

}

function 0xabc(0xabcarg0x0) private {
    Begin block 0xabc
    prev=[], succ=[0xb0c, 0x3a42]
    =================================
    0xabd: vabd(0x3) = CONST 
    0xac0: vac0 = SLOAD vabd(0x3)
    0xac1: vac1(0x1) = CONST 
    0xac4: vac4(0x1) = CONST 
    0xac6: vac6 = AND vac4(0x1), vac0
    0xac7: vac7 = ISZERO vac6
    0xac8: vac8(0x100) = CONST 
    0xacb: vacb = MUL vac8(0x100), vac7
    0xacc: vacc = SUB vacb, vac1(0x1)
    0xacd: vacd = AND vacc, vac0
    0xace: vace(0x2) = CONST 
    0xad1: vad1 = DIV vacd, vace(0x2)
    0xad3: vad3(0x1f) = CONST 
    0xad5: vad5 = ADD vad3(0x1f), vad1
    0xad6: vad6(0x20) = CONST 
    0xada: vada = DIV vad5, vad6(0x20)
    0xadb: vadb = MUL vada, vad6(0x20)
    0xadc: vadc(0x20) = CONST 
    0xade: vade = ADD vadc(0x20), vadb
    0xadf: vadf(0x40) = CONST 
    0xae1: vae1 = MLOAD vadf(0x40)
    0xae4: vae4 = ADD vae1, vade
    0xae5: vae5(0x40) = CONST 
    0xae7: MSTORE vae5(0x40), vae4
    0xaee: MSTORE vae1, vad1
    0xaef: vaef(0x20) = CONST 
    0xaf1: vaf1 = ADD vaef(0x20), vae1
    0xaf4: vaf4 = SLOAD vabd(0x3)
    0xaf5: vaf5(0x1) = CONST 
    0xaf8: vaf8(0x1) = CONST 
    0xafa: vafa = AND vaf8(0x1), vaf4
    0xafb: vafb = ISZERO vafa
    0xafc: vafc(0x100) = CONST 
    0xaff: vaff = MUL vafc(0x100), vafb
    0xb00: vb00 = SUB vaff, vaf5(0x1)
    0xb01: vb01 = AND vb00, vaf4
    0xb02: vb02(0x2) = CONST 
    0xb05: vb05 = DIV vb01, vb02(0x2)
    0xb07: vb07 = ISZERO vb05
    0xb08: vb08(0x3a42) = CONST 
    0xb0b: JUMPI vb08(0x3a42), vb07

    Begin block 0xb0c
    prev=[0xabc], succ=[0xb14, 0xb27]
    =================================
    0xb0d: vb0d(0x1f) = CONST 
    0xb0f: vb0f = LT vb0d(0x1f), vb05
    0xb10: vb10(0xb27) = CONST 
    0xb13: JUMPI vb10(0xb27), vb0f

    Begin block 0xb14
    prev=[0xb0c], succ=[0x3a69]
    =================================
    0xb14: vb14(0x100) = CONST 
    0xb19: vb19 = SLOAD vabd(0x3)
    0xb1a: vb1a = DIV vb19, vb14(0x100)
    0xb1b: vb1b = MUL vb1a, vb14(0x100)
    0xb1d: MSTORE vaf1, vb1b
    0xb1f: vb1f(0x20) = CONST 
    0xb21: vb21 = ADD vb1f(0x20), vaf1
    0xb23: vb23(0x3a69) = CONST 
    0xb26: JUMP vb23(0x3a69)

    Begin block 0x3a69
    prev=[0xb14], succ=[]
    =================================
    0x3a70: RETURNPRIVATE vabcarg0, vae1, vabcarg0

    Begin block 0xb27
    prev=[0xb0c], succ=[0xb35]
    =================================
    0xb29: vb29 = ADD vaf1, vb05
    0xb2c: vb2c(0x0) = CONST 
    0xb2e: MSTORE vb2c(0x0), vabd(0x3)
    0xb2f: vb2f(0x20) = CONST 
    0xb31: vb31(0x0) = CONST 
    0xb33: vb33 = SHA3 vb31(0x0), vb2f(0x20)

    Begin block 0xb35
    prev=[0xb27, 0xb35], succ=[0xb35, 0xb49]
    =================================
    0xb35_0x0: vb35_0 = PHI vaf1, vb41
    0xb35_0x1: vb35_1 = PHI vb33, vb3d
    0xb37: vb37 = SLOAD vb35_1
    0xb39: MSTORE vb35_0, vb37
    0xb3b: vb3b(0x1) = CONST 
    0xb3d: vb3d = ADD vb3b(0x1), vb35_1
    0xb3f: vb3f(0x20) = CONST 
    0xb41: vb41 = ADD vb3f(0x20), vb35_0
    0xb44: vb44 = GT vb29, vb41
    0xb45: vb45(0xb35) = CONST 
    0xb48: JUMPI vb45(0xb35), vb44

    Begin block 0xb49
    prev=[0xb35], succ=[0xb52]
    =================================
    0xb4b: vb4b = SUB vb41, vb29
    0xb4c: vb4c(0x1f) = CONST 
    0xb4e: vb4e = AND vb4c(0x1f), vb4b
    0xb50: vb50 = ADD vb29, vb4e

    Begin block 0xb52
    prev=[0xb49], succ=[]
    =================================
    0xb59: RETURNPRIVATE vabcarg0, vae1, vabcarg0

    Begin block 0x3a42
    prev=[0xabc], succ=[]
    =================================
    0x3a49: RETURNPRIVATE vabcarg0, vae1, vabcarg0

}

function 0xc54(0xc54arg0x0, 0xc54arg0x1) private {
    Begin block 0xc54
    prev=[], succ=[0xcaa, 0xcae]
    =================================
    0xc55: vc55(0x1) = CONST 
    0xc57: vc57(0x0) = CONST 
    0xc5a: vc5a = SLOAD vc55(0x1)
    0xc5c: vc5c(0x100) = CONST 
    0xc5f: vc5f(0x1) = EXP vc5c(0x100), vc57(0x0)
    0xc61: vc61 = DIV vc5a, vc5f(0x1)
    0xc62: vc62(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xc77: vc77 = AND vc62(0xffffffffffffffffffffffffffffffffffffffff), vc61
    0xc78: vc78(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xc8d: vc8d = AND vc78(0xffffffffffffffffffffffffffffffffffffffff), vc77
    0xc8e: vc8e = CALLER 
    0xc8f: vc8f(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xca4: vca4 = AND vc8f(0xffffffffffffffffffffffffffffffffffffffff), vc8e
    0xca5: vca5 = EQ vca4, vc8d
    0xca6: vca6(0xcae) = CONST 
    0xca9: JUMPI vca6(0xcae), vca5

    Begin block 0xcaa
    prev=[0xc54], succ=[]
    =================================
    0xcaa: vcaa(0x0) = CONST 
    0xcad: REVERT vcaa(0x0), vcaa(0x0)

    Begin block 0xcae
    prev=[0xc54], succ=[0xd03]
    =================================
    0xcaf: vcaf(0xcb7) = CONST 
    0xcb3: vcb3(0xd03) = CONST 
    0xcb6: JUMP vcb3(0xd03)

    Begin block 0xd03
    prev=[0xcae], succ=[0xd39, 0xd3d]
    =================================
    0xd04: vd04(0x0) = CONST 
    0xd06: vd06(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xd1b: vd1b(0x0) = AND vd06(0xffffffffffffffffffffffffffffffffffffffff), vd04(0x0)
    0xd1d: vd1d(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xd32: vd32 = AND vd1d(0xffffffffffffffffffffffffffffffffffffffff), vc54arg0
    0xd33: vd33 = EQ vd32, vd1b(0x0)
    0xd34: vd34 = ISZERO vd33
    0xd35: vd35(0xd3d) = CONST 
    0xd38: JUMPI vd35(0xd3d), vd34

    Begin block 0xd39
    prev=[0xd03], succ=[]
    =================================
    0xd39: vd39(0x0) = CONST 
    0xd3c: REVERT vd39(0x0), vd39(0x0)

    Begin block 0xd3d
    prev=[0xd03], succ=[0xcb7]
    =================================
    0xd3f: vd3f(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xd54: vd54 = AND vd3f(0xffffffffffffffffffffffffffffffffffffffff), vc54arg0
    0xd55: vd55(0x1) = CONST 
    0xd57: vd57(0x0) = CONST 
    0xd5a: vd5a = SLOAD vd55(0x1)
    0xd5c: vd5c(0x100) = CONST 
    0xd5f: vd5f(0x1) = EXP vd5c(0x100), vd57(0x0)
    0xd61: vd61 = DIV vd5a, vd5f(0x1)
    0xd62: vd62(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xd77: vd77 = AND vd62(0xffffffffffffffffffffffffffffffffffffffff), vd61
    0xd78: vd78(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xd8d: vd8d = AND vd78(0xffffffffffffffffffffffffffffffffffffffff), vd77
    0xd8e: vd8e(0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0) = CONST 
    0xdaf: vdaf(0x40) = CONST 
    0xdb1: vdb1 = MLOAD vdaf(0x40)
    0xdb2: vdb2(0x40) = CONST 
    0xdb4: vdb4 = MLOAD vdb2(0x40)
    0xdb7: vdb7 = SUB vdb1, vdb4
    0xdb9: LOG3 vdb4, vdb7, vd8e(0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0), vd8d, vd54
    0xdbb: vdbb(0x1) = CONST 
    0xdbd: vdbd(0x0) = CONST 
    0xdbf: vdbf(0x100) = CONST 
    0xdc2: vdc2(0x1) = EXP vdbf(0x100), vdbd(0x0)
    0xdc4: vdc4 = SLOAD vdbb(0x1)
    0xdc6: vdc6(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xddb: vddb(0xffffffffffffffffffffffffffffffffffffffff) = MUL vdc6(0xffffffffffffffffffffffffffffffffffffffff), vdc2(0x1)
    0xddc: vddc(0xffffffffffffffffffffffff0000000000000000000000000000000000000000) = NOT vddb(0xffffffffffffffffffffffffffffffffffffffff)
    0xddd: vddd = AND vddc(0xffffffffffffffffffffffff0000000000000000000000000000000000000000), vdc4
    0xde0: vde0(0xffffffffffffffffffffffffffffffffffffffff) = CONST 
    0xdf5: vdf5 = AND vde0(0xffffffffffffffffffffffffffffffffffffffff), vc54arg0
    0xdf6: vdf6 = MUL vdf5, vdc2(0x1)
    0xdf7: vdf7 = OR vdf6, vddd
    0xdf9: SSTORE vdbb(0x1), vdf7
    0xdfc: JUMP vcaf(0xcb7)

    Begin block 0xcb7
    prev=[0xd3d], succ=[]
    =================================
    0xcb9: RETURNPRIVATE vc54arg1

}

