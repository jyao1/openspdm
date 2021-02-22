## @file
#  SPDM library.
#
#  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#
# Platform Macro Definition
#

!INCLUDE $(WORKSPACE)\MakeFile.Flags

#
# Module Macro Definition
#
MODULE_NAME = OpensslLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\OsStub\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\OsStub\$(MODULE_NAME)

CC_FLAGS = $(CC_FLAGS) -U_WIN32 -U_WIN64 -U_MSC_VER -DL_ENDIAN -DOPENSSL_SMALL_FOOTPRINT -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -DOPENSSL_SYS_UEFI=1 $(OPENSSL_FLAGS) 

#
# Build Macro
#


OBJECT_1_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_cbc.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_cfb.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_core.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_ecb.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_ige.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_misc.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_ofb.obj \
    $(OUTPUT_DIR)\openssl\crypto\aes\aes_wrap.obj \


OBJECT_2_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\aria\aria.obj \


OBJECT_3_A_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_bitstr.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_d2i_fp.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_digest.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_dup.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_gentm.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_i2d_fp.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_int.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_mbstr.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_object.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_octet.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_print.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_sign.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_strex.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_strnid.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_time.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_type.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_utctm.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_utf8.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\a_verify.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\ameth_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn1_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn1_gen.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn1_item_list.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn1_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn1_par.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn_mime.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn_moid.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn_mstbl.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\asn_pack.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\bio_asn1.obj \

OBJECT_3_B_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\asn1\bio_ndef.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\d2i_pr.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\d2i_pu.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\evp_asn1.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\f_int.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\f_string.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\i2d_pr.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\i2d_pu.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\n_pkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\nsseq.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\p5_pbe.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\p5_pbev2.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\p5_scrypt.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\p8_pkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\t_bitst.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\t_pkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\t_spki.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_dec.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_enc.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_fre.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_new.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_prn.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_scn.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_typ.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\tasn_utl.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_algor.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_bignum.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_info.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_int64.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_long.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_pkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_sig.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_spki.obj \
    $(OUTPUT_DIR)\openssl\crypto\asn1\x_val.obj \


OBJECT_4_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\async\arch\async_null.obj \
    $(OUTPUT_DIR)\openssl\crypto\async\arch\async_posix.obj \
    $(OUTPUT_DIR)\openssl\crypto\async\arch\async_win.obj \
    $(OUTPUT_DIR)\openssl\crypto\async\async.obj \
    $(OUTPUT_DIR)\openssl\crypto\async\async_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\async\async_wait.obj \


OBJECT_5_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\bio\b_addr.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\b_dump.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\b_sock.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\b_sock2.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bf_buff.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bf_lbuf.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bf_nbio.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bf_null.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bio_cb.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bio_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bio_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bio_meth.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_acpt.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_bio.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_conn.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_dgram.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_fd.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_file.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_log.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_mem.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_null.obj \
    $(OUTPUT_DIR)\openssl\crypto\bio\bss_sock.obj \


OBJECT_6_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_add.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_asm.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_blind.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_const.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_ctx.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_depr.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_dh.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_div.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_exp.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_exp2.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_gcd.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_gf2m.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_intern.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_kron.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_mod.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_mont.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_mpi.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_mul.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_nist.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_prime.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_print.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_rand.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_recp.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_shift.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_sqr.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_sqrt.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_srp.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_word.obj \
    $(OUTPUT_DIR)\openssl\crypto\bn\bn_x931p.obj \


OBJECT_7_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\buffer\buf_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\buffer\buffer.obj \


OBJECT_8_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\chacha\chacha_enc.obj \


OBJECT_9_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\cmac\cm_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\cmac\cm_pmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\cmac\cmac.obj \


OBJECT_10_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\comp\c_zlib.obj \
    $(OUTPUT_DIR)\openssl\crypto\comp\comp_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\comp\comp_lib.obj \


OBJECT_11_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_api.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_def.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_mall.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_mod.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_sap.obj \
    $(OUTPUT_DIR)\openssl\crypto\conf\conf_ssl.obj \


OBJECT_12_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\cpt_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\cryptlib.obj \
    $(OUTPUT_DIR)\openssl\crypto\ctype.obj \
    $(OUTPUT_DIR)\openssl\crypto\cversion.obj \
    $(OUTPUT_DIR)\openssl\crypto\ebcdic.obj \
    $(OUTPUT_DIR)\openssl\crypto\ex_data.obj \
    $(OUTPUT_DIR)\openssl\crypto\getenv.obj \
    $(OUTPUT_DIR)\openssl\crypto\init.obj \
    $(OUTPUT_DIR)\openssl\crypto\mem.obj \
    $(OUTPUT_DIR)\openssl\crypto\mem_clr.obj \
    $(OUTPUT_DIR)\openssl\crypto\mem_dbg.obj \
    $(OUTPUT_DIR)\openssl\crypto\mem_sec.obj \
    $(OUTPUT_DIR)\openssl\crypto\o_dir.obj \
    $(OUTPUT_DIR)\openssl\crypto\o_fips.obj \
    $(OUTPUT_DIR)\openssl\crypto\o_fopen.obj \
    $(OUTPUT_DIR)\openssl\crypto\o_init.obj \
    $(OUTPUT_DIR)\openssl\crypto\o_str.obj \
    $(OUTPUT_DIR)\openssl\crypto\o_time.obj \
    $(OUTPUT_DIR)\openssl\crypto\threads_none.obj \
    $(OUTPUT_DIR)\openssl\crypto\threads_pthread.obj \
    $(OUTPUT_DIR)\openssl\crypto\threads_win.obj \
    $(OUTPUT_DIR)\openssl\crypto\uid.obj \


OBJECT_13_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_asn1.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_check.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_depr.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_gen.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_kdf.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_key.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_meth.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_pmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_prn.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_rfc5114.obj \
    $(OUTPUT_DIR)\openssl\crypto\dh\dh_rfc7919.obj \


OBJECT_14_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_dl.obj \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_dlfcn.obj \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_openssl.obj \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_vms.obj \
    $(OUTPUT_DIR)\openssl\crypto\dso\dso_win32.obj \


OBJECT_15_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve25519.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve448\arch_32\f_impl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve448\curve448.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve448\curve448_tables.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve448\eddsa.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve448\f_generic.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\curve448\scalar.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec2_oct.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec2_smpl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_asn1.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_check.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_curve.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_cvt.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_key.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_kmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_mult.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_oct.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_pmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ec_print.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecdh_kdf.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecdh_ossl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecdsa_ossl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecdsa_sign.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecdsa_vrf.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\eck_prn.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_mont.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_nist.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistp224.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistp256.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistp521.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistputil.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_oct.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecp_smpl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ec\ecx_meth.obj \


OBJECT_16_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\err\err.obj \
    $(OUTPUT_DIR)\openssl\crypto\err\err_prn.obj \


OBJECT_17_A_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\evp\bio_b64.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\bio_enc.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\bio_md.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\bio_ok.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\c_allc.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\c_alld.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\cmeth_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\digest.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_aes.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_aes_cbc_hmac_sha256.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_aria.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_bf.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_camellia.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_cast.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_chacha20_poly1305.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_null.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_old.obj \

OBJECT_17_B_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_seed.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\e_xcbc_d.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\encode.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_cnf.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_enc.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_key.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_pbe.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\evp_pkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_md5.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_mdc2.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_null.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_ripemd.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_sha1.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_sha3.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_sigver.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\m_wp.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\names.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p5_crpt.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p5_crpt2.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_dec.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_enc.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_open.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_seal.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_sign.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\p_verify.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\pbe_scrypt.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\pmeth_fn.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\pmeth_gn.obj \
    $(OUTPUT_DIR)\openssl\crypto\evp\pmeth_lib.obj \


OBJECT_18_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\hmac\hm_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\hmac\hm_pmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\hmac\hmac.obj \


OBJECT_19_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\kdf\hkdf.obj \
    $(OUTPUT_DIR)\openssl\crypto\kdf\kdf_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\kdf\scrypt.obj \
    $(OUTPUT_DIR)\openssl\crypto\kdf\tls1_prf.obj \


OBJECT_20_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\lhash\lh_stats.obj \
    $(OUTPUT_DIR)\openssl\crypto\lhash\lhash.obj \


OBJECT_21_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\md5\md5_dgst.obj \
    $(OUTPUT_DIR)\openssl\crypto\md5\md5_one.obj \


OBJECT_22_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\modes\cbc128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\ccm128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\cfb128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\ctr128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\cts128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\gcm128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\ocb128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\ofb128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\wrap128.obj \
    $(OUTPUT_DIR)\openssl\crypto\modes\xts128.obj \


OBJECT_23_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\objects\o_names.obj \
    $(OUTPUT_DIR)\openssl\crypto\objects\obj_dat.obj \
    $(OUTPUT_DIR)\openssl\crypto\objects\obj_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\objects\obj_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\objects\obj_xref.obj \


OBJECT_24_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_asn.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_cl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_ext.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_ht.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_prn.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_srv.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_vfy.obj \
    $(OUTPUT_DIR)\openssl\crypto\ocsp\v3_ocsp.obj \


OBJECT_25_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_all.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_info.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_oth.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_pk8.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_pkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_sign.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_x509.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pem_xaux.obj \
    $(OUTPUT_DIR)\openssl\crypto\pem\pvkfmt.obj \


OBJECT_26_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_add.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_asn.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_attr.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_crpt.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_crt.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_decr.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_init.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_key.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_kiss.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_mutl.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_npas.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_p8d.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_p8e.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_sbag.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_utl.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs12\pk12err.obj \


OBJECT_27_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\bio_pk7.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_asn1.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_attr.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_doit.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_mime.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_smime.obj \
    $(OUTPUT_DIR)\openssl\crypto\pkcs7\pkcs7err.obj \


OBJECT_28_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\poly1305\poly1305.obj \
    $(OUTPUT_DIR)\openssl\crypto\poly1305\poly1305_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\poly1305\poly1305_pmeth.obj \


OBJECT_29_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\rand\drbg_ctr.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\drbg_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\rand_egd.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\rand_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\rand_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\rand_unix.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\rand_vms.obj \
    $(OUTPUT_DIR)\openssl\crypto\rand\rand_win.obj \


OBJECT_30_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_asn1.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_chk.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_crpt.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_depr.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_gen.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_meth.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_mp.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_none.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_oaep.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_ossl.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_pk1.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_pmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_prn.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_pss.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_saos.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_sign.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_ssl.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_x931.obj \
    $(OUTPUT_DIR)\openssl\crypto\rsa\rsa_x931g.obj \


OBJECT_31_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\sha\keccak1600.obj \
    $(OUTPUT_DIR)\openssl\crypto\sha\sha1_one.obj \
    $(OUTPUT_DIR)\openssl\crypto\sha\sha1dgst.obj \
    $(OUTPUT_DIR)\openssl\crypto\sha\sha256.obj \
    $(OUTPUT_DIR)\openssl\crypto\sha\sha512.obj \


OBJECT_32_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\siphash\siphash.obj \
    $(OUTPUT_DIR)\openssl\crypto\siphash\siphash_ameth.obj \
    $(OUTPUT_DIR)\openssl\crypto\siphash\siphash_pmeth.obj \


OBJECT_33_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\stack\stack.obj \


OBJECT_34_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\txt_db\txt_db.obj \


OBJECT_35_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\ui\ui_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\ui\ui_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\ui\ui_null.obj \
    $(OUTPUT_DIR)\openssl\crypto\ui\ui_openssl.obj \
    $(OUTPUT_DIR)\openssl\crypto\ui\ui_util.obj \


OBJECT_36_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\x509\by_dir.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\by_file.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\t_crl.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\t_req.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\t_x509.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_att.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_cmp.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_d2.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_def.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_ext.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_lu.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_meth.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_obj.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_r2x.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_req.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_set.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_trs.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_txt.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_v3.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_vfy.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509_vpm.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509cset.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509name.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509rset.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509spki.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x509type.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_all.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_attrib.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_crl.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_exten.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_name.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_pubkey.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_req.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_x509.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509\x_x509a.obj \

OBJECT_37_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_cache.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_data.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_map.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_node.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_tree.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_addr.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_admis.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_akey.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_akeya.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_alt.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_asid.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_bcons.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_bitst.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_conf.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_cpols.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_crld.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_enum.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_extku.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_genn.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_ia5.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_info.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_int.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_lib.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_ncons.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pci.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pcia.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pcons.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pku.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pmaps.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_prn.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_purp.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_skey.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_sxnet.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_tlsf.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3_utl.obj \
    $(OUTPUT_DIR)\openssl\crypto\x509v3\v3err.obj \

OBJECT_38_FILES =  \
    $(OUTPUT_DIR)\openssl\crypto\sm2\sm2_crypt.obj \
    $(OUTPUT_DIR)\openssl\crypto\sm2\sm2_err.obj \
    $(OUTPUT_DIR)\openssl\crypto\sm2\sm2_pmeth.obj \
    $(OUTPUT_DIR)\openssl\crypto\sm2\sm2_sign.obj \
    $(OUTPUT_DIR)\openssl\crypto\sm3\m_sm3.obj \
    $(OUTPUT_DIR)\openssl\crypto\sm3\sm3.obj \
    $(OUTPUT_DIR)\openssl\crypto\sm4\sm4.obj \

OBJECT_39_FILES =  \
    $(OUTPUT_DIR)\ossl_store.obj \
    $(OUTPUT_DIR)\rand_pool.obj \

INC =  \
    -I$(SOURCE_DIR)\openssl\crypto\store \
    -I$(SOURCE_DIR)\openssl\crypto\x509v3 \
    -I$(SOURCE_DIR)\openssl\crypto\x509 \
    -I$(SOURCE_DIR)\openssl\crypto\ui \
    -I$(SOURCE_DIR)\openssl\crypto\txt_db \
    -I$(SOURCE_DIR)\openssl\crypto\stack \
    -I$(SOURCE_DIR)\openssl\crypto\siphash \
    -I$(SOURCE_DIR)\openssl\crypto\sha \
    -I$(SOURCE_DIR)\openssl\crypto\rsa \
    -I$(SOURCE_DIR)\openssl\crypto\rand \
    -I$(SOURCE_DIR)\openssl\crypto\poly1305 \
    -I$(SOURCE_DIR)\openssl\crypto\pkcs7 \
    -I$(SOURCE_DIR)\openssl\crypto\pkcs12 \
    -I$(SOURCE_DIR)\openssl\crypto\pem \
    -I$(SOURCE_DIR)\openssl\crypto\ocsp \
    -I$(SOURCE_DIR)\openssl\crypto\objects \
    -I$(SOURCE_DIR)\openssl\crypto\modes \
    -I$(SOURCE_DIR)\openssl\crypto\md5 \
    -I$(SOURCE_DIR)\openssl\crypto\lhash \
    -I$(SOURCE_DIR)\openssl\crypto\kdf \
    -I$(SOURCE_DIR)\openssl\crypto\hmac \
    -I$(SOURCE_DIR)\openssl\crypto\evp \
    -I$(SOURCE_DIR)\openssl\crypto\err \
    -I$(SOURCE_DIR)\openssl\crypto\dso \
    -I$(SOURCE_DIR)\openssl\crypto\ec \
    -I$(SOURCE_DIR)\openssl\crypto\ec\curve448 \
    -I$(SOURCE_DIR)\openssl\crypto\ec\curve448\arch_32 \
    -I$(SOURCE_DIR)\openssl\crypto\dh \
    -I$(SOURCE_DIR)\openssl\crypto \
    -I$(SOURCE_DIR)\openssl\crypto\conf \
    -I$(SOURCE_DIR)\openssl\crypto\comp \
    -I$(SOURCE_DIR)\openssl\crypto\cmac \
    -I$(SOURCE_DIR)\openssl\crypto\chacha \
    -I$(SOURCE_DIR)\openssl\crypto\buffer \
    -I$(SOURCE_DIR)\openssl\crypto\bn \
    -I$(SOURCE_DIR)\openssl\crypto\bio \
    -I$(SOURCE_DIR)\openssl\crypto\async \
    -I$(SOURCE_DIR)\openssl\crypto\async\arch \
    -I$(SOURCE_DIR)\openssl\crypto\asn1 \
    -I$(SOURCE_DIR)\openssl\crypto\aria \
    -I$(SOURCE_DIR)\openssl\crypto\aes \
    -I$(SOURCE_DIR)\openssl\crypto\sm2 \
    -I$(SOURCE_DIR)\openssl\crypto\sm3 \
    -I$(SOURCE_DIR)\openssl\crypto\sm4 \
    -I$(SOURCE_DIR)\openssl\ms \
    -I$(SOURCE_DIR)\openssl \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include \
    -I$(WORKSPACE)\OsStub\OpensslLib\Include \
    -I$(WORKSPACE)\OsStub\OpensslLib\openssl\include \
    -I$(WORKSPACE)\OsStub\OpensslLib\openssl\crypto\include

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)\$(MODULE_NAME).lib

#
# Default target, which will build dependent libraries in addition to source files
#

all: mbuild

#
# ModuleTarget
#

mbuild: $(INIT_TARGET) $(CODA_TARGET)

#
# Initialization target: print build information and create necessary directories
#
init:
	-@if not exist $(OUTPUT_DIR)\openssl $(MD) $(OUTPUT_DIR)\openssl
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\store $(MD) $(OUTPUT_DIR)\openssl\crypto\store
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\x509v3 $(MD) $(OUTPUT_DIR)\openssl\crypto\x509v3
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\x509 $(MD) $(OUTPUT_DIR)\openssl\crypto\x509
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\ui $(MD) $(OUTPUT_DIR)\openssl\crypto\ui
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\txt_db $(MD) $(OUTPUT_DIR)\openssl\crypto\txt_db
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\stack $(MD) $(OUTPUT_DIR)\openssl\crypto\stack
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\siphash $(MD) $(OUTPUT_DIR)\openssl\crypto\siphash
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\sha $(MD) $(OUTPUT_DIR)\openssl\crypto\sha
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\rsa $(MD) $(OUTPUT_DIR)\openssl\crypto\rsa
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\rand $(MD) $(OUTPUT_DIR)\openssl\crypto\rand
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\poly1305 $(MD) $(OUTPUT_DIR)\openssl\crypto\poly1305
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\pkcs7 $(MD) $(OUTPUT_DIR)\openssl\crypto\pkcs7
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\pkcs12 $(MD) $(OUTPUT_DIR)\openssl\crypto\pkcs12
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\pem $(MD) $(OUTPUT_DIR)\openssl\crypto\pem
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\ocsp $(MD) $(OUTPUT_DIR)\openssl\crypto\ocsp
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\objects $(MD) $(OUTPUT_DIR)\openssl\crypto\objects
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\modes $(MD) $(OUTPUT_DIR)\openssl\crypto\modes
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\md5 $(MD) $(OUTPUT_DIR)\openssl\crypto\md5
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\lhash $(MD) $(OUTPUT_DIR)\openssl\crypto\lhash
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\kdf $(MD) $(OUTPUT_DIR)\openssl\crypto\kdf
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\hmac $(MD) $(OUTPUT_DIR)\openssl\crypto\hmac
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\evp $(MD) $(OUTPUT_DIR)\openssl\crypto\evp
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\err $(MD) $(OUTPUT_DIR)\openssl\crypto\err
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\dso $(MD) $(OUTPUT_DIR)\openssl\crypto\dso
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\ec $(MD) $(OUTPUT_DIR)\openssl\crypto\ec
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\ec\curve448 $(MD) $(OUTPUT_DIR)\openssl\crypto\ec\curve448
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\ec\curve448\arch_32 $(MD) $(OUTPUT_DIR)\openssl\crypto\ec\curve448\arch_32
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\dh $(MD) $(OUTPUT_DIR)\openssl\crypto\dh
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\conf $(MD) $(OUTPUT_DIR)\openssl\crypto\conf
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\comp $(MD) $(OUTPUT_DIR)\openssl\crypto\comp
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\cmac $(MD) $(OUTPUT_DIR)\openssl\crypto\cmac
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\chacha $(MD) $(OUTPUT_DIR)\openssl\crypto\chacha
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\buffer $(MD) $(OUTPUT_DIR)\openssl\crypto\buffer
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\bn $(MD) $(OUTPUT_DIR)\openssl\crypto\bn
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\bio $(MD) $(OUTPUT_DIR)\openssl\crypto\bio
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\async $(MD) $(OUTPUT_DIR)\openssl\crypto\async
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\async\arch $(MD) $(OUTPUT_DIR)\openssl\crypto\async\arch
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\asn1 $(MD) $(OUTPUT_DIR)\openssl\crypto\asn1
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\aria $(MD) $(OUTPUT_DIR)\openssl\crypto\aria
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\aes $(MD) $(OUTPUT_DIR)\openssl\crypto\aes
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\sm2 $(MD) $(OUTPUT_DIR)\openssl\crypto\sm2
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\sm3 $(MD) $(OUTPUT_DIR)\openssl\crypto\sm3
	-@if not exist $(OUTPUT_DIR)\openssl\crypto\sm4 $(MD) $(OUTPUT_DIR)\openssl\crypto\sm4
	-@if not exist $(OUTPUT_DIR)\openssl\ms $(MD) $(OUTPUT_DIR)\openssl\ms

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\openssl\crypto\aes\aes_cbc.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_cbc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_cbc.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_cfb.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_cfb.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_cfb.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_core.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_core.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_core.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_ecb.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_ecb.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_ecb.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_ige.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_ige.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_ige.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_misc.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_misc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_misc.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_ofb.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_ofb.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_ofb.c

$(OUTPUT_DIR)\openssl\crypto\aes\aes_wrap.obj : $(SOURCE_DIR)\openssl\crypto\aes\aes_wrap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aes\aes_wrap.c

$(OUTPUT_DIR)\openssl\crypto\aria\aria.obj : $(SOURCE_DIR)\openssl\crypto\aria\aria.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\aria\aria.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_bitstr.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_bitstr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_bitstr.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_d2i_fp.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_d2i_fp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_d2i_fp.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_digest.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_digest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_digest.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_dup.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_dup.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_dup.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_gentm.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_gentm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_gentm.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_i2d_fp.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_i2d_fp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_i2d_fp.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_int.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_int.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_int.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_mbstr.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_mbstr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_mbstr.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_object.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_object.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_object.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_octet.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_octet.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_octet.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_print.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_print.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_print.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_sign.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_sign.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_strex.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_strex.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_strex.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_strnid.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_strnid.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_strnid.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_time.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_time.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_time.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_type.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_type.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_type.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_utctm.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_utctm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_utctm.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_utf8.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_utf8.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_utf8.c

$(OUTPUT_DIR)\openssl\crypto\asn1\a_verify.obj : $(SOURCE_DIR)\openssl\crypto\asn1\a_verify.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\a_verify.c

$(OUTPUT_DIR)\openssl\crypto\asn1\ameth_lib.obj : $(SOURCE_DIR)\openssl\crypto\asn1\ameth_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\ameth_lib.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn1_err.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn1_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn1_err.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn1_gen.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn1_gen.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn1_gen.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn1_item_list.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn1_item_list.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn1_item_list.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn1_lib.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn1_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn1_lib.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn1_par.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn1_par.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn1_par.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn_mime.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn_mime.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn_mime.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn_moid.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn_moid.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn_moid.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn_mstbl.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn_mstbl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn_mstbl.c

$(OUTPUT_DIR)\openssl\crypto\asn1\asn_pack.obj : $(SOURCE_DIR)\openssl\crypto\asn1\asn_pack.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\asn_pack.c

$(OUTPUT_DIR)\openssl\crypto\asn1\bio_asn1.obj : $(SOURCE_DIR)\openssl\crypto\asn1\bio_asn1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\bio_asn1.c

$(OUTPUT_DIR)\openssl\crypto\asn1\bio_ndef.obj : $(SOURCE_DIR)\openssl\crypto\asn1\bio_ndef.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\bio_ndef.c

$(OUTPUT_DIR)\openssl\crypto\asn1\d2i_pr.obj : $(SOURCE_DIR)\openssl\crypto\asn1\d2i_pr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\d2i_pr.c

$(OUTPUT_DIR)\openssl\crypto\asn1\d2i_pu.obj : $(SOURCE_DIR)\openssl\crypto\asn1\d2i_pu.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\d2i_pu.c

$(OUTPUT_DIR)\openssl\crypto\asn1\evp_asn1.obj : $(SOURCE_DIR)\openssl\crypto\asn1\evp_asn1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\evp_asn1.c

$(OUTPUT_DIR)\openssl\crypto\asn1\f_int.obj : $(SOURCE_DIR)\openssl\crypto\asn1\f_int.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\f_int.c

$(OUTPUT_DIR)\openssl\crypto\asn1\f_string.obj : $(SOURCE_DIR)\openssl\crypto\asn1\f_string.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\f_string.c

$(OUTPUT_DIR)\openssl\crypto\asn1\i2d_pr.obj : $(SOURCE_DIR)\openssl\crypto\asn1\i2d_pr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\i2d_pr.c

$(OUTPUT_DIR)\openssl\crypto\asn1\i2d_pu.obj : $(SOURCE_DIR)\openssl\crypto\asn1\i2d_pu.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\i2d_pu.c

$(OUTPUT_DIR)\openssl\crypto\asn1\n_pkey.obj : $(SOURCE_DIR)\openssl\crypto\asn1\n_pkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\n_pkey.c

$(OUTPUT_DIR)\openssl\crypto\asn1\nsseq.obj : $(SOURCE_DIR)\openssl\crypto\asn1\nsseq.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\nsseq.c

$(OUTPUT_DIR)\openssl\crypto\asn1\p5_pbe.obj : $(SOURCE_DIR)\openssl\crypto\asn1\p5_pbe.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\p5_pbe.c

$(OUTPUT_DIR)\openssl\crypto\asn1\p5_pbev2.obj : $(SOURCE_DIR)\openssl\crypto\asn1\p5_pbev2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\p5_pbev2.c

$(OUTPUT_DIR)\openssl\crypto\asn1\p5_scrypt.obj : $(SOURCE_DIR)\openssl\crypto\asn1\p5_scrypt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\p5_scrypt.c

$(OUTPUT_DIR)\openssl\crypto\asn1\p8_pkey.obj : $(SOURCE_DIR)\openssl\crypto\asn1\p8_pkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\p8_pkey.c

$(OUTPUT_DIR)\openssl\crypto\asn1\t_bitst.obj : $(SOURCE_DIR)\openssl\crypto\asn1\t_bitst.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\t_bitst.c

$(OUTPUT_DIR)\openssl\crypto\asn1\t_pkey.obj : $(SOURCE_DIR)\openssl\crypto\asn1\t_pkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\t_pkey.c

$(OUTPUT_DIR)\openssl\crypto\asn1\t_spki.obj : $(SOURCE_DIR)\openssl\crypto\asn1\t_spki.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\t_spki.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_dec.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_dec.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_dec.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_enc.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_enc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_enc.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_fre.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_fre.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_fre.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_new.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_new.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_new.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_prn.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_prn.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_scn.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_scn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_scn.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_typ.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_typ.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_typ.c

$(OUTPUT_DIR)\openssl\crypto\asn1\tasn_utl.obj : $(SOURCE_DIR)\openssl\crypto\asn1\tasn_utl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\tasn_utl.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_algor.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_algor.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_algor.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_bignum.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_bignum.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_bignum.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_info.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_info.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_info.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_int64.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_int64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_int64.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_long.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_long.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_long.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_pkey.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_pkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_pkey.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_sig.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_sig.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_sig.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_spki.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_spki.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_spki.c

$(OUTPUT_DIR)\openssl\crypto\asn1\x_val.obj : $(SOURCE_DIR)\openssl\crypto\asn1\x_val.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\asn1\x_val.c

$(OUTPUT_DIR)\openssl\crypto\async\arch\async_null.obj : $(SOURCE_DIR)\openssl\crypto\async\arch\async_null.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\async\arch\async_null.c

$(OUTPUT_DIR)\openssl\crypto\async\arch\async_posix.obj : $(SOURCE_DIR)\openssl\crypto\async\arch\async_posix.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\async\arch\async_posix.c

$(OUTPUT_DIR)\openssl\crypto\async\arch\async_win.obj : $(SOURCE_DIR)\openssl\crypto\async\arch\async_win.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\async\arch\async_win.c

$(OUTPUT_DIR)\openssl\crypto\async\async.obj : $(SOURCE_DIR)\openssl\crypto\async\async.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\async\async.c

$(OUTPUT_DIR)\openssl\crypto\async\async_err.obj : $(SOURCE_DIR)\openssl\crypto\async\async_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\async\async_err.c

$(OUTPUT_DIR)\openssl\crypto\async\async_wait.obj : $(SOURCE_DIR)\openssl\crypto\async\async_wait.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\async\async_wait.c

$(OUTPUT_DIR)\openssl\crypto\bio\b_addr.obj : $(SOURCE_DIR)\openssl\crypto\bio\b_addr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\b_addr.c

$(OUTPUT_DIR)\openssl\crypto\bio\b_dump.obj : $(SOURCE_DIR)\openssl\crypto\bio\b_dump.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\b_dump.c

$(OUTPUT_DIR)\openssl\crypto\bio\b_sock.obj : $(SOURCE_DIR)\openssl\crypto\bio\b_sock.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\b_sock.c

$(OUTPUT_DIR)\openssl\crypto\bio\b_sock2.obj : $(SOURCE_DIR)\openssl\crypto\bio\b_sock2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\b_sock2.c

$(OUTPUT_DIR)\openssl\crypto\bio\bf_buff.obj : $(SOURCE_DIR)\openssl\crypto\bio\bf_buff.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bf_buff.c

$(OUTPUT_DIR)\openssl\crypto\bio\bf_lbuf.obj : $(SOURCE_DIR)\openssl\crypto\bio\bf_lbuf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bf_lbuf.c

$(OUTPUT_DIR)\openssl\crypto\bio\bf_nbio.obj : $(SOURCE_DIR)\openssl\crypto\bio\bf_nbio.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bf_nbio.c

$(OUTPUT_DIR)\openssl\crypto\bio\bf_null.obj : $(SOURCE_DIR)\openssl\crypto\bio\bf_null.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bf_null.c

$(OUTPUT_DIR)\openssl\crypto\bio\bio_cb.obj : $(SOURCE_DIR)\openssl\crypto\bio\bio_cb.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bio_cb.c

$(OUTPUT_DIR)\openssl\crypto\bio\bio_err.obj : $(SOURCE_DIR)\openssl\crypto\bio\bio_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bio_err.c

$(OUTPUT_DIR)\openssl\crypto\bio\bio_lib.obj : $(SOURCE_DIR)\openssl\crypto\bio\bio_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bio_lib.c

$(OUTPUT_DIR)\openssl\crypto\bio\bio_meth.obj : $(SOURCE_DIR)\openssl\crypto\bio\bio_meth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bio_meth.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_acpt.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_acpt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_acpt.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_bio.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_bio.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_bio.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_conn.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_conn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_conn.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_dgram.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_dgram.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_dgram.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_fd.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_fd.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_fd.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_file.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_file.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_file.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_log.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_log.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_log.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_mem.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_mem.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_mem.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_null.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_null.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_null.c

$(OUTPUT_DIR)\openssl\crypto\bio\bss_sock.obj : $(SOURCE_DIR)\openssl\crypto\bio\bss_sock.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bio\bss_sock.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_add.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_add.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_add.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_asm.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_asm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_asm.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_blind.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_blind.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_blind.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_const.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_const.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_const.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_ctx.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_ctx.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_ctx.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_depr.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_depr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_depr.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_dh.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_dh.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_dh.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_div.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_div.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_div.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_err.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_err.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_exp.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_exp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_exp.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_exp2.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_exp2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_exp2.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_gcd.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_gcd.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_gcd.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_gf2m.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_gf2m.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_gf2m.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_intern.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_intern.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_intern.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_kron.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_kron.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_kron.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_lib.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_lib.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_mod.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_mod.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_mod.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_mont.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_mont.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_mont.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_mpi.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_mpi.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_mpi.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_mul.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_mul.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_mul.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_nist.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_nist.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_nist.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_prime.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_prime.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_prime.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_print.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_print.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_print.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_rand.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_rand.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_rand.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_recp.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_recp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_recp.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_shift.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_shift.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_shift.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_sqr.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_sqr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_sqr.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_sqrt.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_sqrt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_sqrt.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_srp.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_srp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_srp.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_word.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_word.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_word.c

$(OUTPUT_DIR)\openssl\crypto\bn\bn_x931p.obj : $(SOURCE_DIR)\openssl\crypto\bn\bn_x931p.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\bn\bn_x931p.c

$(OUTPUT_DIR)\openssl\crypto\buffer\buf_err.obj : $(SOURCE_DIR)\openssl\crypto\buffer\buf_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\buffer\buf_err.c

$(OUTPUT_DIR)\openssl\crypto\buffer\buffer.obj : $(SOURCE_DIR)\openssl\crypto\buffer\buffer.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\buffer\buffer.c

$(OUTPUT_DIR)\openssl\crypto\chacha\chacha_enc.obj : $(SOURCE_DIR)\openssl\crypto\chacha\chacha_enc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\chacha\chacha_enc.c

$(OUTPUT_DIR)\openssl\crypto\cmac\cm_ameth.obj : $(SOURCE_DIR)\openssl\crypto\cmac\cm_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\cmac\cm_ameth.c

$(OUTPUT_DIR)\openssl\crypto\cmac\cm_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\cmac\cm_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\cmac\cm_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\cmac\cmac.obj : $(SOURCE_DIR)\openssl\crypto\cmac\cmac.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\cmac\cmac.c

$(OUTPUT_DIR)\openssl\crypto\comp\c_zlib.obj : $(SOURCE_DIR)\openssl\crypto\comp\c_zlib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\comp\c_zlib.c

$(OUTPUT_DIR)\openssl\crypto\comp\comp_err.obj : $(SOURCE_DIR)\openssl\crypto\comp\comp_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\comp\comp_err.c

$(OUTPUT_DIR)\openssl\crypto\comp\comp_lib.obj : $(SOURCE_DIR)\openssl\crypto\comp\comp_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\comp\comp_lib.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_api.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_api.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_api.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_def.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_def.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_def.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_err.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_err.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_lib.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_lib.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_mall.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_mall.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_mall.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_mod.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_mod.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_mod.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_sap.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_sap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_sap.c

$(OUTPUT_DIR)\openssl\crypto\conf\conf_ssl.obj : $(SOURCE_DIR)\openssl\crypto\conf\conf_ssl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\conf\conf_ssl.c

$(OUTPUT_DIR)\openssl\crypto\cpt_err.obj : $(SOURCE_DIR)\openssl\crypto\cpt_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\cpt_err.c

$(OUTPUT_DIR)\openssl\crypto\cryptlib.obj : $(SOURCE_DIR)\openssl\crypto\cryptlib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\cryptlib.c

$(OUTPUT_DIR)\openssl\crypto\ctype.obj : $(SOURCE_DIR)\openssl\crypto\ctype.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ctype.c

$(OUTPUT_DIR)\openssl\crypto\cversion.obj : $(SOURCE_DIR)\openssl\crypto\cversion.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\cversion.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_ameth.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_ameth.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_asn1.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_asn1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_asn1.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_check.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_check.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_check.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_depr.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_depr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_depr.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_err.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_err.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_gen.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_gen.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_gen.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_kdf.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_kdf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_kdf.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_key.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_key.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_key.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_lib.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_lib.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_meth.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_meth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_meth.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_prn.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_prn.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_rfc5114.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_rfc5114.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_rfc5114.c

$(OUTPUT_DIR)\openssl\crypto\dh\dh_rfc7919.obj : $(SOURCE_DIR)\openssl\crypto\dh\dh_rfc7919.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dh\dh_rfc7919.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_dl.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_dl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_dl.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_dlfcn.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_dlfcn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_dlfcn.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_err.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_err.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_lib.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_lib.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_openssl.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_openssl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_openssl.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_vms.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_vms.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_vms.c

$(OUTPUT_DIR)\openssl\crypto\dso\dso_win32.obj : $(SOURCE_DIR)\openssl\crypto\dso\dso_win32.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\dso\dso_win32.c

$(OUTPUT_DIR)\openssl\crypto\ebcdic.obj : $(SOURCE_DIR)\openssl\crypto\ebcdic.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ebcdic.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve25519.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve25519.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve25519.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve448\arch_32\f_impl.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve448\arch_32\f_impl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve448\arch_32\f_impl.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve448\curve448.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve448\curve448.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve448\curve448.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve448\curve448_tables.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve448\curve448_tables.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve448\curve448_tables.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve448\eddsa.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve448\eddsa.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve448\eddsa.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve448\f_generic.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve448\f_generic.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve448\f_generic.c

$(OUTPUT_DIR)\openssl\crypto\ec\curve448\scalar.obj : $(SOURCE_DIR)\openssl\crypto\ec\curve448\scalar.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\curve448\scalar.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec2_oct.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec2_oct.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec2_oct.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec2_smpl.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec2_smpl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec2_smpl.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_ameth.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_ameth.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_asn1.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_asn1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_asn1.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_check.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_check.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_check.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_curve.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_curve.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_curve.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_cvt.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_cvt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_cvt.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_err.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_err.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_key.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_key.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_key.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_kmeth.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_kmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_kmeth.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_lib.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_lib.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_mult.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_mult.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_mult.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_oct.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_oct.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_oct.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\ec\ec_print.obj : $(SOURCE_DIR)\openssl\crypto\ec\ec_print.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ec_print.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecdh_kdf.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecdh_kdf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecdh_kdf.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecdh_ossl.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecdh_ossl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecdh_ossl.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecdsa_ossl.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecdsa_ossl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecdsa_ossl.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecdsa_sign.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecdsa_sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecdsa_sign.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecdsa_vrf.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecdsa_vrf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecdsa_vrf.c

$(OUTPUT_DIR)\openssl\crypto\ec\eck_prn.obj : $(SOURCE_DIR)\openssl\crypto\ec\eck_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\eck_prn.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_mont.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_mont.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_mont.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_nist.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_nist.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_nist.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistp224.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp224.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp224.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistp256.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp256.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistp521.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp521.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp521.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_nistputil.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistputil.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_nistputil.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_oct.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_oct.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_oct.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecp_smpl.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecp_smpl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecp_smpl.c

$(OUTPUT_DIR)\openssl\crypto\ec\ecx_meth.obj : $(SOURCE_DIR)\openssl\crypto\ec\ecx_meth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ec\ecx_meth.c

$(OUTPUT_DIR)\openssl\crypto\err\err.obj : $(SOURCE_DIR)\openssl\crypto\err\err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\err\err.c

$(OUTPUT_DIR)\openssl\crypto\err\err_prn.obj : $(SOURCE_DIR)\openssl\crypto\err\err_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\err\err_prn.c

$(OUTPUT_DIR)\openssl\crypto\evp\bio_b64.obj : $(SOURCE_DIR)\openssl\crypto\evp\bio_b64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\bio_b64.c

$(OUTPUT_DIR)\openssl\crypto\evp\bio_enc.obj : $(SOURCE_DIR)\openssl\crypto\evp\bio_enc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\bio_enc.c

$(OUTPUT_DIR)\openssl\crypto\evp\bio_md.obj : $(SOURCE_DIR)\openssl\crypto\evp\bio_md.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\bio_md.c

$(OUTPUT_DIR)\openssl\crypto\evp\bio_ok.obj : $(SOURCE_DIR)\openssl\crypto\evp\bio_ok.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\bio_ok.c

$(OUTPUT_DIR)\openssl\crypto\evp\c_allc.obj : $(SOURCE_DIR)\openssl\crypto\evp\c_allc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\c_allc.c

$(OUTPUT_DIR)\openssl\crypto\evp\c_alld.obj : $(SOURCE_DIR)\openssl\crypto\evp\c_alld.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\c_alld.c

$(OUTPUT_DIR)\openssl\crypto\evp\cmeth_lib.obj : $(SOURCE_DIR)\openssl\crypto\evp\cmeth_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\cmeth_lib.c

$(OUTPUT_DIR)\openssl\crypto\evp\digest.obj : $(SOURCE_DIR)\openssl\crypto\evp\digest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\digest.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_aes.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_aes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_aes.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_aes_cbc_hmac_sha256.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_aes_cbc_hmac_sha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_aes_cbc_hmac_sha256.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_aria.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_aria.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_aria.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_bf.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_bf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_bf.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_camellia.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_camellia.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_camellia.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_cast.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_cast.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_cast.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_chacha20_poly1305.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_chacha20_poly1305.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_chacha20_poly1305.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_null.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_null.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_null.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_old.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_old.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_old.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_seed.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_seed.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_seed.c

$(OUTPUT_DIR)\openssl\crypto\evp\e_xcbc_d.obj : $(SOURCE_DIR)\openssl\crypto\evp\e_xcbc_d.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\e_xcbc_d.c

$(OUTPUT_DIR)\openssl\crypto\evp\encode.obj : $(SOURCE_DIR)\openssl\crypto\evp\encode.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\encode.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_cnf.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_cnf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_cnf.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_enc.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_enc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_enc.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_err.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_err.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_key.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_key.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_key.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_lib.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_lib.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_pbe.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_pbe.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_pbe.c

$(OUTPUT_DIR)\openssl\crypto\evp\evp_pkey.obj : $(SOURCE_DIR)\openssl\crypto\evp\evp_pkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\evp_pkey.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_md5.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_md5.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_md5.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_mdc2.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_mdc2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_mdc2.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_null.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_null.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_null.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_ripemd.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_ripemd.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_ripemd.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_sha1.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_sha1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_sha1.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_sha3.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_sha3.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_sha3.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_sigver.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_sigver.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_sigver.c

$(OUTPUT_DIR)\openssl\crypto\evp\m_wp.obj : $(SOURCE_DIR)\openssl\crypto\evp\m_wp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\m_wp.c

$(OUTPUT_DIR)\openssl\crypto\evp\names.obj : $(SOURCE_DIR)\openssl\crypto\evp\names.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\names.c

$(OUTPUT_DIR)\openssl\crypto\evp\p5_crpt.obj : $(SOURCE_DIR)\openssl\crypto\evp\p5_crpt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p5_crpt.c

$(OUTPUT_DIR)\openssl\crypto\evp\p5_crpt2.obj : $(SOURCE_DIR)\openssl\crypto\evp\p5_crpt2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p5_crpt2.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_dec.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_dec.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_dec.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_enc.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_enc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_enc.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_lib.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_lib.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_open.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_open.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_open.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_seal.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_seal.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_seal.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_sign.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_sign.c

$(OUTPUT_DIR)\openssl\crypto\evp\p_verify.obj : $(SOURCE_DIR)\openssl\crypto\evp\p_verify.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\p_verify.c

$(OUTPUT_DIR)\openssl\crypto\evp\pbe_scrypt.obj : $(SOURCE_DIR)\openssl\crypto\evp\pbe_scrypt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\pbe_scrypt.c

$(OUTPUT_DIR)\openssl\crypto\evp\pmeth_fn.obj : $(SOURCE_DIR)\openssl\crypto\evp\pmeth_fn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\pmeth_fn.c

$(OUTPUT_DIR)\openssl\crypto\evp\pmeth_gn.obj : $(SOURCE_DIR)\openssl\crypto\evp\pmeth_gn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\pmeth_gn.c

$(OUTPUT_DIR)\openssl\crypto\evp\pmeth_lib.obj : $(SOURCE_DIR)\openssl\crypto\evp\pmeth_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\evp\pmeth_lib.c

$(OUTPUT_DIR)\openssl\crypto\ex_data.obj : $(SOURCE_DIR)\openssl\crypto\ex_data.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ex_data.c

$(OUTPUT_DIR)\openssl\crypto\getenv.obj : $(SOURCE_DIR)\openssl\crypto\getenv.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\getenv.c

$(OUTPUT_DIR)\openssl\crypto\hmac\hm_ameth.obj : $(SOURCE_DIR)\openssl\crypto\hmac\hm_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\hmac\hm_ameth.c

$(OUTPUT_DIR)\openssl\crypto\hmac\hm_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\hmac\hm_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\hmac\hm_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\hmac\hmac.obj : $(SOURCE_DIR)\openssl\crypto\hmac\hmac.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\hmac\hmac.c

$(OUTPUT_DIR)\openssl\crypto\init.obj : $(SOURCE_DIR)\openssl\crypto\init.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\init.c

$(OUTPUT_DIR)\openssl\crypto\kdf\hkdf.obj : $(SOURCE_DIR)\openssl\crypto\kdf\hkdf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\kdf\hkdf.c

$(OUTPUT_DIR)\openssl\crypto\kdf\kdf_err.obj : $(SOURCE_DIR)\openssl\crypto\kdf\kdf_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\kdf\kdf_err.c

$(OUTPUT_DIR)\openssl\crypto\kdf\scrypt.obj : $(SOURCE_DIR)\openssl\crypto\kdf\scrypt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\kdf\scrypt.c

$(OUTPUT_DIR)\openssl\crypto\kdf\tls1_prf.obj : $(SOURCE_DIR)\openssl\crypto\kdf\tls1_prf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\kdf\tls1_prf.c

$(OUTPUT_DIR)\openssl\crypto\lhash\lh_stats.obj : $(SOURCE_DIR)\openssl\crypto\lhash\lh_stats.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\lhash\lh_stats.c

$(OUTPUT_DIR)\openssl\crypto\lhash\lhash.obj : $(SOURCE_DIR)\openssl\crypto\lhash\lhash.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\lhash\lhash.c

$(OUTPUT_DIR)\openssl\crypto\md5\md5_dgst.obj : $(SOURCE_DIR)\openssl\crypto\md5\md5_dgst.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\md5\md5_dgst.c

$(OUTPUT_DIR)\openssl\crypto\md5\md5_one.obj : $(SOURCE_DIR)\openssl\crypto\md5\md5_one.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\md5\md5_one.c

$(OUTPUT_DIR)\openssl\crypto\mem.obj : $(SOURCE_DIR)\openssl\crypto\mem.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\mem.c

$(OUTPUT_DIR)\openssl\crypto\mem_clr.obj : $(SOURCE_DIR)\openssl\crypto\mem_clr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\mem_clr.c

$(OUTPUT_DIR)\openssl\crypto\mem_dbg.obj : $(SOURCE_DIR)\openssl\crypto\mem_dbg.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\mem_dbg.c

$(OUTPUT_DIR)\openssl\crypto\mem_sec.obj : $(SOURCE_DIR)\openssl\crypto\mem_sec.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\mem_sec.c

$(OUTPUT_DIR)\openssl\crypto\modes\cbc128.obj : $(SOURCE_DIR)\openssl\crypto\modes\cbc128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\cbc128.c

$(OUTPUT_DIR)\openssl\crypto\modes\ccm128.obj : $(SOURCE_DIR)\openssl\crypto\modes\ccm128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\ccm128.c

$(OUTPUT_DIR)\openssl\crypto\modes\cfb128.obj : $(SOURCE_DIR)\openssl\crypto\modes\cfb128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\cfb128.c

$(OUTPUT_DIR)\openssl\crypto\modes\ctr128.obj : $(SOURCE_DIR)\openssl\crypto\modes\ctr128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\ctr128.c

$(OUTPUT_DIR)\openssl\crypto\modes\cts128.obj : $(SOURCE_DIR)\openssl\crypto\modes\cts128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\cts128.c

$(OUTPUT_DIR)\openssl\crypto\modes\gcm128.obj : $(SOURCE_DIR)\openssl\crypto\modes\gcm128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\gcm128.c

$(OUTPUT_DIR)\openssl\crypto\modes\ocb128.obj : $(SOURCE_DIR)\openssl\crypto\modes\ocb128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\ocb128.c

$(OUTPUT_DIR)\openssl\crypto\modes\ofb128.obj : $(SOURCE_DIR)\openssl\crypto\modes\ofb128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\ofb128.c

$(OUTPUT_DIR)\openssl\crypto\modes\wrap128.obj : $(SOURCE_DIR)\openssl\crypto\modes\wrap128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\wrap128.c

$(OUTPUT_DIR)\openssl\crypto\modes\xts128.obj : $(SOURCE_DIR)\openssl\crypto\modes\xts128.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\modes\xts128.c

$(OUTPUT_DIR)\openssl\crypto\o_dir.obj : $(SOURCE_DIR)\openssl\crypto\o_dir.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\o_dir.c

$(OUTPUT_DIR)\openssl\crypto\o_fips.obj : $(SOURCE_DIR)\openssl\crypto\o_fips.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\o_fips.c

$(OUTPUT_DIR)\openssl\crypto\o_fopen.obj : $(SOURCE_DIR)\openssl\crypto\o_fopen.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\o_fopen.c

$(OUTPUT_DIR)\openssl\crypto\o_init.obj : $(SOURCE_DIR)\openssl\crypto\o_init.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\o_init.c

$(OUTPUT_DIR)\openssl\crypto\o_str.obj : $(SOURCE_DIR)\openssl\crypto\o_str.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\o_str.c

$(OUTPUT_DIR)\openssl\crypto\o_time.obj : $(SOURCE_DIR)\openssl\crypto\o_time.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\o_time.c

$(OUTPUT_DIR)\openssl\crypto\objects\o_names.obj : $(SOURCE_DIR)\openssl\crypto\objects\o_names.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\objects\o_names.c

$(OUTPUT_DIR)\openssl\crypto\objects\obj_dat.obj : $(SOURCE_DIR)\openssl\crypto\objects\obj_dat.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\objects\obj_dat.c

$(OUTPUT_DIR)\openssl\crypto\objects\obj_err.obj : $(SOURCE_DIR)\openssl\crypto\objects\obj_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\objects\obj_err.c

$(OUTPUT_DIR)\openssl\crypto\objects\obj_lib.obj : $(SOURCE_DIR)\openssl\crypto\objects\obj_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\objects\obj_lib.c

$(OUTPUT_DIR)\openssl\crypto\objects\obj_xref.obj : $(SOURCE_DIR)\openssl\crypto\objects\obj_xref.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\objects\obj_xref.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_asn.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_asn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_asn.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_cl.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_cl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_cl.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_err.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_err.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_ext.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_ext.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_ext.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_ht.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_ht.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_ht.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_lib.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_lib.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_prn.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_prn.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_srv.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_srv.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_srv.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\ocsp_vfy.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_vfy.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_vfy.c

$(OUTPUT_DIR)\openssl\crypto\ocsp\v3_ocsp.obj : $(SOURCE_DIR)\openssl\crypto\ocsp\v3_ocsp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ocsp\v3_ocsp.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_all.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_all.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_all.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_err.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_err.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_info.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_info.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_info.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_lib.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_lib.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_oth.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_oth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_oth.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_pk8.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_pk8.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_pk8.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_pkey.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_pkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_pkey.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_sign.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_sign.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_x509.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_x509.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_x509.c

$(OUTPUT_DIR)\openssl\crypto\pem\pem_xaux.obj : $(SOURCE_DIR)\openssl\crypto\pem\pem_xaux.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pem_xaux.c

$(OUTPUT_DIR)\openssl\crypto\pem\pvkfmt.obj : $(SOURCE_DIR)\openssl\crypto\pem\pvkfmt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pem\pvkfmt.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_add.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_add.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_add.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_asn.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_asn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_asn.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_attr.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_attr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_attr.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_crpt.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_crpt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_crpt.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_crt.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_crt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_crt.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_decr.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_decr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_decr.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_init.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_init.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_init.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_key.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_key.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_key.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_kiss.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_kiss.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_kiss.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_mutl.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_mutl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_mutl.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_npas.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_npas.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_npas.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_p8d.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_p8d.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_p8d.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_p8e.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_p8e.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_p8e.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_sbag.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_sbag.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_sbag.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\p12_utl.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_utl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\p12_utl.c

$(OUTPUT_DIR)\openssl\crypto\pkcs12\pk12err.obj : $(SOURCE_DIR)\openssl\crypto\pkcs12\pk12err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs12\pk12err.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\bio_pk7.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\bio_pk7.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\bio_pk7.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_asn1.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_asn1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_asn1.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_attr.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_attr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_attr.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_doit.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_doit.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_doit.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_lib.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_lib.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_mime.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_mime.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_mime.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pk7_smime.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_smime.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_smime.c

$(OUTPUT_DIR)\openssl\crypto\pkcs7\pkcs7err.obj : $(SOURCE_DIR)\openssl\crypto\pkcs7\pkcs7err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\pkcs7\pkcs7err.c

$(OUTPUT_DIR)\openssl\crypto\poly1305\poly1305.obj : $(SOURCE_DIR)\openssl\crypto\poly1305\poly1305.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\poly1305\poly1305.c

$(OUTPUT_DIR)\openssl\crypto\poly1305\poly1305_ameth.obj : $(SOURCE_DIR)\openssl\crypto\poly1305\poly1305_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\poly1305\poly1305_ameth.c

$(OUTPUT_DIR)\openssl\crypto\poly1305\poly1305_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\poly1305\poly1305_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\poly1305\poly1305_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\rand\drbg_ctr.obj : $(SOURCE_DIR)\openssl\crypto\rand\drbg_ctr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\drbg_ctr.c

$(OUTPUT_DIR)\openssl\crypto\rand\drbg_lib.obj : $(SOURCE_DIR)\openssl\crypto\rand\drbg_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\drbg_lib.c

$(OUTPUT_DIR)\openssl\crypto\rand\rand_egd.obj : $(SOURCE_DIR)\openssl\crypto\rand\rand_egd.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\rand_egd.c

$(OUTPUT_DIR)\openssl\crypto\rand\rand_err.obj : $(SOURCE_DIR)\openssl\crypto\rand\rand_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\rand_err.c

$(OUTPUT_DIR)\openssl\crypto\rand\rand_lib.obj : $(SOURCE_DIR)\openssl\crypto\rand\rand_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\rand_lib.c

$(OUTPUT_DIR)\openssl\crypto\rand\rand_unix.obj : $(SOURCE_DIR)\openssl\crypto\rand\rand_unix.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\rand_unix.c

$(OUTPUT_DIR)\openssl\crypto\rand\rand_vms.obj : $(SOURCE_DIR)\openssl\crypto\rand\rand_vms.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\rand_vms.c

$(OUTPUT_DIR)\openssl\crypto\rand\rand_win.obj : $(SOURCE_DIR)\openssl\crypto\rand\rand_win.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rand\rand_win.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_ameth.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_ameth.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_asn1.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_asn1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_asn1.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_chk.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_chk.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_chk.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_crpt.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_crpt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_crpt.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_depr.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_depr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_depr.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_err.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_err.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_gen.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_gen.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_gen.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_lib.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_lib.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_meth.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_meth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_meth.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_mp.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_mp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_mp.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_none.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_none.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_none.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_oaep.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_oaep.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_oaep.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_ossl.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_ossl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_ossl.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_pk1.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_pk1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_pk1.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_prn.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_prn.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_pss.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_pss.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_pss.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_saos.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_saos.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_saos.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_sign.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_sign.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_ssl.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_ssl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_ssl.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_x931.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_x931.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_x931.c

$(OUTPUT_DIR)\openssl\crypto\rsa\rsa_x931g.obj : $(SOURCE_DIR)\openssl\crypto\rsa\rsa_x931g.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\rsa\rsa_x931g.c

$(OUTPUT_DIR)\openssl\crypto\sha\keccak1600.obj : $(SOURCE_DIR)\openssl\crypto\sha\keccak1600.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sha\keccak1600.c

$(OUTPUT_DIR)\openssl\crypto\sha\sha1_one.obj : $(SOURCE_DIR)\openssl\crypto\sha\sha1_one.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sha\sha1_one.c

$(OUTPUT_DIR)\openssl\crypto\sha\sha1dgst.obj : $(SOURCE_DIR)\openssl\crypto\sha\sha1dgst.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sha\sha1dgst.c

$(OUTPUT_DIR)\openssl\crypto\sha\sha256.obj : $(SOURCE_DIR)\openssl\crypto\sha\sha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sha\sha256.c

$(OUTPUT_DIR)\openssl\crypto\sha\sha512.obj : $(SOURCE_DIR)\openssl\crypto\sha\sha512.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sha\sha512.c

$(OUTPUT_DIR)\openssl\crypto\siphash\siphash.obj : $(SOURCE_DIR)\openssl\crypto\siphash\siphash.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\siphash\siphash.c

$(OUTPUT_DIR)\openssl\crypto\siphash\siphash_ameth.obj : $(SOURCE_DIR)\openssl\crypto\siphash\siphash_ameth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\siphash\siphash_ameth.c

$(OUTPUT_DIR)\openssl\crypto\siphash\siphash_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\siphash\siphash_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\siphash\siphash_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\stack\stack.obj : $(SOURCE_DIR)\openssl\crypto\stack\stack.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\stack\stack.c

$(OUTPUT_DIR)\openssl\crypto\threads_none.obj : $(SOURCE_DIR)\openssl\crypto\threads_none.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\threads_none.c

$(OUTPUT_DIR)\openssl\crypto\threads_pthread.obj : $(SOURCE_DIR)\openssl\crypto\threads_pthread.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\threads_pthread.c

$(OUTPUT_DIR)\openssl\crypto\threads_win.obj : $(SOURCE_DIR)\openssl\crypto\threads_win.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\threads_win.c

$(OUTPUT_DIR)\openssl\crypto\txt_db\txt_db.obj : $(SOURCE_DIR)\openssl\crypto\txt_db\txt_db.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\txt_db\txt_db.c

$(OUTPUT_DIR)\openssl\crypto\ui\ui_err.obj : $(SOURCE_DIR)\openssl\crypto\ui\ui_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ui\ui_err.c

$(OUTPUT_DIR)\openssl\crypto\ui\ui_lib.obj : $(SOURCE_DIR)\openssl\crypto\ui\ui_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ui\ui_lib.c

$(OUTPUT_DIR)\openssl\crypto\ui\ui_null.obj : $(SOURCE_DIR)\openssl\crypto\ui\ui_null.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ui\ui_null.c

$(OUTPUT_DIR)\openssl\crypto\ui\ui_openssl.obj : $(SOURCE_DIR)\openssl\crypto\ui\ui_openssl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ui\ui_openssl.c

$(OUTPUT_DIR)\openssl\crypto\ui\ui_util.obj : $(SOURCE_DIR)\openssl\crypto\ui\ui_util.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\ui\ui_util.c

$(OUTPUT_DIR)\openssl\crypto\uid.obj : $(SOURCE_DIR)\openssl\crypto\uid.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\uid.c

$(OUTPUT_DIR)\openssl\crypto\x509\by_dir.obj : $(SOURCE_DIR)\openssl\crypto\x509\by_dir.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\by_dir.c

$(OUTPUT_DIR)\openssl\crypto\x509\by_file.obj : $(SOURCE_DIR)\openssl\crypto\x509\by_file.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\by_file.c

$(OUTPUT_DIR)\openssl\crypto\x509\t_crl.obj : $(SOURCE_DIR)\openssl\crypto\x509\t_crl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\t_crl.c

$(OUTPUT_DIR)\openssl\crypto\x509\t_req.obj : $(SOURCE_DIR)\openssl\crypto\x509\t_req.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\t_req.c

$(OUTPUT_DIR)\openssl\crypto\x509\t_x509.obj : $(SOURCE_DIR)\openssl\crypto\x509\t_x509.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\t_x509.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_att.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_att.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_att.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_cmp.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_cmp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_cmp.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_d2.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_d2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_d2.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_def.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_def.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_def.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_err.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_err.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_ext.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_ext.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_ext.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_lu.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_lu.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_lu.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_meth.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_meth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_meth.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_obj.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_obj.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_obj.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_r2x.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_r2x.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_r2x.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_req.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_req.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_req.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_set.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_set.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_set.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_trs.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_trs.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_trs.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_txt.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_txt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_txt.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_v3.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_v3.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_v3.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_vfy.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_vfy.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_vfy.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509_vpm.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509_vpm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509_vpm.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509cset.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509cset.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509cset.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509name.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509name.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509name.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509rset.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509rset.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509rset.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509spki.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509spki.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509spki.c

$(OUTPUT_DIR)\openssl\crypto\x509\x509type.obj : $(SOURCE_DIR)\openssl\crypto\x509\x509type.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x509type.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_all.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_all.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_all.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_attrib.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_attrib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_attrib.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_crl.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_crl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_crl.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_exten.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_exten.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_exten.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_name.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_name.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_name.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_pubkey.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_pubkey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_pubkey.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_req.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_req.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_req.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_x509.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_x509.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_x509.c

$(OUTPUT_DIR)\openssl\crypto\x509\x_x509a.obj : $(SOURCE_DIR)\openssl\crypto\x509\x_x509a.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509\x_x509a.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_cache.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_cache.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_cache.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_data.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_data.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_data.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_lib.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_lib.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_map.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_map.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_map.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_node.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_node.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_node.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\pcy_tree.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_tree.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\pcy_tree.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_addr.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_addr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_addr.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_admis.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_admis.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_admis.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_akey.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_akey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_akey.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_akeya.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_akeya.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_akeya.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_alt.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_alt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_alt.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_asid.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_asid.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_asid.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_bcons.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_bcons.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_bcons.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_bitst.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_bitst.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_bitst.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_conf.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_conf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_conf.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_cpols.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_cpols.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_cpols.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_crld.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_crld.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_crld.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_enum.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_enum.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_enum.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_extku.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_extku.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_extku.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_genn.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_genn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_genn.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_ia5.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_ia5.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_ia5.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_info.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_info.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_info.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_int.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_int.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_int.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_lib.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_lib.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_lib.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_ncons.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_ncons.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_ncons.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pci.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pci.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pci.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pcia.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pcia.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pcia.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pcons.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pcons.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pcons.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pku.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pku.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pku.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_pmaps.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pmaps.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_pmaps.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_prn.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_prn.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_prn.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_purp.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_purp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_purp.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_skey.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_skey.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_skey.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_sxnet.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_sxnet.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_sxnet.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_tlsf.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_tlsf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_tlsf.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3_utl.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3_utl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3_utl.c

$(OUTPUT_DIR)\openssl\crypto\x509v3\v3err.obj : $(SOURCE_DIR)\openssl\crypto\x509v3\v3err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\x509v3\v3err.c

$(OUTPUT_DIR)\openssl\crypto\sm2\sm2_crypt.obj : $(SOURCE_DIR)\openssl\crypto\sm2\sm2_crypt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm2\sm2_crypt.c

$(OUTPUT_DIR)\openssl\crypto\sm2\sm2_err.obj : $(SOURCE_DIR)\openssl\crypto\sm2\sm2_err.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm2\sm2_err.c

$(OUTPUT_DIR)\openssl\crypto\sm2\sm2_pmeth.obj : $(SOURCE_DIR)\openssl\crypto\sm2\sm2_pmeth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm2\sm2_pmeth.c

$(OUTPUT_DIR)\openssl\crypto\sm2\sm2_sign.obj : $(SOURCE_DIR)\openssl\crypto\sm2\sm2_sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm2\sm2_sign.c

$(OUTPUT_DIR)\openssl\crypto\sm3\m_sm3.obj : $(SOURCE_DIR)\openssl\crypto\sm3\m_sm3.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm3\m_sm3.c

$(OUTPUT_DIR)\openssl\crypto\sm3\sm3.obj : $(SOURCE_DIR)\openssl\crypto\sm3\sm3.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm3\sm3.c

$(OUTPUT_DIR)\openssl\crypto\sm4\sm4.obj : $(SOURCE_DIR)\openssl\crypto\sm4\sm4.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\openssl\crypto\sm4\sm4.c

$(OUTPUT_DIR)\ossl_store.obj : $(SOURCE_DIR)\ossl_store.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\ossl_store.c

$(OUTPUT_DIR)\rand_pool.obj : $(SOURCE_DIR)\rand_pool.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\rand_pool.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_1_FILES) \
                                   $(OBJECT_2_FILES) \
                                   $(OBJECT_3_A_FILES) \
                                   $(OBJECT_3_B_FILES) \
                                   $(OBJECT_4_FILES) \
                                   $(OBJECT_5_FILES) \
                                   $(OBJECT_6_FILES) \
                                   $(OBJECT_7_FILES) \
                                   $(OBJECT_8_FILES) \
                                   $(OBJECT_9_FILES) \
                                   $(OBJECT_10_FILES) \
                                   $(OBJECT_11_FILES) \
                                   $(OBJECT_12_FILES) \
                                   $(OBJECT_13_FILES) \
                                   $(OBJECT_14_FILES) \
                                   $(OBJECT_15_FILES) \
                                   $(OBJECT_16_FILES) \
                                   $(OBJECT_17_A_FILES) \
                                   $(OBJECT_17_B_FILES) \
                                   $(OBJECT_18_FILES) \
                                   $(OBJECT_19_FILES) \
                                   $(OBJECT_20_FILES) \
                                   $(OBJECT_21_FILES) \
                                   $(OBJECT_22_FILES) \
                                   $(OBJECT_23_FILES) \
                                   $(OBJECT_24_FILES) \
                                   $(OBJECT_25_FILES) \
                                   $(OBJECT_26_FILES) \
                                   $(OBJECT_27_FILES) \
                                   $(OBJECT_28_FILES) \
                                   $(OBJECT_29_FILES) \
                                   $(OBJECT_30_FILES) \
                                   $(OBJECT_31_FILES) \
                                   $(OBJECT_32_FILES) \
                                   $(OBJECT_33_FILES) \
                                   $(OBJECT_34_FILES) \
                                   $(OBJECT_35_FILES) \
                                   $(OBJECT_36_FILES) \
                                   $(OBJECT_37_FILES) \
                                   $(OBJECT_38_FILES) \
                                   $(OBJECT_39_FILES)
    echo  $(OBJECT_1_FILES) > $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_2_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_3_A_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_3_B_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_4_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_5_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_6_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_7_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_8_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_9_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_10_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_11_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_12_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_13_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_14_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_15_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_16_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_17_A_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_17_B_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_18_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_19_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_20_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_21_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_22_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_23_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_24_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_25_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_26_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_27_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_28_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_29_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_30_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_31_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_32_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_33_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_34_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_35_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_36_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_37_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_38_FILES) >> $(OUTPUT_DIR)\object_files.lst
    echo  $(OBJECT_39_FILES) >> $(OUTPUT_DIR)\object_files.lst
    $(SLINK) $(SLINK_FLAGS) @$(OUTPUT_DIR)\object_files.lst $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


