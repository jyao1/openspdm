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

OPENSSL_FLAGS = -DL_ENDIAN -DOPENSSL_SMALL_FOOTPRINT -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -DOPENSSL_SYS_UEFI=1
CC_FLAGS = $(CC_FLAGS) -U_WIN32 -U_WIN64 -U_MSC_VER $(OPENSSL_FLAGS) /FIBase.h /wd4090 /wd4132 /wd4244 /wd4245 /wd4267 /wd4306 /wd4310 /wd4700 /wd4389 /wd4702 /wd4706 /wd4819

#
# Build Macro
#
SOURCE_1_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_ofb.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_misc.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_cfb.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_ecb.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_ige.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_cbc.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_wrap.c \
	$(SOURCE_DIR)\openssl\crypto\aes\aes_core.c \


SOURCE_2_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\aria\aria.c \


SOURCE_3_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\asn1\t_bitst.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_gentm.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\p8_pkey.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_new.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_dup.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_i2d_fp.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_object.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_val.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn1_par.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_spki.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_type.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_int.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_print.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_info.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_scn.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_utctm.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn1_err.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn1_item_list.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_dec.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\nsseq.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_mbstr.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn_pack.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\evp_asn1.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn1_gen.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_pkey.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_int64.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn_mime.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\i2d_pr.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\d2i_pr.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn_moid.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\i2d_pu.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_fre.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\t_spki.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\bio_ndef.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_long.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_enc.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\n_pkey.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_strnid.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\p5_pbev2.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\p5_scrypt.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_d2i_fp.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\bio_asn1.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_utl.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_sign.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\f_int.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_bignum.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\ameth_lib.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn1_lib.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_typ.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_digest.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\asn_mstbl.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_sig.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_verify.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_octet.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_time.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\tasn_prn.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_strex.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\d2i_pu.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\x_algor.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_bitstr.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\f_string.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\a_utf8.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\p5_pbe.c \
	$(SOURCE_DIR)\openssl\crypto\asn1\t_pkey.c \


SOURCE_4_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\async\arch\async_win.c \
	$(SOURCE_DIR)\openssl\crypto\async\arch\async_posix.c \
	$(SOURCE_DIR)\openssl\crypto\async\arch\async_null.c \
	$(SOURCE_DIR)\openssl\crypto\async\async_err.c \
	$(SOURCE_DIR)\openssl\crypto\async\async.c \
	$(SOURCE_DIR)\openssl\crypto\async\async_wait.c \


SOURCE_5_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_sock.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bf_nbio.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_dgram.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_null.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bf_null.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_log.c \
	$(SOURCE_DIR)\openssl\crypto\bio\b_sock2.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_bio.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_fd.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_file.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bio_meth.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bio_err.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_conn.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bio_cb.c \
	$(SOURCE_DIR)\openssl\crypto\bio\b_addr.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bio_lib.c \
	$(SOURCE_DIR)\openssl\crypto\bio\b_sock.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_acpt.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bf_buff.c \
	$(SOURCE_DIR)\openssl\crypto\bio\b_dump.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bss_mem.c \
	$(SOURCE_DIR)\openssl\crypto\bio\bf_lbuf.c \


SOURCE_6_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_intern.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_rand.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_blind.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_err.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_sqrt.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_gcd.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_mul.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_asm.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_kron.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_add.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_const.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_gf2m.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_recp.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_prime.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_div.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_sqr.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_exp.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_mpi.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_nist.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_dh.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_ctx.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_x931p.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_mod.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_srp.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_lib.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_mont.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_depr.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_exp2.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_shift.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_word.c \
	$(SOURCE_DIR)\openssl\crypto\bn\bn_print.c \


SOURCE_7_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\buffer\buffer.c \
	$(SOURCE_DIR)\openssl\crypto\buffer\buf_err.c \


SOURCE_8_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\chacha\chacha_enc.c \


SOURCE_9_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\cmac\cm_pmeth.c \
	$(SOURCE_DIR)\openssl\crypto\cmac\cmac.c \
	$(SOURCE_DIR)\openssl\crypto\cmac\cm_ameth.c \


SOURCE_10_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\comp\c_zlib.c \
	$(SOURCE_DIR)\openssl\crypto\comp\comp_lib.c \
	$(SOURCE_DIR)\openssl\crypto\comp\comp_err.c \


SOURCE_11_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_lib.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_def.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_err.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_ssl.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_sap.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_mall.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_mod.c \
	$(SOURCE_DIR)\openssl\crypto\conf\conf_api.c \


SOURCE_12_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\o_dir.c \
	$(SOURCE_DIR)\openssl\crypto\ctype.c \
	$(SOURCE_DIR)\openssl\crypto\o_time.c \
	$(SOURCE_DIR)\openssl\crypto\uid.c \
	$(SOURCE_DIR)\openssl\crypto\o_fopen.c \
	$(SOURCE_DIR)\openssl\crypto\ex_data.c \
	$(SOURCE_DIR)\openssl\crypto\threads_pthread.c \
	$(SOURCE_DIR)\openssl\crypto\threads_none.c \
	$(SOURCE_DIR)\openssl\crypto\ebcdic.c \
	$(SOURCE_DIR)\openssl\crypto\mem_clr.c \
	$(SOURCE_DIR)\openssl\crypto\threads_win.c \
	$(SOURCE_DIR)\openssl\crypto\mem_sec.c \
	$(SOURCE_DIR)\openssl\crypto\o_str.c \
	$(SOURCE_DIR)\openssl\crypto\mem_dbg.c \
	$(SOURCE_DIR)\openssl\crypto\mem.c \
	$(SOURCE_DIR)\openssl\crypto\cversion.c \
	$(SOURCE_DIR)\openssl\crypto\cpt_err.c \
	$(SOURCE_DIR)\openssl\crypto\getenv.c \
	$(SOURCE_DIR)\openssl\crypto\o_fips.c \
	$(SOURCE_DIR)\openssl\crypto\o_init.c \
	$(SOURCE_DIR)\openssl\crypto\init.c \
	$(SOURCE_DIR)\openssl\crypto\cryptlib.c \


SOURCE_13_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_lib.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_key.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_pmeth.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_rfc5114.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_depr.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_check.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_ameth.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_gen.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_rfc7919.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_kdf.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_prn.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_meth.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_err.c \
	$(SOURCE_DIR)\openssl\crypto\dh\dh_asn1.c \


SOURCE_14_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_openssl.c \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_win32.c \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_vms.c \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_err.c \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_lib.c \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_dl.c \
	$(SOURCE_DIR)\openssl\crypto\dso\dso_dlfcn.c \


SOURCE_15_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_nistputil.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_key.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve25519.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_print.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_pmeth.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_oct.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_smpl.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_nist.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_curve.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec2_smpl.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_asn1.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_cvt.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_err.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecdh_ossl.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_oct.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecdsa_vrf.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_mult.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_mont.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecdsa_sign.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_ameth.c \
	$(SOURCE_DIR)\openssl\crypto\ec\eck_prn.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp521.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec2_oct.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_lib.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecdh_kdf.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecdsa_ossl.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp256.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecx_meth.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_kmeth.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ec_check.c \
	$(SOURCE_DIR)\openssl\crypto\ec\ecp_nistp224.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve448\scalar.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve448\f_generic.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve448\eddsa.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve448\curve448_tables.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve448\curve448.c \
	$(SOURCE_DIR)\openssl\crypto\ec\curve448\arch_32\f_impl.c \


SOURCE_16_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\err\err_prn.c \
	$(SOURCE_DIR)\openssl\crypto\err\err.c \


SOURCE_17_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_pbe.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_enc.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_wp.c \
	$(SOURCE_DIR)\openssl\crypto\evp\pbe_scrypt.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_open.c \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_enc.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_mdc2.c \
	$(SOURCE_DIR)\openssl\crypto\evp\bio_ok.c \
	$(SOURCE_DIR)\openssl\crypto\evp\encode.c \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_pkey.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_sha1.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_camellia.c \
	$(SOURCE_DIR)\openssl\crypto\evp\bio_enc.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_old.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p5_crpt2.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_dec.c \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_key.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_sha3.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_lib.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_verify.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_xcbc_d.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_seed.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_md5.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_null.c \
	$(SOURCE_DIR)\openssl\crypto\evp\pmeth_fn.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_ripemd.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_aes_cbc_hmac_sha256.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_aes.c \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_err.c \
	$(SOURCE_DIR)\openssl\crypto\evp\digest.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_aria.c \
	$(SOURCE_DIR)\openssl\crypto\evp\names.c \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_cnf.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_cast.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_sigver.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_bf.c \
	$(SOURCE_DIR)\openssl\crypto\evp\cmeth_lib.c \
	$(SOURCE_DIR)\openssl\crypto\evp\pmeth_gn.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_sign.c \
	$(SOURCE_DIR)\openssl\crypto\evp\bio_b64.c \
	$(SOURCE_DIR)\openssl\crypto\evp\c_alld.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_chacha20_poly1305.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_rc5.c \
	$(SOURCE_DIR)\openssl\crypto\evp\m_md2.c \
	$(SOURCE_DIR)\openssl\crypto\evp\e_null.c \
	$(SOURCE_DIR)\openssl\crypto\evp\evp_lib.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p_seal.c \
	$(SOURCE_DIR)\openssl\crypto\evp\p5_crpt.c \
	$(SOURCE_DIR)\openssl\crypto\evp\bio_md.c \
	$(SOURCE_DIR)\openssl\crypto\evp\pmeth_lib.c \
	$(SOURCE_DIR)\openssl\crypto\evp\c_allc.c \


SOURCE_18_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\hmac\hmac.c \
	$(SOURCE_DIR)\openssl\crypto\hmac\hm_ameth.c \
	$(SOURCE_DIR)\openssl\crypto\hmac\hm_pmeth.c \


SOURCE_19_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\kdf\scrypt.c \
	$(SOURCE_DIR)\openssl\crypto\kdf\kdf_err.c \
	$(SOURCE_DIR)\openssl\crypto\kdf\tls1_prf.c \
	$(SOURCE_DIR)\openssl\crypto\kdf\hkdf.c \


SOURCE_20_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\lhash\lh_stats.c \
	$(SOURCE_DIR)\openssl\crypto\lhash\lhash.c \


SOURCE_21_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\md5\md5_one.c \
	$(SOURCE_DIR)\openssl\crypto\md5\md5_dgst.c \


SOURCE_22_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\modes\xts128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\ocb128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\ctr128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\cts128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\cbc128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\gcm128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\ofb128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\cfb128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\wrap128.c \
	$(SOURCE_DIR)\openssl\crypto\modes\ccm128.c \


SOURCE_23_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\objects\obj_xref.c \
	$(SOURCE_DIR)\openssl\crypto\objects\obj_lib.c \
	$(SOURCE_DIR)\openssl\crypto\objects\obj_err.c \
	$(SOURCE_DIR)\openssl\crypto\objects\o_names.c \
	$(SOURCE_DIR)\openssl\crypto\objects\obj_dat.c \


SOURCE_24_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_err.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_cl.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_prn.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_ext.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_asn.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_srv.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_lib.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_ht.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\v3_ocsp.c \
	$(SOURCE_DIR)\openssl\crypto\ocsp\ocsp_vfy.c \


SOURCE_25_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_xaux.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pvkfmt.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_info.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_sign.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_pk8.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_x509.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_err.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_all.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_pkey.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_oth.c \
	$(SOURCE_DIR)\openssl\crypto\pem\pem_lib.c \


SOURCE_26_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_npas.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_kiss.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_attr.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_key.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_decr.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_add.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_init.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_utl.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_asn.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_mutl.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_sbag.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_crpt.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\pk12err.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_crt.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_p8d.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs12\p12_p8e.c \


SOURCE_27_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_attr.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_doit.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_smime.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pkcs7err.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_asn1.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_mime.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\bio_pk7.c \
	$(SOURCE_DIR)\openssl\crypto\pkcs7\pk7_lib.c \


SOURCE_28_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\poly1305\poly1305_ameth.c \
	$(SOURCE_DIR)\openssl\crypto\poly1305\poly1305_pmeth.c \
	$(SOURCE_DIR)\openssl\crypto\poly1305\poly1305.c \


SOURCE_29_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\rand\rand_win.c \
	$(SOURCE_DIR)\openssl\crypto\rand\rand_unix.c \
	$(SOURCE_DIR)\openssl\crypto\rand\rand_vms.c \
	$(SOURCE_DIR)\openssl\crypto\rand\drbg_ctr.c \
	$(SOURCE_DIR)\openssl\crypto\rand\rand_lib.c \
	$(SOURCE_DIR)\openssl\crypto\rand\rand_egd.c \
	$(SOURCE_DIR)\openssl\crypto\rand\drbg_lib.c \
	$(SOURCE_DIR)\openssl\crypto\rand\rand_err.c \


SOURCE_30_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_depr.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_ssl.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_asn1.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_pk1.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_pmeth.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_meth.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_prn.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_crpt.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_lib.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_mp.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_x931g.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_none.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_oaep.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_pss.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_gen.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_err.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_saos.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_sign.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_chk.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_ossl.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_ameth.c \
	$(SOURCE_DIR)\openssl\crypto\rsa\rsa_x931.c \


SOURCE_31_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\sha\sha512.c \
	$(SOURCE_DIR)\openssl\crypto\sha\keccak1600.c \
	$(SOURCE_DIR)\openssl\crypto\sha\sha1_one.c \
	$(SOURCE_DIR)\openssl\crypto\sha\sha1dgst.c \
	$(SOURCE_DIR)\openssl\crypto\sha\sha256.c \


SOURCE_32_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\siphash\siphash_pmeth.c \
	$(SOURCE_DIR)\openssl\crypto\siphash\siphash_ameth.c \
	$(SOURCE_DIR)\openssl\crypto\siphash\siphash.c \


SOURCE_33_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\stack\stack.c \


SOURCE_34_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\txt_db\txt_db.c \


SOURCE_35_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\ui\ui_err.c \
	$(SOURCE_DIR)\openssl\crypto\ui\ui_util.c \
	$(SOURCE_DIR)\openssl\crypto\ui\ui_openssl.c \
	$(SOURCE_DIR)\openssl\crypto\ui\ui_lib.c \
	$(SOURCE_DIR)\openssl\crypto\ui\ui_null.c \


SOURCE_36_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\x509\x_attrib.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_vpm.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_req.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_cmp.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_v3.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_crl.c \
	$(SOURCE_DIR)\openssl\crypto\x509\t_crl.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_r2x.c \
	$(SOURCE_DIR)\openssl\crypto\x509\t_x509.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_req.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_name.c \
	$(SOURCE_DIR)\openssl\crypto\x509\by_file.c \
	$(SOURCE_DIR)\openssl\crypto\x509\by_dir.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_att.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_trs.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_ext.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_meth.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_err.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_def.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_vfy.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509name.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_obj.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509cset.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_exten.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_lu.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_d2.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_txt.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_pubkey.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509_set.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_all.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_x509a.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509type.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509rset.c \
	$(SOURCE_DIR)\openssl\crypto\x509\t_req.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x_x509.c \
	$(SOURCE_DIR)\openssl\crypto\x509\x509spki.c \


SOURCE_37_FILES =  \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_akey.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_lib.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_ncons.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_cpols.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_sxnet.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_akeya.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_pci.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_admis.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\pcy_map.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_addr.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_int.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_tlsf.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3err.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_pku.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_skey.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_prn.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\pcy_tree.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_bitst.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_info.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_pcia.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_asid.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\pcy_data.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_utl.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_alt.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_pmaps.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_purp.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_enum.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_crld.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_extku.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_conf.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\pcy_lib.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_pcons.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_genn.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\pcy_cache.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_ia5.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\pcy_node.c \
	$(SOURCE_DIR)\openssl\crypto\x509v3\v3_bcons.c \


SOURCE_38_FILES =  \
	$(SOURCE_DIR)\rand_pool.c \
	$(SOURCE_DIR)\ossl_store.c \



OBJECT_1_FILES =  \
    $(OUTPUT_DIR)\aes_cbc.obj \
    $(OUTPUT_DIR)\aes_cfb.obj \
    $(OUTPUT_DIR)\aes_core.obj \
    $(OUTPUT_DIR)\aes_ecb.obj \
    $(OUTPUT_DIR)\aes_ige.obj \
    $(OUTPUT_DIR)\aes_misc.obj \
    $(OUTPUT_DIR)\aes_ofb.obj \
    $(OUTPUT_DIR)\aes_wrap.obj \


OBJECT_2_FILES =  \
    $(OUTPUT_DIR)\aria.obj \


OBJECT_3_FILES =  \
    $(OUTPUT_DIR)\a_bitstr.obj \
    $(OUTPUT_DIR)\a_d2i_fp.obj \
    $(OUTPUT_DIR)\a_digest.obj \
    $(OUTPUT_DIR)\a_dup.obj \
    $(OUTPUT_DIR)\a_gentm.obj \
    $(OUTPUT_DIR)\a_i2d_fp.obj \
    $(OUTPUT_DIR)\a_int.obj \
    $(OUTPUT_DIR)\a_mbstr.obj \
    $(OUTPUT_DIR)\a_object.obj \
    $(OUTPUT_DIR)\a_octet.obj \
    $(OUTPUT_DIR)\a_print.obj \
    $(OUTPUT_DIR)\a_sign.obj \
    $(OUTPUT_DIR)\a_strex.obj \
    $(OUTPUT_DIR)\a_strnid.obj \
    $(OUTPUT_DIR)\a_time.obj \
    $(OUTPUT_DIR)\a_type.obj \
    $(OUTPUT_DIR)\a_utctm.obj \
    $(OUTPUT_DIR)\a_utf8.obj \
    $(OUTPUT_DIR)\a_verify.obj \
    $(OUTPUT_DIR)\ameth_lib.obj \
    $(OUTPUT_DIR)\asn1_err.obj \
    $(OUTPUT_DIR)\asn1_gen.obj \
    $(OUTPUT_DIR)\asn1_item_list.obj \
    $(OUTPUT_DIR)\asn1_lib.obj \
    $(OUTPUT_DIR)\asn1_par.obj \
    $(OUTPUT_DIR)\asn_mime.obj \
    $(OUTPUT_DIR)\asn_moid.obj \
    $(OUTPUT_DIR)\asn_mstbl.obj \
    $(OUTPUT_DIR)\asn_pack.obj \
    $(OUTPUT_DIR)\bio_asn1.obj \
    $(OUTPUT_DIR)\bio_ndef.obj \
    $(OUTPUT_DIR)\d2i_pr.obj \
    $(OUTPUT_DIR)\d2i_pu.obj \
    $(OUTPUT_DIR)\evp_asn1.obj \
    $(OUTPUT_DIR)\f_int.obj \
    $(OUTPUT_DIR)\f_string.obj \
    $(OUTPUT_DIR)\i2d_pr.obj \
    $(OUTPUT_DIR)\i2d_pu.obj \
    $(OUTPUT_DIR)\n_pkey.obj \
    $(OUTPUT_DIR)\nsseq.obj \
    $(OUTPUT_DIR)\p5_pbe.obj \
    $(OUTPUT_DIR)\p5_pbev2.obj \
    $(OUTPUT_DIR)\p5_scrypt.obj \
    $(OUTPUT_DIR)\p8_pkey.obj \
    $(OUTPUT_DIR)\t_bitst.obj \
    $(OUTPUT_DIR)\t_pkey.obj \
    $(OUTPUT_DIR)\t_spki.obj \
    $(OUTPUT_DIR)\tasn_dec.obj \
    $(OUTPUT_DIR)\tasn_enc.obj \
    $(OUTPUT_DIR)\tasn_fre.obj \
    $(OUTPUT_DIR)\tasn_new.obj \
    $(OUTPUT_DIR)\tasn_prn.obj \
    $(OUTPUT_DIR)\tasn_scn.obj \
    $(OUTPUT_DIR)\tasn_typ.obj \
    $(OUTPUT_DIR)\tasn_utl.obj \
    $(OUTPUT_DIR)\x_algor.obj \
    $(OUTPUT_DIR)\x_bignum.obj \
    $(OUTPUT_DIR)\x_info.obj \
    $(OUTPUT_DIR)\x_int64.obj \
    $(OUTPUT_DIR)\x_long.obj \
    $(OUTPUT_DIR)\x_pkey.obj \
    $(OUTPUT_DIR)\x_sig.obj \
    $(OUTPUT_DIR)\x_spki.obj \
    $(OUTPUT_DIR)\x_val.obj \


OBJECT_4_FILES =  \
    $(OUTPUT_DIR)\async_null.obj \
    $(OUTPUT_DIR)\async_posix.obj \
    $(OUTPUT_DIR)\async_win.obj \
    $(OUTPUT_DIR)\async.obj \
    $(OUTPUT_DIR)\async_err.obj \
    $(OUTPUT_DIR)\async_wait.obj \


OBJECT_5_FILES =  \
    $(OUTPUT_DIR)\b_addr.obj \
    $(OUTPUT_DIR)\b_dump.obj \
    $(OUTPUT_DIR)\b_sock.obj \
    $(OUTPUT_DIR)\b_sock2.obj \
    $(OUTPUT_DIR)\bf_buff.obj \
    $(OUTPUT_DIR)\bf_lbuf.obj \
    $(OUTPUT_DIR)\bf_nbio.obj \
    $(OUTPUT_DIR)\bf_null.obj \
    $(OUTPUT_DIR)\bio_cb.obj \
    $(OUTPUT_DIR)\bio_err.obj \
    $(OUTPUT_DIR)\bio_lib.obj \
    $(OUTPUT_DIR)\bio_meth.obj \
    $(OUTPUT_DIR)\bss_acpt.obj \
    $(OUTPUT_DIR)\bss_bio.obj \
    $(OUTPUT_DIR)\bss_conn.obj \
    $(OUTPUT_DIR)\bss_dgram.obj \
    $(OUTPUT_DIR)\bss_fd.obj \
    $(OUTPUT_DIR)\bss_file.obj \
    $(OUTPUT_DIR)\bss_log.obj \
    $(OUTPUT_DIR)\bss_mem.obj \
    $(OUTPUT_DIR)\bss_null.obj \
    $(OUTPUT_DIR)\bss_sock.obj \


OBJECT_6_FILES =  \
    $(OUTPUT_DIR)\bn_add.obj \
    $(OUTPUT_DIR)\bn_asm.obj \
    $(OUTPUT_DIR)\bn_blind.obj \
    $(OUTPUT_DIR)\bn_const.obj \
    $(OUTPUT_DIR)\bn_ctx.obj \
    $(OUTPUT_DIR)\bn_depr.obj \
    $(OUTPUT_DIR)\bn_dh.obj \
    $(OUTPUT_DIR)\bn_div.obj \
    $(OUTPUT_DIR)\bn_err.obj \
    $(OUTPUT_DIR)\bn_exp.obj \
    $(OUTPUT_DIR)\bn_exp2.obj \
    $(OUTPUT_DIR)\bn_gcd.obj \
    $(OUTPUT_DIR)\bn_gf2m.obj \
    $(OUTPUT_DIR)\bn_intern.obj \
    $(OUTPUT_DIR)\bn_kron.obj \
    $(OUTPUT_DIR)\bn_lib.obj \
    $(OUTPUT_DIR)\bn_mod.obj \
    $(OUTPUT_DIR)\bn_mont.obj \
    $(OUTPUT_DIR)\bn_mpi.obj \
    $(OUTPUT_DIR)\bn_mul.obj \
    $(OUTPUT_DIR)\bn_nist.obj \
    $(OUTPUT_DIR)\bn_prime.obj \
    $(OUTPUT_DIR)\bn_print.obj \
    $(OUTPUT_DIR)\bn_rand.obj \
    $(OUTPUT_DIR)\bn_recp.obj \
    $(OUTPUT_DIR)\bn_shift.obj \
    $(OUTPUT_DIR)\bn_sqr.obj \
    $(OUTPUT_DIR)\bn_sqrt.obj \
    $(OUTPUT_DIR)\bn_srp.obj \
    $(OUTPUT_DIR)\bn_word.obj \
    $(OUTPUT_DIR)\bn_x931p.obj \


OBJECT_7_FILES =  \
    $(OUTPUT_DIR)\buf_err.obj \
    $(OUTPUT_DIR)\buffer.obj \


OBJECT_8_FILES =  \
    $(OUTPUT_DIR)\chacha_enc.obj \


OBJECT_9_FILES =  \
    $(OUTPUT_DIR)\cm_ameth.obj \
    $(OUTPUT_DIR)\cm_pmeth.obj \
    $(OUTPUT_DIR)\cmac.obj \


OBJECT_10_FILES =  \
    $(OUTPUT_DIR)\c_zlib.obj \
    $(OUTPUT_DIR)\comp_err.obj \
    $(OUTPUT_DIR)\comp_lib.obj \


OBJECT_11_FILES =  \
    $(OUTPUT_DIR)\conf_api.obj \
    $(OUTPUT_DIR)\conf_def.obj \
    $(OUTPUT_DIR)\conf_err.obj \
    $(OUTPUT_DIR)\conf_lib.obj \
    $(OUTPUT_DIR)\conf_mall.obj \
    $(OUTPUT_DIR)\conf_mod.obj \
    $(OUTPUT_DIR)\conf_sap.obj \
    $(OUTPUT_DIR)\conf_ssl.obj \


OBJECT_12_FILES =  \
    $(OUTPUT_DIR)\cpt_err.obj \
    $(OUTPUT_DIR)\cryptlib.obj \
    $(OUTPUT_DIR)\ctype.obj \
    $(OUTPUT_DIR)\cversion.obj \
    $(OUTPUT_DIR)\ebcdic.obj \
    $(OUTPUT_DIR)\ex_data.obj \
    $(OUTPUT_DIR)\getenv.obj \
    $(OUTPUT_DIR)\init.obj \
    $(OUTPUT_DIR)\mem.obj \
    $(OUTPUT_DIR)\mem_clr.obj \
    $(OUTPUT_DIR)\mem_dbg.obj \
    $(OUTPUT_DIR)\mem_sec.obj \
    $(OUTPUT_DIR)\o_dir.obj \
    $(OUTPUT_DIR)\o_fips.obj \
    $(OUTPUT_DIR)\o_fopen.obj \
    $(OUTPUT_DIR)\o_init.obj \
    $(OUTPUT_DIR)\o_str.obj \
    $(OUTPUT_DIR)\o_time.obj \
    $(OUTPUT_DIR)\threads_none.obj \
    $(OUTPUT_DIR)\threads_pthread.obj \
    $(OUTPUT_DIR)\threads_win.obj \
    $(OUTPUT_DIR)\uid.obj \


OBJECT_13_FILES =  \
    $(OUTPUT_DIR)\dh_ameth.obj \
    $(OUTPUT_DIR)\dh_asn1.obj \
    $(OUTPUT_DIR)\dh_check.obj \
    $(OUTPUT_DIR)\dh_depr.obj \
    $(OUTPUT_DIR)\dh_err.obj \
    $(OUTPUT_DIR)\dh_gen.obj \
    $(OUTPUT_DIR)\dh_kdf.obj \
    $(OUTPUT_DIR)\dh_key.obj \
    $(OUTPUT_DIR)\dh_lib.obj \
    $(OUTPUT_DIR)\dh_meth.obj \
    $(OUTPUT_DIR)\dh_pmeth.obj \
    $(OUTPUT_DIR)\dh_prn.obj \
    $(OUTPUT_DIR)\dh_rfc5114.obj \
    $(OUTPUT_DIR)\dh_rfc7919.obj \


OBJECT_14_FILES =  \
    $(OUTPUT_DIR)\dso_dl.obj \
    $(OUTPUT_DIR)\dso_dlfcn.obj \
    $(OUTPUT_DIR)\dso_err.obj \
    $(OUTPUT_DIR)\dso_lib.obj \
    $(OUTPUT_DIR)\dso_openssl.obj \
    $(OUTPUT_DIR)\dso_vms.obj \
    $(OUTPUT_DIR)\dso_win32.obj \


OBJECT_15_FILES =  \
    $(OUTPUT_DIR)\curve25519.obj \
    $(OUTPUT_DIR)\f_impl.obj \
    $(OUTPUT_DIR)\curve448.obj \
    $(OUTPUT_DIR)\curve448_tables.obj \
    $(OUTPUT_DIR)\eddsa.obj \
    $(OUTPUT_DIR)\f_generic.obj \
    $(OUTPUT_DIR)\scalar.obj \
    $(OUTPUT_DIR)\ec2_oct.obj \
    $(OUTPUT_DIR)\ec2_smpl.obj \
    $(OUTPUT_DIR)\ec_ameth.obj \
    $(OUTPUT_DIR)\ec_asn1.obj \
    $(OUTPUT_DIR)\ec_check.obj \
    $(OUTPUT_DIR)\ec_curve.obj \
    $(OUTPUT_DIR)\ec_cvt.obj \
    $(OUTPUT_DIR)\ec_err.obj \
    $(OUTPUT_DIR)\ec_key.obj \
    $(OUTPUT_DIR)\ec_kmeth.obj \
    $(OUTPUT_DIR)\ec_lib.obj \
    $(OUTPUT_DIR)\ec_mult.obj \
    $(OUTPUT_DIR)\ec_oct.obj \
    $(OUTPUT_DIR)\ec_pmeth.obj \
    $(OUTPUT_DIR)\ec_print.obj \
    $(OUTPUT_DIR)\ecdh_kdf.obj \
    $(OUTPUT_DIR)\ecdh_ossl.obj \
    $(OUTPUT_DIR)\ecdsa_ossl.obj \
    $(OUTPUT_DIR)\ecdsa_sign.obj \
    $(OUTPUT_DIR)\ecdsa_vrf.obj \
    $(OUTPUT_DIR)\eck_prn.obj \
    $(OUTPUT_DIR)\ecp_mont.obj \
    $(OUTPUT_DIR)\ecp_nist.obj \
    $(OUTPUT_DIR)\ecp_nistp224.obj \
    $(OUTPUT_DIR)\ecp_nistp256.obj \
    $(OUTPUT_DIR)\ecp_nistp521.obj \
    $(OUTPUT_DIR)\ecp_nistputil.obj \
    $(OUTPUT_DIR)\ecp_oct.obj \
    $(OUTPUT_DIR)\ecp_smpl.obj \
    $(OUTPUT_DIR)\ecx_meth.obj \


OBJECT_16_FILES =  \
    $(OUTPUT_DIR)\err.obj \
    $(OUTPUT_DIR)\err_prn.obj \


OBJECT_17_FILES =  \
    $(OUTPUT_DIR)\bio_b64.obj \
    $(OUTPUT_DIR)\bio_enc.obj \
    $(OUTPUT_DIR)\bio_md.obj \
    $(OUTPUT_DIR)\bio_ok.obj \
    $(OUTPUT_DIR)\c_allc.obj \
    $(OUTPUT_DIR)\c_alld.obj \
    $(OUTPUT_DIR)\cmeth_lib.obj \
    $(OUTPUT_DIR)\digest.obj \
    $(OUTPUT_DIR)\e_aes.obj \
    $(OUTPUT_DIR)\e_aes_cbc_hmac_sha256.obj \
    $(OUTPUT_DIR)\e_aria.obj \
    $(OUTPUT_DIR)\e_bf.obj \
    $(OUTPUT_DIR)\e_camellia.obj \
    $(OUTPUT_DIR)\e_cast.obj \
    $(OUTPUT_DIR)\e_chacha20_poly1305.obj \
    $(OUTPUT_DIR)\e_null.obj \
    $(OUTPUT_DIR)\e_old.obj \
    $(OUTPUT_DIR)\e_seed.obj \
    $(OUTPUT_DIR)\e_xcbc_d.obj \
    $(OUTPUT_DIR)\encode.obj \
    $(OUTPUT_DIR)\evp_cnf.obj \
    $(OUTPUT_DIR)\evp_enc.obj \
    $(OUTPUT_DIR)\evp_err.obj \
    $(OUTPUT_DIR)\evp_key.obj \
    $(OUTPUT_DIR)\evp_lib.obj \
    $(OUTPUT_DIR)\evp_pbe.obj \
    $(OUTPUT_DIR)\evp_pkey.obj \
    $(OUTPUT_DIR)\m_md5.obj \
    $(OUTPUT_DIR)\m_mdc2.obj \
    $(OUTPUT_DIR)\m_null.obj \
    $(OUTPUT_DIR)\m_ripemd.obj \
    $(OUTPUT_DIR)\m_sha1.obj \
    $(OUTPUT_DIR)\m_sha3.obj \
    $(OUTPUT_DIR)\m_sigver.obj \
    $(OUTPUT_DIR)\m_wp.obj \
    $(OUTPUT_DIR)\names.obj \
    $(OUTPUT_DIR)\p5_crpt.obj \
    $(OUTPUT_DIR)\p5_crpt2.obj \
    $(OUTPUT_DIR)\p_dec.obj \
    $(OUTPUT_DIR)\p_enc.obj \
    $(OUTPUT_DIR)\p_lib.obj \
    $(OUTPUT_DIR)\p_open.obj \
    $(OUTPUT_DIR)\p_seal.obj \
    $(OUTPUT_DIR)\p_sign.obj \
    $(OUTPUT_DIR)\p_verify.obj \
    $(OUTPUT_DIR)\pbe_scrypt.obj \
    $(OUTPUT_DIR)\pmeth_fn.obj \
    $(OUTPUT_DIR)\pmeth_gn.obj \
    $(OUTPUT_DIR)\pmeth_lib.obj \


OBJECT_18_FILES =  \
    $(OUTPUT_DIR)\hm_ameth.obj \
    $(OUTPUT_DIR)\hm_pmeth.obj \
    $(OUTPUT_DIR)\hmac.obj \


OBJECT_19_FILES =  \
    $(OUTPUT_DIR)\hkdf.obj \
    $(OUTPUT_DIR)\kdf_err.obj \
    $(OUTPUT_DIR)\scrypt.obj \
    $(OUTPUT_DIR)\tls1_prf.obj \


OBJECT_20_FILES =  \
    $(OUTPUT_DIR)\lh_stats.obj \
    $(OUTPUT_DIR)\lhash.obj \


OBJECT_21_FILES =  \
    $(OUTPUT_DIR)\md5_dgst.obj \
    $(OUTPUT_DIR)\md5_one.obj \


OBJECT_22_FILES =  \
    $(OUTPUT_DIR)\cbc128.obj \
    $(OUTPUT_DIR)\ccm128.obj \
    $(OUTPUT_DIR)\cfb128.obj \
    $(OUTPUT_DIR)\ctr128.obj \
    $(OUTPUT_DIR)\cts128.obj \
    $(OUTPUT_DIR)\gcm128.obj \
    $(OUTPUT_DIR)\ocb128.obj \
    $(OUTPUT_DIR)\ofb128.obj \
    $(OUTPUT_DIR)\wrap128.obj \
    $(OUTPUT_DIR)\xts128.obj \


OBJECT_23_FILES =  \
    $(OUTPUT_DIR)\o_names.obj \
    $(OUTPUT_DIR)\obj_dat.obj \
    $(OUTPUT_DIR)\obj_err.obj \
    $(OUTPUT_DIR)\obj_lib.obj \
    $(OUTPUT_DIR)\obj_xref.obj \


OBJECT_24_FILES =  \
    $(OUTPUT_DIR)\ocsp_asn.obj \
    $(OUTPUT_DIR)\ocsp_cl.obj \
    $(OUTPUT_DIR)\ocsp_err.obj \
    $(OUTPUT_DIR)\ocsp_ext.obj \
    $(OUTPUT_DIR)\ocsp_ht.obj \
    $(OUTPUT_DIR)\ocsp_lib.obj \
    $(OUTPUT_DIR)\ocsp_prn.obj \
    $(OUTPUT_DIR)\ocsp_srv.obj \
    $(OUTPUT_DIR)\ocsp_vfy.obj \
    $(OUTPUT_DIR)\v3_ocsp.obj \


OBJECT_25_FILES =  \
    $(OUTPUT_DIR)\pem_all.obj \
    $(OUTPUT_DIR)\pem_err.obj \
    $(OUTPUT_DIR)\pem_info.obj \
    $(OUTPUT_DIR)\pem_lib.obj \
    $(OUTPUT_DIR)\pem_oth.obj \
    $(OUTPUT_DIR)\pem_pk8.obj \
    $(OUTPUT_DIR)\pem_pkey.obj \
    $(OUTPUT_DIR)\pem_sign.obj \
    $(OUTPUT_DIR)\pem_x509.obj \
    $(OUTPUT_DIR)\pem_xaux.obj \
    $(OUTPUT_DIR)\pvkfmt.obj \


OBJECT_26_FILES =  \
    $(OUTPUT_DIR)\p12_add.obj \
    $(OUTPUT_DIR)\p12_asn.obj \
    $(OUTPUT_DIR)\p12_attr.obj \
    $(OUTPUT_DIR)\p12_crpt.obj \
    $(OUTPUT_DIR)\p12_crt.obj \
    $(OUTPUT_DIR)\p12_decr.obj \
    $(OUTPUT_DIR)\p12_init.obj \
    $(OUTPUT_DIR)\p12_key.obj \
    $(OUTPUT_DIR)\p12_kiss.obj \
    $(OUTPUT_DIR)\p12_mutl.obj \
    $(OUTPUT_DIR)\p12_npas.obj \
    $(OUTPUT_DIR)\p12_p8d.obj \
    $(OUTPUT_DIR)\p12_p8e.obj \
    $(OUTPUT_DIR)\p12_sbag.obj \
    $(OUTPUT_DIR)\p12_utl.obj \
    $(OUTPUT_DIR)\pk12err.obj \


OBJECT_27_FILES =  \
    $(OUTPUT_DIR)\bio_pk7.obj \
    $(OUTPUT_DIR)\pk7_asn1.obj \
    $(OUTPUT_DIR)\pk7_attr.obj \
    $(OUTPUT_DIR)\pk7_doit.obj \
    $(OUTPUT_DIR)\pk7_lib.obj \
    $(OUTPUT_DIR)\pk7_mime.obj \
    $(OUTPUT_DIR)\pk7_smime.obj \
    $(OUTPUT_DIR)\pkcs7err.obj \


OBJECT_28_FILES =  \
    $(OUTPUT_DIR)\poly1305.obj \
    $(OUTPUT_DIR)\poly1305_ameth.obj \
    $(OUTPUT_DIR)\poly1305_pmeth.obj \


OBJECT_29_FILES =  \
    $(OUTPUT_DIR)\drbg_ctr.obj \
    $(OUTPUT_DIR)\drbg_lib.obj \
    $(OUTPUT_DIR)\rand_egd.obj \
    $(OUTPUT_DIR)\rand_err.obj \
    $(OUTPUT_DIR)\rand_lib.obj \
    $(OUTPUT_DIR)\rand_unix.obj \
    $(OUTPUT_DIR)\rand_vms.obj \
    $(OUTPUT_DIR)\rand_win.obj \


OBJECT_30_FILES =  \
    $(OUTPUT_DIR)\rsa_ameth.obj \
    $(OUTPUT_DIR)\rsa_asn1.obj \
    $(OUTPUT_DIR)\rsa_chk.obj \
    $(OUTPUT_DIR)\rsa_crpt.obj \
    $(OUTPUT_DIR)\rsa_depr.obj \
    $(OUTPUT_DIR)\rsa_err.obj \
    $(OUTPUT_DIR)\rsa_gen.obj \
    $(OUTPUT_DIR)\rsa_lib.obj \
    $(OUTPUT_DIR)\rsa_meth.obj \
    $(OUTPUT_DIR)\rsa_mp.obj \
    $(OUTPUT_DIR)\rsa_none.obj \
    $(OUTPUT_DIR)\rsa_oaep.obj \
    $(OUTPUT_DIR)\rsa_ossl.obj \
    $(OUTPUT_DIR)\rsa_pk1.obj \
    $(OUTPUT_DIR)\rsa_pmeth.obj \
    $(OUTPUT_DIR)\rsa_prn.obj \
    $(OUTPUT_DIR)\rsa_pss.obj \
    $(OUTPUT_DIR)\rsa_saos.obj \
    $(OUTPUT_DIR)\rsa_sign.obj \
    $(OUTPUT_DIR)\rsa_ssl.obj \
    $(OUTPUT_DIR)\rsa_x931.obj \
    $(OUTPUT_DIR)\rsa_x931g.obj \


OBJECT_31_FILES =  \
    $(OUTPUT_DIR)\keccak1600.obj \
    $(OUTPUT_DIR)\sha1_one.obj \
    $(OUTPUT_DIR)\sha1dgst.obj \
    $(OUTPUT_DIR)\sha256.obj \
    $(OUTPUT_DIR)\sha512.obj \


OBJECT_32_FILES =  \
    $(OUTPUT_DIR)\siphash.obj \
    $(OUTPUT_DIR)\siphash_ameth.obj \
    $(OUTPUT_DIR)\siphash_pmeth.obj \


OBJECT_33_FILES =  \
    $(OUTPUT_DIR)\stack.obj \


OBJECT_34_FILES =  \
    $(OUTPUT_DIR)\txt_db.obj \


OBJECT_35_FILES =  \
    $(OUTPUT_DIR)\ui_err.obj \
    $(OUTPUT_DIR)\ui_lib.obj \
    $(OUTPUT_DIR)\ui_null.obj \
    $(OUTPUT_DIR)\ui_openssl.obj \
    $(OUTPUT_DIR)\ui_util.obj \


OBJECT_36_FILES =  \
    $(OUTPUT_DIR)\by_dir.obj \
    $(OUTPUT_DIR)\by_file.obj \
    $(OUTPUT_DIR)\t_crl.obj \
    $(OUTPUT_DIR)\t_req.obj \
    $(OUTPUT_DIR)\t_x509.obj \
    $(OUTPUT_DIR)\x509_att.obj \
    $(OUTPUT_DIR)\x509_cmp.obj \
    $(OUTPUT_DIR)\x509_d2.obj \
    $(OUTPUT_DIR)\x509_def.obj \
    $(OUTPUT_DIR)\x509_err.obj \
    $(OUTPUT_DIR)\x509_ext.obj \
    $(OUTPUT_DIR)\x509_lu.obj \
    $(OUTPUT_DIR)\x509_meth.obj \
    $(OUTPUT_DIR)\x509_obj.obj \
    $(OUTPUT_DIR)\x509_r2x.obj \
    $(OUTPUT_DIR)\x509_req.obj \
    $(OUTPUT_DIR)\x509_set.obj \
    $(OUTPUT_DIR)\x509_trs.obj \
    $(OUTPUT_DIR)\x509_txt.obj \
    $(OUTPUT_DIR)\x509_v3.obj \
    $(OUTPUT_DIR)\x509_vfy.obj \
    $(OUTPUT_DIR)\x509_vpm.obj \
    $(OUTPUT_DIR)\x509cset.obj \
    $(OUTPUT_DIR)\x509name.obj \
    $(OUTPUT_DIR)\x509rset.obj \
    $(OUTPUT_DIR)\x509spki.obj \
    $(OUTPUT_DIR)\x509type.obj \
    $(OUTPUT_DIR)\x_all.obj \
    $(OUTPUT_DIR)\x_attrib.obj \
    $(OUTPUT_DIR)\x_crl.obj \
    $(OUTPUT_DIR)\x_exten.obj \
    $(OUTPUT_DIR)\x_name.obj \
    $(OUTPUT_DIR)\x_pubkey.obj \
    $(OUTPUT_DIR)\x_req.obj \
    $(OUTPUT_DIR)\x_x509.obj \
    $(OUTPUT_DIR)\x_x509a.obj \

OBJECT_37_FILES =  \
    $(OUTPUT_DIR)\pcy_cache.obj \
    $(OUTPUT_DIR)\pcy_data.obj \
    $(OUTPUT_DIR)\pcy_lib.obj \
    $(OUTPUT_DIR)\pcy_map.obj \
    $(OUTPUT_DIR)\pcy_node.obj \
    $(OUTPUT_DIR)\pcy_tree.obj \
    $(OUTPUT_DIR)\v3_addr.obj \
    $(OUTPUT_DIR)\v3_admis.obj \
    $(OUTPUT_DIR)\v3_akey.obj \
    $(OUTPUT_DIR)\v3_akeya.obj \
    $(OUTPUT_DIR)\v3_alt.obj \
    $(OUTPUT_DIR)\v3_asid.obj \
    $(OUTPUT_DIR)\v3_bcons.obj \
    $(OUTPUT_DIR)\v3_bitst.obj \
    $(OUTPUT_DIR)\v3_conf.obj \
    $(OUTPUT_DIR)\v3_cpols.obj \
    $(OUTPUT_DIR)\v3_crld.obj \
    $(OUTPUT_DIR)\v3_enum.obj \
    $(OUTPUT_DIR)\v3_extku.obj \
    $(OUTPUT_DIR)\v3_genn.obj \
    $(OUTPUT_DIR)\v3_ia5.obj \
    $(OUTPUT_DIR)\v3_info.obj \
    $(OUTPUT_DIR)\v3_int.obj \
    $(OUTPUT_DIR)\v3_lib.obj \
    $(OUTPUT_DIR)\v3_ncons.obj \
    $(OUTPUT_DIR)\v3_pci.obj \
    $(OUTPUT_DIR)\v3_pcia.obj \
    $(OUTPUT_DIR)\v3_pcons.obj \
    $(OUTPUT_DIR)\v3_pku.obj \
    $(OUTPUT_DIR)\v3_pmaps.obj \
    $(OUTPUT_DIR)\v3_prn.obj \
    $(OUTPUT_DIR)\v3_purp.obj \
    $(OUTPUT_DIR)\v3_skey.obj \
    $(OUTPUT_DIR)\v3_sxnet.obj \
    $(OUTPUT_DIR)\v3_tlsf.obj \
    $(OUTPUT_DIR)\v3_utl.obj \
    $(OUTPUT_DIR)\v3err.obj \

OBJECT_38_FILES =  \
    $(OUTPUT_DIR)\ossl_store.obj \
    $(OUTPUT_DIR)\rand_pool.obj \

LIB_FILES = \
    $(OUTPUT_DIR)\lib1.lib \
    $(OUTPUT_DIR)\lib2.lib \
    $(OUTPUT_DIR)\lib3.lib \
    $(OUTPUT_DIR)\lib4.lib \
    $(OUTPUT_DIR)\lib5.lib \
    $(OUTPUT_DIR)\lib6.lib \
    $(OUTPUT_DIR)\lib7.lib \
    $(OUTPUT_DIR)\lib8.lib \
    $(OUTPUT_DIR)\lib9.lib \
    $(OUTPUT_DIR)\lib10.lib \
    $(OUTPUT_DIR)\lib11.lib \
    $(OUTPUT_DIR)\lib12.lib \
    $(OUTPUT_DIR)\lib13.lib \
    $(OUTPUT_DIR)\lib14.lib \
    $(OUTPUT_DIR)\lib15.lib \
    $(OUTPUT_DIR)\lib16.lib \
    $(OUTPUT_DIR)\lib17.lib \
    $(OUTPUT_DIR)\lib18.lib \
    $(OUTPUT_DIR)\lib19.lib \
    $(OUTPUT_DIR)\lib20.lib \
    $(OUTPUT_DIR)\lib21.lib \
    $(OUTPUT_DIR)\lib22.lib \
    $(OUTPUT_DIR)\lib23.lib \
    $(OUTPUT_DIR)\lib24.lib \
    $(OUTPUT_DIR)\lib25.lib \
    $(OUTPUT_DIR)\lib26.lib \
    $(OUTPUT_DIR)\lib27.lib \
    $(OUTPUT_DIR)\lib28.lib \
    $(OUTPUT_DIR)\lib29.lib \
    $(OUTPUT_DIR)\lib30.lib \
    $(OUTPUT_DIR)\lib31.lib \
    $(OUTPUT_DIR)\lib32.lib \
    $(OUTPUT_DIR)\lib33.lib \
    $(OUTPUT_DIR)\lib34.lib \
    $(OUTPUT_DIR)\lib35.lib \
    $(OUTPUT_DIR)\lib36.lib \
    $(OUTPUT_DIR)\lib37.lib \
    $(OUTPUT_DIR)\lib38.lib \


INC =  \
    /I$(SOURCE_DIR)\openssl\crypto\store \
    /I$(SOURCE_DIR)\openssl\crypto\x509v3 \
    /I$(SOURCE_DIR)\openssl\crypto\x509 \
    /I$(SOURCE_DIR)\openssl\crypto\ui \
    /I$(SOURCE_DIR)\openssl\crypto\txt_db \
    /I$(SOURCE_DIR)\openssl\crypto\stack \
    /I$(SOURCE_DIR)\openssl\crypto\siphash \
    /I$(SOURCE_DIR)\openssl\crypto\sha \
    /I$(SOURCE_DIR)\openssl\crypto\rsa \
    /I$(SOURCE_DIR)\openssl\crypto\rand \
    /I$(SOURCE_DIR)\openssl\crypto\poly1305 \
    /I$(SOURCE_DIR)\openssl\crypto\pkcs7 \
    /I$(SOURCE_DIR)\openssl\crypto\pkcs12 \
    /I$(SOURCE_DIR)\openssl\crypto\pem \
    /I$(SOURCE_DIR)\openssl\crypto\ocsp \
    /I$(SOURCE_DIR)\openssl\crypto\objects \
    /I$(SOURCE_DIR)\openssl\crypto\modes \
    /I$(SOURCE_DIR)\openssl\crypto\md5 \
    /I$(SOURCE_DIR)\openssl\crypto\lhash \
    /I$(SOURCE_DIR)\openssl\crypto\kdf \
    /I$(SOURCE_DIR)\openssl\crypto\hmac \
    /I$(SOURCE_DIR)\openssl\crypto\evp \
    /I$(SOURCE_DIR)\openssl\crypto\err \
    /I$(SOURCE_DIR)\openssl\crypto\dso \
    /I$(SOURCE_DIR)\openssl\crypto\ec \
    /I$(SOURCE_DIR)\openssl\crypto\ec\curve448 \
    /I$(SOURCE_DIR)\openssl\crypto\ec\curve448\arch_32 \
    /I$(SOURCE_DIR)\openssl\crypto\dh \
    /I$(SOURCE_DIR)\openssl\crypto \
    /I$(SOURCE_DIR)\openssl\crypto\conf \
    /I$(SOURCE_DIR)\openssl\crypto\comp \
    /I$(SOURCE_DIR)\openssl\crypto\cmac \
    /I$(SOURCE_DIR)\openssl\crypto\chacha \
    /I$(SOURCE_DIR)\openssl\crypto\buffer \
    /I$(SOURCE_DIR)\openssl\crypto\bn \
    /I$(SOURCE_DIR)\openssl\crypto\bio \
    /I$(SOURCE_DIR)\openssl\crypto\async \
    /I$(SOURCE_DIR)\openssl\crypto\async\arch \
    /I$(SOURCE_DIR)\openssl\crypto\asn1 \
    /I$(SOURCE_DIR)\openssl\crypto\aria \
    /I$(SOURCE_DIR)\openssl\crypto\aes \
    /I$(SOURCE_DIR)\openssl\ms \
    /I$(SOURCE_DIR)\openssl \
    /I$(SOURCE_DIR) \
    /I$(WORKSPACE)\Include \
    /I$(WORKSPACE)\Include\Hal \
    /I$(WORKSPACE)\Include\Hal\$(ARCH) \
    /I$(WORKSPACE)\OsStub\Include \
    /I$(WORKSPACE)\OsStub\OpensslLib\Include \
    /I$(WORKSPACE)\OsStub\OpensslLib\openssl\include \
    /I$(WORKSPACE)\OsStub\OpensslLib\openssl\crypto\include

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
	-@if not exist $(OUTPUT_DIR) $(MD) $(OUTPUT_DIR)

#
# Individual Object Build Targets
#
$(OBJECT_1_FILES):  $(SOURCE_1_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_1_FILES)

$(OUTPUT_DIR)\lib1.lib: $(OBJECT_1_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_1_FILES) /OUT:$(OUTPUT_DIR)\lib1.lib

$(OBJECT_2_FILES):  $(SOURCE_2_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_2_FILES)

$(OUTPUT_DIR)\lib2.lib: $(OBJECT_2_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_2_FILES) /OUT:$(OUTPUT_DIR)\lib2.lib

$(OBJECT_3_FILES):  $(SOURCE_3_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_3_FILES)

$(OUTPUT_DIR)\lib3.lib: $(OBJECT_3_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_3_FILES) /OUT:$(OUTPUT_DIR)\lib3.lib

$(OBJECT_4_FILES):  $(SOURCE_4_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_4_FILES)

$(OUTPUT_DIR)\lib4.lib: $(OBJECT_4_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_4_FILES) /OUT:$(OUTPUT_DIR)\lib4.lib

$(OBJECT_5_FILES):  $(SOURCE_5_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_5_FILES)

$(OUTPUT_DIR)\lib5.lib: $(OBJECT_5_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_5_FILES) /OUT:$(OUTPUT_DIR)\lib5.lib

$(OBJECT_6_FILES):  $(SOURCE_6_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_6_FILES)

$(OUTPUT_DIR)\lib6.lib: $(OBJECT_6_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_6_FILES) /OUT:$(OUTPUT_DIR)\lib6.lib

$(OBJECT_7_FILES):  $(SOURCE_7_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_7_FILES)

$(OUTPUT_DIR)\lib7.lib: $(OBJECT_7_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_7_FILES) /OUT:$(OUTPUT_DIR)\lib7.lib

$(OBJECT_8_FILES):  $(SOURCE_8_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_8_FILES)

$(OUTPUT_DIR)\lib8.lib: $(OBJECT_8_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_8_FILES) /OUT:$(OUTPUT_DIR)\lib8.lib

$(OBJECT_9_FILES):  $(SOURCE_9_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_9_FILES)

$(OUTPUT_DIR)\lib9.lib: $(OBJECT_9_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_9_FILES) /OUT:$(OUTPUT_DIR)\lib9.lib

$(OBJECT_10_FILES):  $(SOURCE_10_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_10_FILES)

$(OUTPUT_DIR)\lib10.lib: $(OBJECT_10_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_10_FILES) /OUT:$(OUTPUT_DIR)\lib10.lib

$(OBJECT_11_FILES):  $(SOURCE_11_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_11_FILES)

$(OUTPUT_DIR)\lib11.lib: $(OBJECT_11_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_11_FILES) /OUT:$(OUTPUT_DIR)\lib11.lib

$(OBJECT_12_FILES):  $(SOURCE_12_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_12_FILES)

$(OUTPUT_DIR)\lib12.lib: $(OBJECT_12_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_12_FILES) /OUT:$(OUTPUT_DIR)\lib12.lib

$(OBJECT_13_FILES):  $(SOURCE_13_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_13_FILES)

$(OUTPUT_DIR)\lib13.lib: $(OBJECT_13_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_13_FILES) /OUT:$(OUTPUT_DIR)\lib13.lib

$(OBJECT_14_FILES):  $(SOURCE_14_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_14_FILES)

$(OUTPUT_DIR)\lib14.lib: $(OBJECT_14_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_14_FILES) /OUT:$(OUTPUT_DIR)\lib14.lib

$(OBJECT_15_FILES):  $(SOURCE_15_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_15_FILES)

$(OUTPUT_DIR)\lib15.lib: $(OBJECT_15_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_15_FILES) /OUT:$(OUTPUT_DIR)\lib15.lib

$(OBJECT_16_FILES):  $(SOURCE_16_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_16_FILES)

$(OUTPUT_DIR)\lib16.lib: $(OBJECT_16_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_16_FILES) /OUT:$(OUTPUT_DIR)\lib16.lib

$(OBJECT_17_FILES):  $(SOURCE_17_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_17_FILES)

$(OUTPUT_DIR)\lib17.lib: $(OBJECT_17_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_17_FILES) /OUT:$(OUTPUT_DIR)\lib17.lib

$(OBJECT_18_FILES):  $(SOURCE_18_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_18_FILES)

$(OUTPUT_DIR)\lib18.lib: $(OBJECT_18_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_18_FILES) /OUT:$(OUTPUT_DIR)\lib18.lib

$(OBJECT_19_FILES):  $(SOURCE_19_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_19_FILES)

$(OUTPUT_DIR)\lib19.lib: $(OBJECT_19_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_19_FILES) /OUT:$(OUTPUT_DIR)\lib19.lib

$(OBJECT_20_FILES):  $(SOURCE_20_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_20_FILES)

$(OUTPUT_DIR)\lib20.lib: $(OBJECT_20_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_20_FILES) /OUT:$(OUTPUT_DIR)\lib20.lib

$(OBJECT_21_FILES):  $(SOURCE_21_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_21_FILES)

$(OUTPUT_DIR)\lib21.lib: $(OBJECT_21_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_21_FILES) /OUT:$(OUTPUT_DIR)\lib21.lib

$(OBJECT_22_FILES):  $(SOURCE_22_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_22_FILES)

$(OUTPUT_DIR)\lib22.lib: $(OBJECT_22_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_22_FILES) /OUT:$(OUTPUT_DIR)\lib22.lib

$(OBJECT_23_FILES):  $(SOURCE_23_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_23_FILES)

$(OUTPUT_DIR)\lib23.lib: $(OBJECT_23_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_23_FILES) /OUT:$(OUTPUT_DIR)\lib23.lib

$(OBJECT_24_FILES):  $(SOURCE_24_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_24_FILES)

$(OUTPUT_DIR)\lib24.lib: $(OBJECT_24_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_24_FILES) /OUT:$(OUTPUT_DIR)\lib24.lib

$(OBJECT_25_FILES):  $(SOURCE_25_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_25_FILES)

$(OUTPUT_DIR)\lib25.lib: $(OBJECT_25_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_25_FILES) /OUT:$(OUTPUT_DIR)\lib25.lib

$(OBJECT_26_FILES):  $(SOURCE_26_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_26_FILES)

$(OUTPUT_DIR)\lib26.lib: $(OBJECT_26_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_26_FILES) /OUT:$(OUTPUT_DIR)\lib26.lib

$(OBJECT_27_FILES):  $(SOURCE_27_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_27_FILES)

$(OUTPUT_DIR)\lib27.lib: $(OBJECT_27_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_27_FILES) /OUT:$(OUTPUT_DIR)\lib27.lib

$(OBJECT_28_FILES):  $(SOURCE_28_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_28_FILES)

$(OUTPUT_DIR)\lib28.lib: $(OBJECT_28_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_28_FILES) /OUT:$(OUTPUT_DIR)\lib28.lib

$(OBJECT_29_FILES):  $(SOURCE_29_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_29_FILES)

$(OUTPUT_DIR)\lib29.lib: $(OBJECT_29_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_29_FILES) /OUT:$(OUTPUT_DIR)\lib29.lib

$(OBJECT_30_FILES):  $(SOURCE_30_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_30_FILES)

$(OUTPUT_DIR)\lib30.lib: $(OBJECT_30_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_30_FILES) /OUT:$(OUTPUT_DIR)\lib30.lib

$(OBJECT_31_FILES):  $(SOURCE_31_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_31_FILES)

$(OUTPUT_DIR)\lib31.lib: $(OBJECT_31_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_31_FILES) /OUT:$(OUTPUT_DIR)\lib31.lib

$(OBJECT_32_FILES):  $(SOURCE_32_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_32_FILES)

$(OUTPUT_DIR)\lib32.lib: $(OBJECT_32_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_32_FILES) /OUT:$(OUTPUT_DIR)\lib32.lib

$(OBJECT_33_FILES):  $(SOURCE_33_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_33_FILES)

$(OUTPUT_DIR)\lib33.lib: $(OBJECT_33_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_33_FILES) /OUT:$(OUTPUT_DIR)\lib33.lib

$(OBJECT_34_FILES):  $(SOURCE_34_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_34_FILES)

$(OUTPUT_DIR)\lib34.lib: $(OBJECT_34_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_34_FILES) /OUT:$(OUTPUT_DIR)\lib34.lib

$(OBJECT_35_FILES):  $(SOURCE_35_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_35_FILES)

$(OUTPUT_DIR)\lib35.lib: $(OBJECT_35_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_35_FILES) /OUT:$(OUTPUT_DIR)\lib35.lib

$(OBJECT_36_FILES):  $(SOURCE_36_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_36_FILES)

$(OUTPUT_DIR)\lib36.lib: $(OBJECT_36_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_36_FILES) /OUT:$(OUTPUT_DIR)\lib36.lib

$(OBJECT_37_FILES):  $(SOURCE_37_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_37_FILES)

$(OUTPUT_DIR)\lib37.lib: $(OBJECT_37_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_37_FILES) /OUT:$(OUTPUT_DIR)\lib37.lib

$(OBJECT_38_FILES):  $(SOURCE_38_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_38_FILES)

$(OUTPUT_DIR)\lib38.lib: $(OBJECT_38_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_38_FILES) /OUT:$(OUTPUT_DIR)\lib38.lib

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(LIB_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(LIB_FILES) /OUT:$@
#    echo  $(OBJECT_FILES) > $(OUTPUT_DIR)\object_files.lst
#    "$(SLINK)" $(SLINK_FLAGS) @$(OUTPUT_DIR)\object_files.lst /OUT:$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


