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

include $(WORKSPACE)/GNUmakefile.Flags

#
# Module Macro Definition
#
MODULE_NAME = OpensslLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/OsStub/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/OsStub/$(MODULE_NAME)

CC_FLAGS += -U_WIN32 -U_WIN64 -DL_ENDIAN -DOPENSSL_SMALL_FOOTPRINT -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -DOPENSSL_SYS_UEFI=1 -DNO_MSABI_VA_FUNCS $(OPENSSL_FLAGS) 


#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_cbc.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_cfb.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_core.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_ecb.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_ige.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_misc.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_ofb.o \
    $(OUTPUT_DIR)/openssl/crypto/aes/aes_wrap.o \
    $(OUTPUT_DIR)/openssl/crypto/aria/aria.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_bitstr.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_d2i_fp.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_digest.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_dup.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_gentm.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_i2d_fp.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_int.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_mbstr.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_object.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_octet.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_print.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_sign.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_strex.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_strnid.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_time.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_type.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_utctm.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_utf8.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/a_verify.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/ameth_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn1_err.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn1_gen.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn1_item_list.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn1_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn1_par.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn_mime.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn_moid.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn_mstbl.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/asn_pack.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/bio_asn1.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/bio_ndef.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/d2i_pr.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/d2i_pu.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/evp_asn1.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/f_int.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/f_string.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/i2d_pr.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/i2d_pu.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/n_pkey.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/nsseq.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/p5_pbe.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/p5_pbev2.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/p5_scrypt.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/p8_pkey.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/t_bitst.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/t_pkey.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/t_spki.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_dec.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_enc.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_fre.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_new.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_scn.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_typ.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/tasn_utl.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_algor.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_bignum.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_info.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_int64.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_long.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_pkey.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_sig.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_spki.o \
    $(OUTPUT_DIR)/openssl/crypto/asn1/x_val.o \
    $(OUTPUT_DIR)/openssl/crypto/async/arch/async_null.o \
    $(OUTPUT_DIR)/openssl/crypto/async/arch/async_posix.o \
    $(OUTPUT_DIR)/openssl/crypto/async/arch/async_win.o \
    $(OUTPUT_DIR)/openssl/crypto/async/async.o \
    $(OUTPUT_DIR)/openssl/crypto/async/async_err.o \
    $(OUTPUT_DIR)/openssl/crypto/async/async_wait.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/b_addr.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/b_dump.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/b_sock.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/b_sock2.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bf_buff.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bf_lbuf.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bf_nbio.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bf_null.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bio_cb.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bio_err.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bio_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bio_meth.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_acpt.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_bio.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_conn.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_dgram.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_fd.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_file.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_log.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_mem.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_null.o \
    $(OUTPUT_DIR)/openssl/crypto/bio/bss_sock.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_add.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_asm.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_blind.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_const.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_ctx.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_depr.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_dh.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_div.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_err.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_exp.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_exp2.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_gcd.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_gf2m.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_intern.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_kron.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_mod.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_mont.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_mpi.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_mul.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_nist.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_prime.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_print.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_rand.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_recp.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_shift.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_sqr.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_sqrt.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_srp.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_word.o \
    $(OUTPUT_DIR)/openssl/crypto/bn/bn_x931p.o \
    $(OUTPUT_DIR)/openssl/crypto/buffer/buf_err.o \
    $(OUTPUT_DIR)/openssl/crypto/buffer/buffer.o \
    $(OUTPUT_DIR)/openssl/crypto/chacha/chacha_enc.o \
    $(OUTPUT_DIR)/openssl/crypto/cmac/cm_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/cmac/cm_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/cmac/cmac.o \
    $(OUTPUT_DIR)/openssl/crypto/comp/c_zlib.o \
    $(OUTPUT_DIR)/openssl/crypto/comp/comp_err.o \
    $(OUTPUT_DIR)/openssl/crypto/comp/comp_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_api.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_def.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_err.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_mall.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_mod.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_sap.o \
    $(OUTPUT_DIR)/openssl/crypto/conf/conf_ssl.o \
    $(OUTPUT_DIR)/openssl/crypto/cpt_err.o \
    $(OUTPUT_DIR)/openssl/crypto/cryptlib.o \
    $(OUTPUT_DIR)/openssl/crypto/ctype.o \
    $(OUTPUT_DIR)/openssl/crypto/cversion.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_asn1.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_check.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_depr.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_err.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_gen.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_kdf.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_key.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_meth.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_rfc5114.o \
    $(OUTPUT_DIR)/openssl/crypto/dh/dh_rfc7919.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_dl.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_dlfcn.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_err.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_openssl.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_vms.o \
    $(OUTPUT_DIR)/openssl/crypto/dso/dso_win32.o \
    $(OUTPUT_DIR)/openssl/crypto/ebcdic.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve25519.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve448/arch_32/f_impl.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve448/curve448.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve448/curve448_tables.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve448/eddsa.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve448/f_generic.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/curve448/scalar.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec2_oct.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec2_smpl.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_asn1.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_check.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_curve.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_cvt.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_err.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_key.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_kmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_mult.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_oct.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ec_print.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecdh_kdf.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecdh_ossl.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecdsa_ossl.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecdsa_sign.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecdsa_vrf.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/eck_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_mont.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_nist.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistp224.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistp256.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistp521.o\
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistputil.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_oct.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecp_smpl.o \
    $(OUTPUT_DIR)/openssl/crypto/ec/ecx_meth.o \
    $(OUTPUT_DIR)/openssl/crypto/err/err.o \
    $(OUTPUT_DIR)/openssl/crypto/err/err_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/bio_b64.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/bio_enc.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/bio_md.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/bio_ok.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/c_allc.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/c_alld.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/cmeth_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/digest.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_aes.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_aes_cbc_hmac_sha256.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_aria.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_bf.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_camellia.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_cast.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_chacha20_poly1305.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_null.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_old.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_seed.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/e_xcbc_d.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/encode.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_cnf.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_enc.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_err.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_key.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_pbe.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/evp_pkey.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_md5.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_mdc2.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_null.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_ripemd.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_sha1.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_sha3.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_sigver.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/m_wp.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/names.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p5_crpt.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p5_crpt2.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_dec.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_enc.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_open.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_seal.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_sign.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/p_verify.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/pbe_scrypt.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/pmeth_fn.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/pmeth_gn.o \
    $(OUTPUT_DIR)/openssl/crypto/evp/pmeth_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/ex_data.o \
    $(OUTPUT_DIR)/openssl/crypto/getenv.o \
    $(OUTPUT_DIR)/openssl/crypto/hmac/hm_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/hmac/hm_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/hmac/hmac.o \
    $(OUTPUT_DIR)/openssl/crypto/init.o \
    $(OUTPUT_DIR)/openssl/crypto/kdf/hkdf.o \
    $(OUTPUT_DIR)/openssl/crypto/kdf/kdf_err.o \
    $(OUTPUT_DIR)/openssl/crypto/kdf/scrypt.o \
    $(OUTPUT_DIR)/openssl/crypto/kdf/tls1_prf.o \
    $(OUTPUT_DIR)/openssl/crypto/lhash/lh_stats.o \
    $(OUTPUT_DIR)/openssl/crypto/lhash/lhash.o \
    $(OUTPUT_DIR)/openssl/crypto/md5/md5_dgst.o \
    $(OUTPUT_DIR)/openssl/crypto/md5/md5_one.o \
    $(OUTPUT_DIR)/openssl/crypto/mem.o \
    $(OUTPUT_DIR)/openssl/crypto/mem_clr.o \
    $(OUTPUT_DIR)/openssl/crypto/mem_dbg.o \
    $(OUTPUT_DIR)/openssl/crypto/mem_sec.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/cbc128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/ccm128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/cfb128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/ctr128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/cts128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/gcm128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/ocb128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/ofb128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/wrap128.o \
    $(OUTPUT_DIR)/openssl/crypto/modes/xts128.o \
    $(OUTPUT_DIR)/openssl/crypto/o_dir.o \
    $(OUTPUT_DIR)/openssl/crypto/o_fips.o \
    $(OUTPUT_DIR)/openssl/crypto/o_fopen.o \
    $(OUTPUT_DIR)/openssl/crypto/o_init.o \
    $(OUTPUT_DIR)/openssl/crypto/o_str.o \
    $(OUTPUT_DIR)/openssl/crypto/o_time.o \
    $(OUTPUT_DIR)/openssl/crypto/objects/o_names.o \
    $(OUTPUT_DIR)/openssl/crypto/objects/obj_dat.o \
    $(OUTPUT_DIR)/openssl/crypto/objects/obj_err.o \
    $(OUTPUT_DIR)/openssl/crypto/objects/obj_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/objects/obj_xref.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_asn.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_cl.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_err.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_ext.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_ht.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_srv.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_vfy.o \
    $(OUTPUT_DIR)/openssl/crypto/ocsp/v3_ocsp.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_all.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_err.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_info.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_oth.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_pk8.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_pkey.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_sign.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_x509.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pem_xaux.o \
    $(OUTPUT_DIR)/openssl/crypto/pem/pvkfmt.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_add.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_asn.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_attr.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_crpt.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_crt.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_decr.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_init.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_key.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_kiss.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_mutl.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_npas.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_p8d.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_p8e.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_sbag.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_utl.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs12/pk12err.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/bio_pk7.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_asn1.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_attr.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_doit.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_mime.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_smime.o \
    $(OUTPUT_DIR)/openssl/crypto/pkcs7/pkcs7err.o \
    $(OUTPUT_DIR)/openssl/crypto/poly1305/poly1305.o \
    $(OUTPUT_DIR)/openssl/crypto/poly1305/poly1305_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/poly1305/poly1305_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/drbg_ctr.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/drbg_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/rand_egd.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/rand_err.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/rand_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/rand_unix.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/rand_vms.o \
    $(OUTPUT_DIR)/openssl/crypto/rand/rand_win.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_asn1.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_chk.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_crpt.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_depr.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_err.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_gen.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_meth.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_mp.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_none.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_oaep.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_ossl.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_pk1.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_pss.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_saos.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_sign.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_ssl.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_x931.o \
    $(OUTPUT_DIR)/openssl/crypto/rsa/rsa_x931g.o \
    $(OUTPUT_DIR)/openssl/crypto/sha/keccak1600.o \
    $(OUTPUT_DIR)/openssl/crypto/sha/sha1_one.o \
    $(OUTPUT_DIR)/openssl/crypto/sha/sha1dgst.o \
    $(OUTPUT_DIR)/openssl/crypto/sha/sha256.o \
    $(OUTPUT_DIR)/openssl/crypto/sha/sha512.o \
    $(OUTPUT_DIR)/openssl/crypto/siphash/siphash.o \
    $(OUTPUT_DIR)/openssl/crypto/siphash/siphash_ameth.o \
    $(OUTPUT_DIR)/openssl/crypto/siphash/siphash_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/sm2/sm2_crypt.o \
    $(OUTPUT_DIR)/openssl/crypto/sm2/sm2_err.o \
    $(OUTPUT_DIR)/openssl/crypto/sm2/sm2_pmeth.o \
    $(OUTPUT_DIR)/openssl/crypto/sm2/sm2_sign.o \
    $(OUTPUT_DIR)/openssl/crypto/sm3/m_sm3.o \
    $(OUTPUT_DIR)/openssl/crypto/sm3/sm3.o \
    $(OUTPUT_DIR)/openssl/crypto/sm4/sm4.o \
    $(OUTPUT_DIR)/openssl/crypto/stack/stack.o \
    $(OUTPUT_DIR)/openssl/crypto/threads_none.o \
    $(OUTPUT_DIR)/openssl/crypto/threads_pthread.o \
    $(OUTPUT_DIR)/openssl/crypto/threads_win.o \
    $(OUTPUT_DIR)/openssl/crypto/txt_db/txt_db.o \
    $(OUTPUT_DIR)/openssl/crypto/ui/ui_err.o \
    $(OUTPUT_DIR)/openssl/crypto/ui/ui_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/ui/ui_null.o \
    $(OUTPUT_DIR)/openssl/crypto/ui/ui_openssl.o \
    $(OUTPUT_DIR)/openssl/crypto/ui/ui_util.o \
    $(OUTPUT_DIR)/openssl/crypto/uid.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/by_dir.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/by_file.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/t_crl.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/t_req.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/t_x509.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_att.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_cmp.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_d2.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_def.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_err.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_ext.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_lu.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_meth.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_obj.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_r2x.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_req.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_set.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_trs.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_txt.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_v3.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_vfy.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509_vpm.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509cset.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509name.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509rset.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509spki.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x509type.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_all.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_attrib.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_crl.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_exten.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_name.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_pubkey.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_req.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_x509.o \
    $(OUTPUT_DIR)/openssl/crypto/x509/x_x509a.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_cache.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_data.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_map.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_node.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_tree.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_addr.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_admis.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_akey.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_akeya.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_alt.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_asid.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_bcons.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_bitst.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_conf.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_cpols.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_crld.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_enum.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_extku.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_genn.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_ia5.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_info.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_int.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_lib.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_ncons.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pci.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pcia.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pcons.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pku.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pmaps.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_prn.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_purp.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_skey.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_sxnet.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_tlsf.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3_utl.o \
    $(OUTPUT_DIR)/openssl/crypto/x509v3/v3err.o \
    $(OUTPUT_DIR)/ossl_store.o \
    $(OUTPUT_DIR)/rand_pool.o \


INC =  \
    -I$(SOURCE_DIR)/openssl/crypto/store \
    -I$(SOURCE_DIR)/openssl/crypto/x509v3 \
    -I$(SOURCE_DIR)/openssl/crypto/x509 \
    -I$(SOURCE_DIR)/openssl/crypto/ui \
    -I$(SOURCE_DIR)/openssl/crypto/txt_db \
    -I$(SOURCE_DIR)/openssl/crypto/stack \
    -I$(SOURCE_DIR)/openssl/crypto/siphash \
    -I$(SOURCE_DIR)/openssl/crypto/sha \
    -I$(SOURCE_DIR)/openssl/crypto/rsa \
    -I$(SOURCE_DIR)/openssl/crypto/rand \
    -I$(SOURCE_DIR)/openssl/crypto/poly1305 \
    -I$(SOURCE_DIR)/openssl/crypto/pkcs7 \
    -I$(SOURCE_DIR)/openssl/crypto/pkcs12 \
    -I$(SOURCE_DIR)/openssl/crypto/pem \
    -I$(SOURCE_DIR)/openssl/crypto/ocsp \
    -I$(SOURCE_DIR)/openssl/crypto/objects \
    -I$(SOURCE_DIR)/openssl/crypto/modes \
    -I$(SOURCE_DIR)/openssl/crypto/md5 \
    -I$(SOURCE_DIR)/openssl/crypto/lhash \
    -I$(SOURCE_DIR)/openssl/crypto/kdf \
    -I$(SOURCE_DIR)/openssl/crypto/hmac \
    -I$(SOURCE_DIR)/openssl/crypto/evp \
    -I$(SOURCE_DIR)/openssl/crypto/err \
    -I$(SOURCE_DIR)/openssl/crypto/dso \
    -I$(SOURCE_DIR)/openssl/crypto/ec \
    -I$(SOURCE_DIR)/openssl/crypto/ec/curve448 \
    -I$(SOURCE_DIR)/openssl/crypto/ec/curve448/arch_32 \
    -I$(SOURCE_DIR)/openssl/crypto/dh \
    -I$(SOURCE_DIR)/openssl/crypto \
    -I$(SOURCE_DIR)/openssl/crypto/conf \
    -I$(SOURCE_DIR)/openssl/crypto/comp \
    -I$(SOURCE_DIR)/openssl/crypto/cmac \
    -I$(SOURCE_DIR)/openssl/crypto/chacha \
    -I$(SOURCE_DIR)/openssl/crypto/buffer \
    -I$(SOURCE_DIR)/openssl/crypto/bn \
    -I$(SOURCE_DIR)/openssl/crypto/bio \
    -I$(SOURCE_DIR)/openssl/crypto/async \
    -I$(SOURCE_DIR)/openssl/crypto/async/arch \
    -I$(SOURCE_DIR)/openssl/crypto/asn1 \
    -I$(SOURCE_DIR)/openssl/crypto/aria \
    -I$(SOURCE_DIR)/openssl/crypto/aes \
    -I$(SOURCE_DIR)/openssl/crypto/sm2 \
    -I$(SOURCE_DIR)/openssl/crypto/sm3 \
    -I$(SOURCE_DIR)/openssl/crypto/sm4 \
    -I$(SOURCE_DIR)/openssl/ms \
    -I$(SOURCE_DIR)/openssl \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include \
    -I$(WORKSPACE)/OsStub/OpensslLib/Include \
    -I$(WORKSPACE)/OsStub/OpensslLib/openssl/include \
    -I$(WORKSPACE)/OsStub/OpensslLib/openssl/crypto/include

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)/$(MODULE_NAME).a

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
	-@$(MD) $(OUTPUT_DIR)
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/store
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/x509v3
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/x509
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/ui
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/txt_db
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/stack
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/siphash
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/sha
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/rsa
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/rand
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/poly1305
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/pkcs7
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/pkcs12
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/pem
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/ocsp
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/objects
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/modes
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/md5
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/lhash
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/kdf
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/hmac
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/evp
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/err
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/dso
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/ec
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/ec/curve448
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/ec/curve448/arch_32
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/dh
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/conf
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/comp
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/cmac
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/chacha
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/buffer
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/bn
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/bio
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/async
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/async/arch
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/asn1
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/aria
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/aes
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/sm2
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/sm3
	-@$(MD) $(OUTPUT_DIR)/openssl/crypto/sm4
	-@$(MD) $(OUTPUT_DIR)/openssl/ms
	-@$(MD) $(OUTPUT_DIR)/openssl
#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/openssl/crypto/aes/aes_cbc.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_cbc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_cfb.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_cfb.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_core.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_core.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_ecb.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_ecb.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_ige.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_ige.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_misc.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_misc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_ofb.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_ofb.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aes/aes_wrap.o : $(SOURCE_DIR)/openssl/crypto/aes/aes_wrap.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/aria/aria.o : $(SOURCE_DIR)/openssl/crypto/aria/aria.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_bitstr.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_bitstr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_d2i_fp.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_d2i_fp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_digest.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_digest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_dup.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_dup.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_gentm.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_gentm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_i2d_fp.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_i2d_fp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_int.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_int.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_mbstr.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_mbstr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_object.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_object.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_octet.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_octet.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_print.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_print.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_sign.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_strex.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_strex.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_strnid.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_strnid.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_time.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_time.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_type.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_type.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_utctm.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_utctm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_utf8.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_utf8.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/a_verify.o : $(SOURCE_DIR)/openssl/crypto/asn1/a_verify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/ameth_lib.o : $(SOURCE_DIR)/openssl/crypto/asn1/ameth_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn1_err.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn1_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn1_gen.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn1_gen.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn1_item_list.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn1_item_list.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn1_lib.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn1_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn1_par.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn1_par.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn_mime.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn_mime.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn_moid.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn_moid.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn_mstbl.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn_mstbl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/asn_pack.o : $(SOURCE_DIR)/openssl/crypto/asn1/asn_pack.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/bio_asn1.o : $(SOURCE_DIR)/openssl/crypto/asn1/bio_asn1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/bio_ndef.o : $(SOURCE_DIR)/openssl/crypto/asn1/bio_ndef.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/d2i_pr.o : $(SOURCE_DIR)/openssl/crypto/asn1/d2i_pr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/d2i_pu.o : $(SOURCE_DIR)/openssl/crypto/asn1/d2i_pu.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/evp_asn1.o : $(SOURCE_DIR)/openssl/crypto/asn1/evp_asn1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/f_int.o : $(SOURCE_DIR)/openssl/crypto/asn1/f_int.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/f_string.o : $(SOURCE_DIR)/openssl/crypto/asn1/f_string.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/i2d_pr.o : $(SOURCE_DIR)/openssl/crypto/asn1/i2d_pr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/i2d_pu.o : $(SOURCE_DIR)/openssl/crypto/asn1/i2d_pu.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/n_pkey.o : $(SOURCE_DIR)/openssl/crypto/asn1/n_pkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/nsseq.o : $(SOURCE_DIR)/openssl/crypto/asn1/nsseq.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/p5_pbe.o : $(SOURCE_DIR)/openssl/crypto/asn1/p5_pbe.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/p5_pbev2.o : $(SOURCE_DIR)/openssl/crypto/asn1/p5_pbev2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/p5_scrypt.o : $(SOURCE_DIR)/openssl/crypto/asn1/p5_scrypt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/p8_pkey.o : $(SOURCE_DIR)/openssl/crypto/asn1/p8_pkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/t_bitst.o : $(SOURCE_DIR)/openssl/crypto/asn1/t_bitst.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/t_pkey.o : $(SOURCE_DIR)/openssl/crypto/asn1/t_pkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/t_spki.o : $(SOURCE_DIR)/openssl/crypto/asn1/t_spki.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_dec.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_dec.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_enc.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_enc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_fre.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_fre.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_new.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_new.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_prn.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_scn.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_scn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_typ.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_typ.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/tasn_utl.o : $(SOURCE_DIR)/openssl/crypto/asn1/tasn_utl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_algor.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_algor.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_bignum.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_bignum.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_info.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_info.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_int64.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_int64.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_long.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_long.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_pkey.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_pkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_sig.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_sig.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_spki.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_spki.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/asn1/x_val.o : $(SOURCE_DIR)/openssl/crypto/asn1/x_val.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/async/arch/async_null.o : $(SOURCE_DIR)/openssl/crypto/async/arch/async_null.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/async/arch/async_posix.o : $(SOURCE_DIR)/openssl/crypto/async/arch/async_posix.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/async/arch/async_win.o : $(SOURCE_DIR)/openssl/crypto/async/arch/async_win.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/async/async.o : $(SOURCE_DIR)/openssl/crypto/async/async.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/async/async_err.o : $(SOURCE_DIR)/openssl/crypto/async/async_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/async/async_wait.o : $(SOURCE_DIR)/openssl/crypto/async/async_wait.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/b_addr.o : $(SOURCE_DIR)/openssl/crypto/bio/b_addr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/b_dump.o : $(SOURCE_DIR)/openssl/crypto/bio/b_dump.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/b_sock.o : $(SOURCE_DIR)/openssl/crypto/bio/b_sock.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/b_sock2.o : $(SOURCE_DIR)/openssl/crypto/bio/b_sock2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bf_buff.o : $(SOURCE_DIR)/openssl/crypto/bio/bf_buff.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bf_lbuf.o : $(SOURCE_DIR)/openssl/crypto/bio/bf_lbuf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bf_nbio.o : $(SOURCE_DIR)/openssl/crypto/bio/bf_nbio.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bf_null.o : $(SOURCE_DIR)/openssl/crypto/bio/bf_null.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bio_cb.o : $(SOURCE_DIR)/openssl/crypto/bio/bio_cb.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bio_err.o : $(SOURCE_DIR)/openssl/crypto/bio/bio_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bio_lib.o : $(SOURCE_DIR)/openssl/crypto/bio/bio_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bio_meth.o : $(SOURCE_DIR)/openssl/crypto/bio/bio_meth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_acpt.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_acpt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_bio.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_bio.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_conn.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_conn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_dgram.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_dgram.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_fd.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_fd.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_file.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_file.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_log.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_log.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_mem.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_mem.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_null.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_null.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bio/bss_sock.o : $(SOURCE_DIR)/openssl/crypto/bio/bss_sock.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_add.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_add.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_asm.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_asm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_blind.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_blind.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_const.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_const.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_ctx.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_ctx.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_depr.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_depr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_dh.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_dh.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_div.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_div.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_err.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_exp.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_exp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_exp2.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_exp2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_gcd.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_gcd.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_gf2m.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_gf2m.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_intern.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_intern.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_kron.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_kron.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_lib.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_mod.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_mod.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_mont.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_mont.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_mpi.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_mpi.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_mul.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_mul.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_nist.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_nist.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_prime.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_prime.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_print.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_print.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_rand.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_rand.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_recp.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_recp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_shift.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_shift.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_sqr.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_sqr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_sqrt.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_sqrt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_srp.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_srp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_word.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_word.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/bn/bn_x931p.o : $(SOURCE_DIR)/openssl/crypto/bn/bn_x931p.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/buffer/buf_err.o : $(SOURCE_DIR)/openssl/crypto/buffer/buf_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/buffer/buffer.o : $(SOURCE_DIR)/openssl/crypto/buffer/buffer.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/chacha/chacha_enc.o : $(SOURCE_DIR)/openssl/crypto/chacha/chacha_enc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/cmac/cm_ameth.o : $(SOURCE_DIR)/openssl/crypto/cmac/cm_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/cmac/cm_pmeth.o : $(SOURCE_DIR)/openssl/crypto/cmac/cm_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/cmac/cmac.o : $(SOURCE_DIR)/openssl/crypto/cmac/cmac.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/comp/c_zlib.o : $(SOURCE_DIR)/openssl/crypto/comp/c_zlib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/comp/comp_err.o : $(SOURCE_DIR)/openssl/crypto/comp/comp_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/comp/comp_lib.o : $(SOURCE_DIR)/openssl/crypto/comp/comp_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_api.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_api.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_def.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_def.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_err.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_lib.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_mall.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_mall.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_mod.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_mod.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_sap.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_sap.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/conf/conf_ssl.o : $(SOURCE_DIR)/openssl/crypto/conf/conf_ssl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/cpt_err.o : $(SOURCE_DIR)/openssl/crypto/cpt_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/cryptlib.o : $(SOURCE_DIR)/openssl/crypto/cryptlib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ctype.o : $(SOURCE_DIR)/openssl/crypto/ctype.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/cversion.o : $(SOURCE_DIR)/openssl/crypto/cversion.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_ameth.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_asn1.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_asn1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_check.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_check.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_depr.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_depr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_err.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_gen.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_gen.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_kdf.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_kdf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_key.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_key.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_lib.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_meth.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_meth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_pmeth.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_prn.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_rfc5114.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_rfc5114.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dh/dh_rfc7919.o : $(SOURCE_DIR)/openssl/crypto/dh/dh_rfc7919.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_dl.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_dl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_dlfcn.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_dlfcn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_err.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_lib.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_openssl.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_openssl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_vms.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_vms.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/dso/dso_win32.o : $(SOURCE_DIR)/openssl/crypto/dso/dso_win32.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ebcdic.o : $(SOURCE_DIR)/openssl/crypto/ebcdic.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve25519.o : $(SOURCE_DIR)/openssl/crypto/ec/curve25519.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve448/arch_32/f_impl.o : $(SOURCE_DIR)/openssl/crypto/ec/curve448/arch_32/f_impl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve448/curve448.o : $(SOURCE_DIR)/openssl/crypto/ec/curve448/curve448.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve448/curve448_tables.o : $(SOURCE_DIR)/openssl/crypto/ec/curve448/curve448_tables.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve448/eddsa.o : $(SOURCE_DIR)/openssl/crypto/ec/curve448/eddsa.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve448/f_generic.o : $(SOURCE_DIR)/openssl/crypto/ec/curve448/f_generic.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/curve448/scalar.o : $(SOURCE_DIR)/openssl/crypto/ec/curve448/scalar.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec2_oct.o : $(SOURCE_DIR)/openssl/crypto/ec/ec2_oct.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec2_smpl.o : $(SOURCE_DIR)/openssl/crypto/ec/ec2_smpl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_ameth.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_asn1.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_asn1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_check.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_check.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_curve.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_curve.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_cvt.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_cvt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_err.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_key.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_key.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_kmeth.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_kmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_lib.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_mult.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_mult.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_oct.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_oct.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_pmeth.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ec_print.o : $(SOURCE_DIR)/openssl/crypto/ec/ec_print.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecdh_kdf.o : $(SOURCE_DIR)/openssl/crypto/ec/ecdh_kdf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecdh_ossl.o : $(SOURCE_DIR)/openssl/crypto/ec/ecdh_ossl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecdsa_ossl.o : $(SOURCE_DIR)/openssl/crypto/ec/ecdsa_ossl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecdsa_sign.o : $(SOURCE_DIR)/openssl/crypto/ec/ecdsa_sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecdsa_vrf.o : $(SOURCE_DIR)/openssl/crypto/ec/ecdsa_vrf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/eck_prn.o : $(SOURCE_DIR)/openssl/crypto/ec/eck_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_mont.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_mont.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_nist.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_nist.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistp224.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_nistp224.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistp256.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_nistp256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistp521.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_nistp521.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_nistputil.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_nistputil.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_oct.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_oct.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecp_smpl.o : $(SOURCE_DIR)/openssl/crypto/ec/ecp_smpl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ec/ecx_meth.o : $(SOURCE_DIR)/openssl/crypto/ec/ecx_meth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/err/err.o : $(SOURCE_DIR)/openssl/crypto/err/err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/err/err_prn.o : $(SOURCE_DIR)/openssl/crypto/err/err_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/bio_b64.o : $(SOURCE_DIR)/openssl/crypto/evp/bio_b64.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/bio_enc.o : $(SOURCE_DIR)/openssl/crypto/evp/bio_enc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/bio_md.o : $(SOURCE_DIR)/openssl/crypto/evp/bio_md.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/bio_ok.o : $(SOURCE_DIR)/openssl/crypto/evp/bio_ok.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/c_allc.o : $(SOURCE_DIR)/openssl/crypto/evp/c_allc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/c_alld.o : $(SOURCE_DIR)/openssl/crypto/evp/c_alld.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/cmeth_lib.o : $(SOURCE_DIR)/openssl/crypto/evp/cmeth_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/digest.o : $(SOURCE_DIR)/openssl/crypto/evp/digest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_aes.o : $(SOURCE_DIR)/openssl/crypto/evp/e_aes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_aes_cbc_hmac_sha256.o : $(SOURCE_DIR)/openssl/crypto/evp/e_aes_cbc_hmac_sha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_aria.o : $(SOURCE_DIR)/openssl/crypto/evp/e_aria.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_bf.o : $(SOURCE_DIR)/openssl/crypto/evp/e_bf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_camellia.o : $(SOURCE_DIR)/openssl/crypto/evp/e_camellia.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_cast.o : $(SOURCE_DIR)/openssl/crypto/evp/e_cast.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_chacha20_poly1305.o : $(SOURCE_DIR)/openssl/crypto/evp/e_chacha20_poly1305.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_null.o : $(SOURCE_DIR)/openssl/crypto/evp/e_null.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_old.o : $(SOURCE_DIR)/openssl/crypto/evp/e_old.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_seed.o : $(SOURCE_DIR)/openssl/crypto/evp/e_seed.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/e_xcbc_d.o : $(SOURCE_DIR)/openssl/crypto/evp/e_xcbc_d.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/encode.o : $(SOURCE_DIR)/openssl/crypto/evp/encode.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_cnf.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_cnf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_enc.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_enc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_err.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_key.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_key.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_lib.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_pbe.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_pbe.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/evp_pkey.o : $(SOURCE_DIR)/openssl/crypto/evp/evp_pkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_md5.o : $(SOURCE_DIR)/openssl/crypto/evp/m_md5.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_mdc2.o : $(SOURCE_DIR)/openssl/crypto/evp/m_mdc2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_null.o : $(SOURCE_DIR)/openssl/crypto/evp/m_null.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_ripemd.o : $(SOURCE_DIR)/openssl/crypto/evp/m_ripemd.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_sha1.o : $(SOURCE_DIR)/openssl/crypto/evp/m_sha1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_sha3.o : $(SOURCE_DIR)/openssl/crypto/evp/m_sha3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_sigver.o : $(SOURCE_DIR)/openssl/crypto/evp/m_sigver.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/m_wp.o : $(SOURCE_DIR)/openssl/crypto/evp/m_wp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/names.o : $(SOURCE_DIR)/openssl/crypto/evp/names.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p5_crpt.o : $(SOURCE_DIR)/openssl/crypto/evp/p5_crpt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p5_crpt2.o : $(SOURCE_DIR)/openssl/crypto/evp/p5_crpt2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_dec.o : $(SOURCE_DIR)/openssl/crypto/evp/p_dec.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_enc.o : $(SOURCE_DIR)/openssl/crypto/evp/p_enc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_lib.o : $(SOURCE_DIR)/openssl/crypto/evp/p_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_open.o : $(SOURCE_DIR)/openssl/crypto/evp/p_open.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_seal.o : $(SOURCE_DIR)/openssl/crypto/evp/p_seal.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_sign.o : $(SOURCE_DIR)/openssl/crypto/evp/p_sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/p_verify.o : $(SOURCE_DIR)/openssl/crypto/evp/p_verify.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/pbe_scrypt.o : $(SOURCE_DIR)/openssl/crypto/evp/pbe_scrypt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/pmeth_fn.o : $(SOURCE_DIR)/openssl/crypto/evp/pmeth_fn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/pmeth_gn.o : $(SOURCE_DIR)/openssl/crypto/evp/pmeth_gn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/evp/pmeth_lib.o : $(SOURCE_DIR)/openssl/crypto/evp/pmeth_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ex_data.o : $(SOURCE_DIR)/openssl/crypto/ex_data.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/getenv.o : $(SOURCE_DIR)/openssl/crypto/getenv.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/hmac/hm_ameth.o : $(SOURCE_DIR)/openssl/crypto/hmac/hm_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/hmac/hm_pmeth.o : $(SOURCE_DIR)/openssl/crypto/hmac/hm_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/hmac/hmac.o : $(SOURCE_DIR)/openssl/crypto/hmac/hmac.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/init.o : $(SOURCE_DIR)/openssl/crypto/init.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/kdf/hkdf.o : $(SOURCE_DIR)/openssl/crypto/kdf/hkdf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/kdf/kdf_err.o : $(SOURCE_DIR)/openssl/crypto/kdf/kdf_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/kdf/scrypt.o : $(SOURCE_DIR)/openssl/crypto/kdf/scrypt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/kdf/tls1_prf.o : $(SOURCE_DIR)/openssl/crypto/kdf/tls1_prf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/lhash/lh_stats.o : $(SOURCE_DIR)/openssl/crypto/lhash/lh_stats.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/lhash/lhash.o : $(SOURCE_DIR)/openssl/crypto/lhash/lhash.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/md5/md5_dgst.o : $(SOURCE_DIR)/openssl/crypto/md5/md5_dgst.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/md5/md5_one.o : $(SOURCE_DIR)/openssl/crypto/md5/md5_one.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/mem.o : $(SOURCE_DIR)/openssl/crypto/mem.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/mem_clr.o : $(SOURCE_DIR)/openssl/crypto/mem_clr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/mem_dbg.o : $(SOURCE_DIR)/openssl/crypto/mem_dbg.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/mem_sec.o : $(SOURCE_DIR)/openssl/crypto/mem_sec.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/cbc128.o : $(SOURCE_DIR)/openssl/crypto/modes/cbc128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/ccm128.o : $(SOURCE_DIR)/openssl/crypto/modes/ccm128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/cfb128.o : $(SOURCE_DIR)/openssl/crypto/modes/cfb128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/ctr128.o : $(SOURCE_DIR)/openssl/crypto/modes/ctr128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/cts128.o : $(SOURCE_DIR)/openssl/crypto/modes/cts128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/gcm128.o : $(SOURCE_DIR)/openssl/crypto/modes/gcm128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/ocb128.o : $(SOURCE_DIR)/openssl/crypto/modes/ocb128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/ofb128.o : $(SOURCE_DIR)/openssl/crypto/modes/ofb128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/wrap128.o : $(SOURCE_DIR)/openssl/crypto/modes/wrap128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/modes/xts128.o : $(SOURCE_DIR)/openssl/crypto/modes/xts128.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/o_dir.o : $(SOURCE_DIR)/openssl/crypto/o_dir.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/o_fips.o : $(SOURCE_DIR)/openssl/crypto/o_fips.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/o_fopen.o : $(SOURCE_DIR)/openssl/crypto/o_fopen.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/o_init.o : $(SOURCE_DIR)/openssl/crypto/o_init.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/o_str.o : $(SOURCE_DIR)/openssl/crypto/o_str.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/o_time.o : $(SOURCE_DIR)/openssl/crypto/o_time.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/objects/o_names.o : $(SOURCE_DIR)/openssl/crypto/objects/o_names.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/objects/obj_dat.o : $(SOURCE_DIR)/openssl/crypto/objects/obj_dat.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/objects/obj_err.o : $(SOURCE_DIR)/openssl/crypto/objects/obj_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/objects/obj_lib.o : $(SOURCE_DIR)/openssl/crypto/objects/obj_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/objects/obj_xref.o : $(SOURCE_DIR)/openssl/crypto/objects/obj_xref.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_asn.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_asn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_cl.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_cl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_err.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_ext.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_ext.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_ht.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_ht.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_lib.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_prn.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_srv.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_srv.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/ocsp_vfy.o : $(SOURCE_DIR)/openssl/crypto/ocsp/ocsp_vfy.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ocsp/v3_ocsp.o : $(SOURCE_DIR)/openssl/crypto/ocsp/v3_ocsp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_all.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_all.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_err.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_info.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_info.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_lib.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_oth.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_oth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_pk8.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_pk8.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_pkey.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_pkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_sign.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_x509.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_x509.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pem_xaux.o : $(SOURCE_DIR)/openssl/crypto/pem/pem_xaux.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pem/pvkfmt.o : $(SOURCE_DIR)/openssl/crypto/pem/pvkfmt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_add.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_add.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_asn.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_asn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_attr.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_attr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_crpt.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_crpt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_crt.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_crt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_decr.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_decr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_init.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_init.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_key.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_key.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_kiss.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_kiss.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_mutl.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_mutl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_npas.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_npas.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_p8d.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_p8d.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_p8e.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_p8e.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_sbag.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_sbag.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/p12_utl.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/p12_utl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs12/pk12err.o : $(SOURCE_DIR)/openssl/crypto/pkcs12/pk12err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/bio_pk7.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/bio_pk7.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_asn1.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pk7_asn1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_attr.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pk7_attr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_doit.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pk7_doit.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_lib.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pk7_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_mime.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pk7_mime.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pk7_smime.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pk7_smime.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/pkcs7/pkcs7err.o : $(SOURCE_DIR)/openssl/crypto/pkcs7/pkcs7err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/poly1305/poly1305.o : $(SOURCE_DIR)/openssl/crypto/poly1305/poly1305.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/poly1305/poly1305_ameth.o : $(SOURCE_DIR)/openssl/crypto/poly1305/poly1305_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/poly1305/poly1305_pmeth.o : $(SOURCE_DIR)/openssl/crypto/poly1305/poly1305_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/drbg_ctr.o : $(SOURCE_DIR)/openssl/crypto/rand/drbg_ctr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/drbg_lib.o : $(SOURCE_DIR)/openssl/crypto/rand/drbg_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/rand_egd.o : $(SOURCE_DIR)/openssl/crypto/rand/rand_egd.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/rand_err.o : $(SOURCE_DIR)/openssl/crypto/rand/rand_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/rand_lib.o : $(SOURCE_DIR)/openssl/crypto/rand/rand_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/rand_unix.o : $(SOURCE_DIR)/openssl/crypto/rand/rand_unix.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/rand_vms.o : $(SOURCE_DIR)/openssl/crypto/rand/rand_vms.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rand/rand_win.o : $(SOURCE_DIR)/openssl/crypto/rand/rand_win.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_ameth.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_asn1.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_asn1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_chk.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_chk.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_crpt.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_crpt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_depr.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_depr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_err.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_gen.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_gen.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_lib.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_meth.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_meth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_mp.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_mp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_none.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_none.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_oaep.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_oaep.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_ossl.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_ossl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_pk1.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_pk1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_pmeth.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_prn.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_pss.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_pss.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_saos.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_saos.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_sign.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_ssl.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_ssl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_x931.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_x931.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/rsa/rsa_x931g.o : $(SOURCE_DIR)/openssl/crypto/rsa/rsa_x931g.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sha/keccak1600.o : $(SOURCE_DIR)/openssl/crypto/sha/keccak1600.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sha/sha1_one.o : $(SOURCE_DIR)/openssl/crypto/sha/sha1_one.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sha/sha1dgst.o : $(SOURCE_DIR)/openssl/crypto/sha/sha1dgst.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sha/sha256.o : $(SOURCE_DIR)/openssl/crypto/sha/sha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sha/sha512.o : $(SOURCE_DIR)/openssl/crypto/sha/sha512.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/siphash/siphash.o : $(SOURCE_DIR)/openssl/crypto/siphash/siphash.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/siphash/siphash_ameth.o : $(SOURCE_DIR)/openssl/crypto/siphash/siphash_ameth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/siphash/siphash_pmeth.o : $(SOURCE_DIR)/openssl/crypto/siphash/siphash_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/stack/stack.o : $(SOURCE_DIR)/openssl/crypto/stack/stack.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/threads_none.o : $(SOURCE_DIR)/openssl/crypto/threads_none.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/threads_pthread.o : $(SOURCE_DIR)/openssl/crypto/threads_pthread.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/threads_win.o : $(SOURCE_DIR)/openssl/crypto/threads_win.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/txt_db/txt_db.o : $(SOURCE_DIR)/openssl/crypto/txt_db/txt_db.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ui/ui_err.o : $(SOURCE_DIR)/openssl/crypto/ui/ui_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ui/ui_lib.o : $(SOURCE_DIR)/openssl/crypto/ui/ui_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ui/ui_null.o : $(SOURCE_DIR)/openssl/crypto/ui/ui_null.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ui/ui_openssl.o : $(SOURCE_DIR)/openssl/crypto/ui/ui_openssl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/ui/ui_util.o : $(SOURCE_DIR)/openssl/crypto/ui/ui_util.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/uid.o : $(SOURCE_DIR)/openssl/crypto/uid.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/by_dir.o : $(SOURCE_DIR)/openssl/crypto/x509/by_dir.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/by_file.o : $(SOURCE_DIR)/openssl/crypto/x509/by_file.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/t_crl.o : $(SOURCE_DIR)/openssl/crypto/x509/t_crl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/t_req.o : $(SOURCE_DIR)/openssl/crypto/x509/t_req.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/t_x509.o : $(SOURCE_DIR)/openssl/crypto/x509/t_x509.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_att.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_att.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_cmp.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_cmp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_d2.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_d2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_def.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_def.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_err.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_ext.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_ext.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_lu.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_lu.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_meth.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_meth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_obj.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_obj.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_r2x.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_r2x.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_req.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_req.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_set.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_set.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_trs.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_trs.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_txt.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_txt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_v3.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_v3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_vfy.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_vfy.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509_vpm.o : $(SOURCE_DIR)/openssl/crypto/x509/x509_vpm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509cset.o : $(SOURCE_DIR)/openssl/crypto/x509/x509cset.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509name.o : $(SOURCE_DIR)/openssl/crypto/x509/x509name.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509rset.o : $(SOURCE_DIR)/openssl/crypto/x509/x509rset.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509spki.o : $(SOURCE_DIR)/openssl/crypto/x509/x509spki.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x509type.o : $(SOURCE_DIR)/openssl/crypto/x509/x509type.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_all.o : $(SOURCE_DIR)/openssl/crypto/x509/x_all.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_attrib.o : $(SOURCE_DIR)/openssl/crypto/x509/x_attrib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_crl.o : $(SOURCE_DIR)/openssl/crypto/x509/x_crl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_exten.o : $(SOURCE_DIR)/openssl/crypto/x509/x_exten.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_name.o : $(SOURCE_DIR)/openssl/crypto/x509/x_name.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_pubkey.o : $(SOURCE_DIR)/openssl/crypto/x509/x_pubkey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_req.o : $(SOURCE_DIR)/openssl/crypto/x509/x_req.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_x509.o : $(SOURCE_DIR)/openssl/crypto/x509/x_x509.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509/x_x509a.o : $(SOURCE_DIR)/openssl/crypto/x509/x_x509a.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_cache.o : $(SOURCE_DIR)/openssl/crypto/x509v3/pcy_cache.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_data.o : $(SOURCE_DIR)/openssl/crypto/x509v3/pcy_data.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_lib.o : $(SOURCE_DIR)/openssl/crypto/x509v3/pcy_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_map.o : $(SOURCE_DIR)/openssl/crypto/x509v3/pcy_map.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_node.o : $(SOURCE_DIR)/openssl/crypto/x509v3/pcy_node.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/pcy_tree.o : $(SOURCE_DIR)/openssl/crypto/x509v3/pcy_tree.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_addr.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_addr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_admis.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_admis.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_akey.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_akey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_akeya.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_akeya.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_alt.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_alt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_asid.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_asid.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_bcons.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_bcons.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_bitst.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_bitst.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_conf.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_conf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_cpols.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_cpols.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_crld.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_crld.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_enum.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_enum.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_extku.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_extku.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_genn.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_genn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_ia5.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_ia5.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_info.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_info.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_int.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_int.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_lib.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_lib.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_ncons.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_ncons.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pci.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_pci.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pcia.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_pcia.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pcons.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_pcons.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pku.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_pku.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_pmaps.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_pmaps.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_prn.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_prn.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_purp.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_purp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_skey.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_skey.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_sxnet.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_sxnet.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_tlsf.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_tlsf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3_utl.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3_utl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/x509v3/v3err.o : $(SOURCE_DIR)/openssl/crypto/x509v3/v3err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm2/sm2_crypt.o : $(SOURCE_DIR)/openssl/crypto/sm2/sm2_crypt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm2/sm2_err.o : $(SOURCE_DIR)/openssl/crypto/sm2/sm2_err.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm2/sm2_pmeth.o : $(SOURCE_DIR)/openssl/crypto/sm2/sm2_pmeth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm2/sm2_sign.o : $(SOURCE_DIR)/openssl/crypto/sm2/sm2_sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm3/m_sm3.o : $(SOURCE_DIR)/openssl/crypto/sm3/m_sm3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm3/sm3.o : $(SOURCE_DIR)/openssl/crypto/sm3/sm3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/openssl/crypto/sm4/sm4.o : $(SOURCE_DIR)/openssl/crypto/sm4/sm4.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ossl_store.o : $(SOURCE_DIR)/ossl_store.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/rand_pool.o : $(SOURCE_DIR)/rand_pool.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


