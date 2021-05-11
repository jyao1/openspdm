/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

#pragma pack(1)
typedef struct {
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST SpdmRequestVersion10;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11;

typedef struct {
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST SpdmRequestVersion10;
  UINT32 Extra[21];
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_OVERSIZED;

typedef struct {
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST SpdmRequestVersion10;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[12];
} SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               Length;
  UINT8                MeasurementSpecificationSel;
  UINT8                Reserved;
  UINT32               MeasurementHashAlgo;
  UINT32               BaseAsymSel;
  UINT32               BaseHashSel;
  UINT8                Reserved2[12];
  UINT8                ExtAsymSelCount;
  UINT8                ExtHashSelCount;
  UINT16               Reserved3;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_ALGORITHMS_RESPONSE_MINE;
#pragma pack()


SPDM_NEGOTIATE_ALGORITHMS_REQUEST    mSpdmNegotiateAlgorithmRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_NEGOTIATE_ALGORITHMS,
    0,
    0
  },
  sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST),
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
UINTN mSpdmNegotiateAlgorithmRequest1Size = sizeof(mSpdmNegotiateAlgorithmRequest1);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST    mSpdmNegotiateAlgorithmRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_NEGOTIATE_ALGORITHMS,
    0,
    0
  },
  sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST),
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
UINTN mSpdmNegotiateAlgorithmRequest2Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest3 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest3Size = sizeof(mSpdmNegotiateAlgorithmRequest3);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest4 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest4Size = sizeof(mSpdmNegotiateAlgorithmRequest4);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest5 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest5Size = sizeof(mSpdmNegotiateAlgorithmRequest5);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest6 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest6Size = sizeof(mSpdmNegotiateAlgorithmRequest6);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest7 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest7Size = sizeof(mSpdmNegotiateAlgorithmRequest7);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest8 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest8Size = sizeof(mSpdmNegotiateAlgorithmRequest8);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11    mSpdmNegotiateAlgorithmRequest9 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      BIT5
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest9Size = sizeof(mSpdmNegotiateAlgorithmRequest9);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST    mSpdmNegotiateAlgorithmRequest10 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_NEGOTIATE_ALGORITHMS,
    0,
    0
  },
  0x44,
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
UINTN mSpdmNegotiateAlgorithmRequest10Size = 0x44;

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_OVERSIZED    mSpdmNegotiateAlgorithmRequest11 = {
  .SpdmRequestVersion10 = {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      4,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_OVERSIZED),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  .StructTable = {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest11Size = sizeof(mSpdmNegotiateAlgorithmRequest11);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES    mSpdmNegotiateAlgorithmRequest12 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      12,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest12Size = sizeof(mSpdmNegotiateAlgorithmRequest12);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES    mSpdmNegotiateAlgorithmRequest13 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      11,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES)-sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest13Size = sizeof(mSpdmNegotiateAlgorithmRequest13)-sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES    mSpdmNegotiateAlgorithmRequest14 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      13,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES)+sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest14Size = sizeof(mSpdmNegotiateAlgorithmRequest14)+sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES    mSpdmNegotiateAlgorithmRequest15 = {
  {
    {
      SPDM_MESSAGE_VERSION_11,
      SPDM_NEGOTIATE_ALGORITHMS,
      12,
      0
    },
    sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST_SPDM11_MULTIPLE_TABLES),
    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
  },
  {
    {
      1,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
      0x20,
      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
      0x20,
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
      0x20,
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
    },
    {
      SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
      0x20,
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
    }
  }
};
UINTN mSpdmNegotiateAlgorithmRequest15Size = sizeof(mSpdmNegotiateAlgorithmRequest15);

void TestSpdmResponderAlgorithmCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ALGORITHMS_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ALGORITHMS);
}

void TestSpdmResponderAlgorithmCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest2Size, &mSpdmNegotiateAlgorithmRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

void TestSpdmResponderAlgorithmCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
}

void TestSpdmResponderAlgorithmCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->Length);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_NEGOTIATE_ALGORITHMS);
}

void TestSpdmResponderAlgorithmCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE_MINE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest12Size, &mSpdmNegotiateAlgorithmRequest12, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ALGORITHMS_RESPONSE)+4*sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ALGORITHMS);
  assert_int_equal (SpdmResponse->Header.SPDMVersion, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (SpdmResponse->StructTable[0].AlgSupported, SpdmContext->LocalContext.Algorithm.DHENamedGroup);
  assert_int_equal (SpdmResponse->StructTable[1].AlgSupported, SpdmContext->LocalContext.Algorithm.AEADCipherSuite);
  assert_int_equal (SpdmResponse->StructTable[2].AlgSupported, SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg);
  assert_int_equal (SpdmResponse->StructTable[3].AlgSupported, SpdmContext->LocalContext.Algorithm.KeySchedule);
}

void TestSpdmResponderAlgorithmCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest4Size, &mSpdmNegotiateAlgorithmRequest4, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest5Size, &mSpdmNegotiateAlgorithmRequest5, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest6Size, &mSpdmNegotiateAlgorithmRequest6, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest7Size, &mSpdmNegotiateAlgorithmRequest7, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest8Size, &mSpdmNegotiateAlgorithmRequest8, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest9Size, &mSpdmNegotiateAlgorithmRequest9, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmResponderAlgorithmCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 0;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest10Size, &mSpdmNegotiateAlgorithmRequest10, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmResponderAlgorithmCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xF;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest11Size, &mSpdmNegotiateAlgorithmRequest11, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmResponderAlgorithmCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE_MINE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest12Size, &mSpdmNegotiateAlgorithmRequest12, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ALGORITHMS_RESPONSE)+4*sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ALGORITHMS);
  assert_int_equal (SpdmResponse->Header.SPDMVersion, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (SpdmResponse->StructTable[0].AlgSupported, SpdmContext->LocalContext.Algorithm.DHENamedGroup);
  assert_int_equal (SpdmResponse->StructTable[1].AlgSupported, SpdmContext->LocalContext.Algorithm.AEADCipherSuite);
  assert_int_equal (SpdmResponse->StructTable[2].AlgSupported, SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg);
  assert_int_equal (SpdmResponse->StructTable[3].AlgSupported, SpdmContext->LocalContext.Algorithm.KeySchedule);
}

void TestSpdmResponderAlgorithmCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE_MINE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest13Size, &mSpdmNegotiateAlgorithmRequest13, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ALGORITHMS_RESPONSE)+4*sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ALGORITHMS);
  assert_int_equal (SpdmResponse->Header.SPDMVersion, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (SpdmResponse->StructTable[0].AlgSupported, SpdmContext->LocalContext.Algorithm.DHENamedGroup);
  assert_int_equal (SpdmResponse->StructTable[1].AlgSupported, SpdmContext->LocalContext.Algorithm.AEADCipherSuite);
  assert_int_equal (SpdmResponse->StructTable[2].AlgSupported, SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg);
  assert_int_equal (SpdmResponse->StructTable[3].AlgSupported, SpdmContext->LocalContext.Algorithm.KeySchedule);
}

void TestSpdmResponderAlgorithmCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE_MINE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest14Size, &mSpdmNegotiateAlgorithmRequest14, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE_MINE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->Transcript.MessageA.BufferSize = 0;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest12Size, &mSpdmNegotiateAlgorithmRequest12, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ALGORITHMS_RESPONSE)+4*sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ALGORITHMS);
  assert_int_equal (SpdmResponse->Header.SPDMVersion, SPDM_MESSAGE_VERSION_11);

  assert_int_equal (SpdmResponse->StructTable[0].AlgSupported, SpdmContext->LocalContext.Algorithm.DHENamedGroup);
  assert_int_equal (SpdmResponse->StructTable[1].AlgSupported, SpdmContext->LocalContext.Algorithm.AEADCipherSuite);
  assert_int_equal (SpdmResponse->StructTable[2].AlgSupported, SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg);
  assert_int_equal (SpdmResponse->StructTable[3].AlgSupported, SpdmContext->LocalContext.Algorithm.KeySchedule);
}

SPDM_TEST_CONTEXT       mSpdmResponderAlgorithmTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderAlgorithmTestMain(void) {
  const struct CMUnitTest SpdmResponderAlgorithmTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderAlgorithmCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderAlgorithmCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderAlgorithmCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderAlgorithmCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderAlgorithmCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderAlgorithmCase6),
    // Success case V1.1
    cmocka_unit_test(TestSpdmResponderAlgorithmCase7),
    // No match for BaseAsymAlgo
    cmocka_unit_test(TestSpdmResponderAlgorithmCase8),
    // No match for BaseHashAlgo
    cmocka_unit_test(TestSpdmResponderAlgorithmCase9),
    // No match for DHENamedGroup
    cmocka_unit_test(TestSpdmResponderAlgorithmCase10),
    // No match for AEADCipherSuite
    cmocka_unit_test(TestSpdmResponderAlgorithmCase11),
    // No match for ReqBaseAsymAlg
    cmocka_unit_test(TestSpdmResponderAlgorithmCase12),
    // No match for KeySchedule
    cmocka_unit_test(TestSpdmResponderAlgorithmCase13),
    // Spdm Length greater than 64 bytes for V1.0
    cmocka_unit_test(TestSpdmResponderAlgorithmCase14),
    // Spdm Length greater than 128 bytes for V1.1
    cmocka_unit_test(TestSpdmResponderAlgorithmCase15),
    // Multiple repeated Alg structs for V1.1
    cmocka_unit_test(TestSpdmResponderAlgorithmCase16),
    // Param1 is smaller than the number of Alg structs for V1.1
    cmocka_unit_test(TestSpdmResponderAlgorithmCase17),
    // Param1 is bigger than the number of  Alg structs for V1.1
    cmocka_unit_test(TestSpdmResponderAlgorithmCase18),
    // Invalid  Alg structs + valid Alg Structs for V1.1
    cmocka_unit_test(TestSpdmResponderAlgorithmCase19),
  };

  mSpdmNegotiateAlgorithmRequest1.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest1.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest2.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest2.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest3.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest3.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest4.SpdmRequestVersion10.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
  mSpdmNegotiateAlgorithmRequest4.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest5.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest5.SpdmRequestVersion10.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
  mSpdmNegotiateAlgorithmRequest6.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest6.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest7.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest7.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest8.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest8.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest9.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest9.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest10.ExtAsymCount = 0x09;
  mSpdmNegotiateAlgorithmRequest11.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest11.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest11.SpdmRequestVersion10.ExtAsymCount = 0x15;
  mSpdmNegotiateAlgorithmRequest12.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest12.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest13.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest13.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest14.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest14.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest15.SpdmRequestVersion10.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest15.SpdmRequestVersion10.BaseHashAlgo = mUseHashAlgo;

  SetupSpdmTestContext (&mSpdmResponderAlgorithmTestContext);

  return cmocka_run_group_tests(SpdmResponderAlgorithmTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
