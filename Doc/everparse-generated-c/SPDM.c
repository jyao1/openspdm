

#include "SPDM.h"

/*
Auto-generated field identifier for error reporting
*/
#define GET_VERSION_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)1U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_VERSION_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)2U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_VERSION_REQUEST_MESSAGE__PARAM1 ((uint64_t)3U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_VERSION_REQUEST_MESSAGE__PARAM2 ((uint64_t)4U)

/*
Auto-generated field identifier for error reporting
*/
#define VERSIONNUMBERENTRY__UPDATEVERSIONNUMBER ((uint64_t)6U)

/*
Auto-generated field identifier for error reporting
*/
#define VERSIONNUMBERENTRY__MAJORVERSION ((uint64_t)8U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)9U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)10U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__PARAM1 ((uint64_t)11U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__PARAM2 ((uint64_t)12U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__RESERVED ((uint64_t)13U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__VERSIONNUMBERENTRYCOUNT           \
    ((uint64_t)14U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_VERSION_RESPONSE_MESSAGE__VERSIONNUMBERENTRIES              \
    ((uint64_t)15U)

/*
Auto-generated field identifier for error reporting
*/
#define REQUESTER_FLAG__MAC_CAP ((uint64_t)22U)

/*
Auto-generated field identifier for error reporting
*/
#define REQUESTER_FLAG__HANDSHAKE_IN_THE_CLEAR_CAP ((uint64_t)29U)

/*
Auto-generated field identifier for error reporting
*/
#define REQUESTER_FLAG__RESERVED1 ((uint64_t)31U)

/*
Auto-generated field identifier for error reporting
*/
#define REQUESTER_FLAG__RESERVED2 ((uint64_t)32U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)33U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)34U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__PARAM1 ((uint64_t)35U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__PARAM2 ((uint64_t)36U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__RESERVED ((uint64_t)37U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__CTEXPONENT ((uint64_t)38U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CPABILITIES_REQUEST_MESSAGE__RESERVED1 ((uint64_t)39U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONDER_FLAG__MAC_CAP ((uint64_t)46U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONDER_FLAG__HANDSHAKE_IN_THE_CLEAR_CAP ((uint64_t)53U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONDER_FLAG__RESERVED1 ((uint64_t)55U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONDER_FLAG__RESERVED2 ((uint64_t)56U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)57U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__REQUESTRESPONSECODE           \
    ((uint64_t)58U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__PARAM1 ((uint64_t)59U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__PARAM2 ((uint64_t)60U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__RESERVED ((uint64_t)61U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__CTEXPONENT ((uint64_t)62U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__RESERVED1 ((uint64_t)63U)

/*
Auto-generated field identifier for error reporting
*/
#define EXTENDED_ALGORITHM_FIELD__REGISTRYID ((uint64_t)64U)

/*
Auto-generated field identifier for error reporting
*/
#define EXTENDED_ALGORITHM_FIELD__RESERVED ((uint64_t)65U)

/*
Auto-generated field identifier for error reporting
*/
#define EXTENDED_ALGORITHM_FIELD__ALGORITHMID ((uint64_t)66U)

/*
Auto-generated field identifier for error reporting
*/
#define DHE__ALGTYPE ((uint64_t)67U)

/*
Auto-generated field identifier for error reporting
*/
#define DHE__ALGCOUNT ((uint64_t)68U)

/*
Auto-generated field identifier for error reporting
*/
#define DHE__ALGSUPPORTED ((uint64_t)69U)

/*
Auto-generated field identifier for error reporting
*/
#define DHE__ALGEXTERNAL ((uint64_t)70U)

/*
Auto-generated field identifier for error reporting
*/
#define AEAD__ALGTYPE ((uint64_t)71U)

/*
Auto-generated field identifier for error reporting
*/
#define AEAD__ALGCOUNT ((uint64_t)72U)

/*
Auto-generated field identifier for error reporting
*/
#define AEAD__ALGSUPPORTED ((uint64_t)73U)

/*
Auto-generated field identifier for error reporting
*/
#define AEAD__ALGEXTERNAL ((uint64_t)74U)

/*
Auto-generated field identifier for error reporting
*/
#define REQBASEASYMALG__ALGTYPE ((uint64_t)75U)

/*
Auto-generated field identifier for error reporting
*/
#define REQBASEASYMALG__ALGCOUNT ((uint64_t)76U)

/*
Auto-generated field identifier for error reporting
*/
#define REQBASEASYMALG__ALGSUPPORTED ((uint64_t)77U)

/*
Auto-generated field identifier for error reporting
*/
#define REQBASEASYMALG__ALGEXTERNAL ((uint64_t)78U)

/*
Auto-generated field identifier for error reporting
*/
#define KEYSCHEDULE__ALGTYPE ((uint64_t)79U)

/*
Auto-generated field identifier for error reporting
*/
#define KEYSCHEDULE__ALGCOUNT ((uint64_t)80U)

/*
Auto-generated field identifier for error reporting
*/
#define KEYSCHEDULE__ALGSUPPORTED ((uint64_t)81U)

/*
Auto-generated field identifier for error reporting
*/
#define KEYSCHEDULE__ALGEXTERNAL ((uint64_t)82U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)83U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__REQUESTRESPONSECODE              \
    ((uint64_t)84U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__PARAM1 ((uint64_t)85U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__PARAM2 ((uint64_t)86U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__LENGTH ((uint64_t)87U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__MEASUREMENTSPECIFICATION         \
    ((uint64_t)88U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__RESERVED ((uint64_t)89U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__BASEASYMALGO ((uint64_t)90U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__BASEHASHALGO ((uint64_t)91U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__RESERVED1 ((uint64_t)92U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTASYMCOUNT ((uint64_t)93U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTHASHCOUNT ((uint64_t)94U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__RESERVED2 ((uint64_t)95U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTASYM ((uint64_t)96U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTHASH ((uint64_t)97U)

/*
Auto-generated field identifier for error reporting
*/
#define NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__REQALGSTRUCT ((uint64_t)98U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)99U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__REQUESTRESPONSECODE            \
    ((uint64_t)100U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__PARAM1 ((uint64_t)101U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__PARAM2 ((uint64_t)102U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__LENGTH ((uint64_t)103U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__MEASUREMENTSPECIFICATIONSEL    \
    ((uint64_t)104U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__RESERVED ((uint64_t)105U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__MEASUREMENTHASHALGO            \
    ((uint64_t)106U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__BASEASYMSEL ((uint64_t)107U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__BASEHASHSEL ((uint64_t)108U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__RESERVED1 ((uint64_t)109U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTASYMSELCOUNT ((uint64_t)110U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTHASHSELCOUNT ((uint64_t)111U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__RESERVED2 ((uint64_t)112U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTASYM ((uint64_t)113U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTHASH ((uint64_t)114U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__REQALGSTRUCT ((uint64_t)115U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_DIGESTS_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)116U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_DIGESTS_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)117U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_DIGESTS_REQUEST_MESSAGE__PARAM1 ((uint64_t)118U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_DIGESTS_REQUEST_MESSAGE__PARAM2 ((uint64_t)119U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)120U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__REQUESTRESPONSECODE               \
    ((uint64_t)121U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__PARAM1 ((uint64_t)122U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__PARAM2 ((uint64_t)123U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__DIGEST ((uint64_t)124U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CERTIFICATE_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)125U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CERTIFICATE_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)126U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CERTIFICATE_REQUEST_MESSAGE__PARAM1 ((uint64_t)127U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CERTIFICATE_REQUEST_MESSAGE__PARAM2 ((uint64_t)128U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CERTIFICATE_REQUEST_MESSAGE__OFFSET ((uint64_t)129U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_CERTIFICATE_REQUEST_MESSAGE__LENGTH ((uint64_t)130U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)131U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__REQUESTRESPONSECODE           \
    ((uint64_t)132U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__PARAM1 ((uint64_t)133U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__PARAM2 ((uint64_t)134U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__PORTIONLENGTH ((uint64_t)135U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__CERTCHAIN ((uint64_t)136U)

/*
Auto-generated field identifier for error reporting
*/
#define CHALLENGE_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)137U)

/*
Auto-generated field identifier for error reporting
*/
#define CHALLENGE_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)138U)

/*
Auto-generated field identifier for error reporting
*/
#define CHALLENGE_REQUEST_MESSAGE__PARAM1 ((uint64_t)139U)

/*
Auto-generated field identifier for error reporting
*/
#define CHALLENGE_REQUEST_MESSAGE__PARAM2 ((uint64_t)140U)

/*
Auto-generated field identifier for error reporting
*/
#define CHALLENGE_REQUEST_MESSAGE__NONCE ((uint64_t)141U)

/*
Auto-generated field identifier for error reporting
*/
#define CHALLENGE_AUTH_RESPONSE_ATTRIBUTE__BASICMUTAUTHREQ ((uint64_t)144U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)145U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__REQUESTRESPONSECODE        \
    ((uint64_t)146U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__PARAM2 ((uint64_t)147U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__CERTCHAINHASH              \
    ((uint64_t)148U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__NONCE ((uint64_t)149U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__MEASUREMENTSUMMARYHASH     \
    ((uint64_t)150U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__OPAQUELENGTH               \
    ((uint64_t)151U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__OPAQUEDATA ((uint64_t)152U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__SIGNATURE ((uint64_t)153U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_MEASUREMENTS_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)154U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_MEASUREMENTS_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)155U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_MEASUREMENTS_REQUEST_MESSAGE__PARAM1 ((uint64_t)156U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_MEASUREMENTS_REQUEST_MESSAGE__PARAM2 ((uint64_t)157U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_MEASUREMENTS_REQUEST_MESSAGE__NONCE ((uint64_t)158U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_MEASUREMENTS_REQUEST_MESSAGE__SLOTIDPARAM ((uint64_t)159U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)160U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__REQUESTRESPONSECODE          \
    ((uint64_t)161U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__PARAM1 ((uint64_t)162U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__PARAM2 ((uint64_t)163U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__NUMBEROFBLOCKS               \
    ((uint64_t)164U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__MEASUREMENTRECORDLENGTH      \
    ((uint64_t)165U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__MEASUREMENTRECORD            \
    ((uint64_t)166U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__NONCE ((uint64_t)167U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__OPAQUELENGTH ((uint64_t)168U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__OPAQUEDATA ((uint64_t)169U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__SIGNATURE ((uint64_t)170U)

/*
Auto-generated field identifier for error reporting
*/
#define ERROR_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)171U)

/*
Auto-generated field identifier for error reporting
*/
#define ERROR_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)172U)

/*
Auto-generated field identifier for error reporting
*/
#define ERROR_RESPONSE_MESSAGE__PARAM1 ((uint64_t)173U)

/*
Auto-generated field identifier for error reporting
*/
#define ERROR_RESPONSE_MESSAGE__PARAM2 ((uint64_t)174U)

/*
Auto-generated field identifier for error reporting
*/
#define ERROR_RESPONSE_MESSAGE__EXTENDEDERRORDATA ((uint64_t)175U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONSENOTREADY_EXTENDED_ERROR_DATA__RDTEXPONENT ((uint64_t)176U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONSENOTREADY_EXTENDED_ERROR_DATA__REQUESTCODE ((uint64_t)177U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONSENOTREADY_EXTENDED_ERROR_DATA__TOKEN ((uint64_t)178U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPONSENOTREADY_EXTENDED_ERROR_DATA__RDTM ((uint64_t)179U)

/*
Auto-generated field identifier for error reporting
*/
#define EXTENDERRORDATA_FOR_VENDOR__LEN ((uint64_t)180U)

/*
Auto-generated field identifier for error reporting
*/
#define EXTENDERRORDATA_FOR_VENDOR__VENDORID ((uint64_t)181U)

/*
Auto-generated field identifier for error reporting
*/
#define EXTENDERRORDATA_FOR_VENDOR__OPAQUEERRORDATA ((uint64_t)182U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPOND_IF_READY_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)183U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPOND_IF_READY_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)184U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPOND_IF_READY_REQUEST_MESSAGE__PARAM1 ((uint64_t)185U)

/*
Auto-generated field identifier for error reporting
*/
#define RESPOND_IF_READY_REQUEST_MESSAGE__PARAM2 ((uint64_t)186U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)187U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__REQUESTRESPONSECODE            \
    ((uint64_t)188U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__PARAM1 ((uint64_t)189U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__PARAM2 ((uint64_t)190U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__STANDARDID ((uint64_t)191U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__LEN ((uint64_t)192U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__VENDORID ((uint64_t)193U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__REQLENGTH ((uint64_t)194U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__VENDORDEFINEDREQPAYLOAD        \
    ((uint64_t)195U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)196U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__REQUESTRESPONSECODE          \
    ((uint64_t)197U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__PARAM1 ((uint64_t)198U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__PARAM2 ((uint64_t)199U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__STANDARDID ((uint64_t)200U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__LEN ((uint64_t)201U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__VENDORID ((uint64_t)202U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__RESPLENGTH ((uint64_t)203U)

/*
Auto-generated field identifier for error reporting
*/
#define VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__VENDORDEFINEDRESPPAYLOAD     \
    ((uint64_t)204U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)205U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)206U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__PARAM1 ((uint64_t)207U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__PARAM2 ((uint64_t)208U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__REQSESSIONID ((uint64_t)209U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__RESERVED ((uint64_t)210U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__RANDOMDATA ((uint64_t)211U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__EXCHANGEDATA ((uint64_t)212U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATALENGTH ((uint64_t)213U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATA ((uint64_t)214U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__SPDMVERSION              \
    ((uint64_t)215U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE      \
    ((uint64_t)216U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM1 ((uint64_t)217U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM2 ((uint64_t)218U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__REQSESSIONID             \
    ((uint64_t)219U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__MUTAUTHREQUESTED         \
    ((uint64_t)220U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__SLOTIDPARAM              \
    ((uint64_t)221U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__RANDOMDATA               \
    ((uint64_t)222U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__EXCHANGEDATA             \
    ((uint64_t)223U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__MEASUREMENTSUMMARYHASH   \
    ((uint64_t)224U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATALENGTH         \
    ((uint64_t)225U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATA               \
    ((uint64_t)226U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__SIGNATURE ((uint64_t)227U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__RESPONDERVERIFYDATA      \
    ((uint64_t)228U)

/*
Auto-generated field identifier for error reporting
*/
#define FINISH_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)229U)

/*
Auto-generated field identifier for error reporting
*/
#define FINISH_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)230U)

/*
Auto-generated field identifier for error reporting
*/
#define FINISH_REQUEST_MESSAGE__PARAM1 ((uint64_t)231U)

/*
Auto-generated field identifier for error reporting
*/
#define FINISH_REQUEST_MESSAGE__PARAM2 ((uint64_t)232U)

/*
Auto-generated field identifier for error reporting
*/
#define FINISH_REQUEST_MESSAGE__SIGNATURE ((uint64_t)233U)

/*
Auto-generated field identifier for error reporting
*/
#define FINISH_REQUEST_MESSAGE__REQUESTERVERIFYDATA ((uint64_t)234U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_FINISH_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)235U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_FINISH_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)236U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_FINISH_RESPONSE_MESSAGE__PARAM1 ((uint64_t)237U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_FINISH_RESPONSE_MESSAGE__PARAM2 ((uint64_t)238U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_FINISH_RESPONSE_MESSAGE__REQUESTERVERIFYDATA ((uint64_t)239U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)240U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)241U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__PARAM1 ((uint64_t)242U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__PARAM2 ((uint64_t)243U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__REQSESSIONID ((uint64_t)244U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__P ((uint64_t)245U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__R ((uint64_t)246U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATALENGTH ((uint64_t)247U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__PSKHINT ((uint64_t)248U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__REQUESTERCONTEXT ((uint64_t)249U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATA ((uint64_t)250U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)251U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)252U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM1 ((uint64_t)253U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM2 ((uint64_t)254U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RSPSESSIONID ((uint64_t)255U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RESERVED ((uint64_t)256U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__Q ((uint64_t)257U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATALENGTH ((uint64_t)258U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__MEASUREMENTSUMMARYHASH              \
    ((uint64_t)259U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RESPONDERCONTEXT ((uint64_t)260U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATA ((uint64_t)261U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RESPONDERVERIFYDATA ((uint64_t)262U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_FINISH_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)263U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_FINISH_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)264U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_FINISH_REQUEST_MESSAGE__PARAM1 ((uint64_t)265U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_FINISH_REQUEST_MESSAGE__PARAM2 ((uint64_t)266U)

/*
Auto-generated field identifier for error reporting
*/
#define PSK_FINISH_REQUEST_MESSAGE__REQUESTERVERIFYDATA ((uint64_t)267U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)268U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE        \
    ((uint64_t)269U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__PARAM1 ((uint64_t)270U)

/*
Auto-generated field identifier for error reporting
*/
#define SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__PARAM2 ((uint64_t)271U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)272U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)273U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_REQUEST_MESSAGE__PARAM1 ((uint64_t)274U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_REQUEST_MESSAGE__PARAM2 ((uint64_t)275U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_ACK_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)276U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)277U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_ACK_RESPONSE_MESSAGE__PARAM1 ((uint64_t)278U)

/*
Auto-generated field identifier for error reporting
*/
#define HEARTBEAT_ACK_RESPONSE_MESSAGE__PARAM2 ((uint64_t)279U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)280U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)281U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_REQUEST_MESSAGE__PARAM1 ((uint64_t)282U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_REQUEST_MESSAGE__PARAM2 ((uint64_t)283U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_ACK_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)284U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)285U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_ACK_RESPONSE_MESSAGE__PARAM1 ((uint64_t)286U)

/*
Auto-generated field identifier for error reporting
*/
#define KEY_UPDATE_ACK_RESPONSE_MESSAGE__PARAM2 ((uint64_t)287U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)288U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__REQUESTRESPONSECODE          \
    ((uint64_t)289U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__PARAM1 ((uint64_t)290U)

/*
Auto-generated field identifier for error reporting
*/
#define GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__PARAM2 ((uint64_t)291U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)292U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__REQUESTRESPONSECODE             \
    ((uint64_t)293U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__PARAM1 ((uint64_t)294U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__PARAM2 ((uint64_t)295U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__ENCAPSULATEDREQUEST             \
    ((uint64_t)296U)

/*
Auto-generated field identifier for error reporting
*/
#define DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__SPDMVERSION             \
    ((uint64_t)297U)

/*
Auto-generated field identifier for error reporting
*/
#define DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__REQUESTRESPONSECODE     \
    ((uint64_t)298U)

/*
Auto-generated field identifier for error reporting
*/
#define DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__PARAM1 ((uint64_t)299U)

/*
Auto-generated field identifier for error reporting
*/
#define DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__PARAM2 ((uint64_t)300U)

/*
Auto-generated field identifier for error reporting
*/
#define DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__ENCAPSULATEDRESPONSE    \
    ((uint64_t)301U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)302U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE        \
    ((uint64_t)303U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__PARAM1 ((uint64_t)304U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__PARAM2 ((uint64_t)305U)

/*
Auto-generated field identifier for error reporting
*/
#define ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__ENCAPSULATEDREQUEST        \
    ((uint64_t)306U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_REQUEST_MESSAGE__SPDMVERSION ((uint64_t)307U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_REQUEST_MESSAGE__REQUESTRESPONSECODE ((uint64_t)308U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_REQUEST_MESSAGE__PARAM1 ((uint64_t)309U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_REQUEST_MESSAGE__PARAM2 ((uint64_t)310U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_ACK_RESPONSE_MESSAGE__SPDMVERSION ((uint64_t)311U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE ((uint64_t)312U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_ACK_RESPONSE_MESSAGE__PARAM1 ((uint64_t)313U)

/*
Auto-generated field identifier for error reporting
*/
#define END_SESSION_ACK_RESPONSE_MESSAGE__PARAM2 ((uint64_t)314U)

#define H ((uint16_t)256U)

#define S ((uint16_t)256U)

static inline uint64_t
ValidateGetVersionRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_VERSION_REQUEST_MESSAGE_SPDMVersion
        of type _GET_VERSION_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_VERSION_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateGetVersionRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_VERSION_REQUEST_MESSAGE_Param1
        of type _GET_VERSION_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, GET_VERSION_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateGetVersionRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_VERSION_REQUEST_MESSAGE_Param2
        of type _GET_VERSION_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, GET_VERSION_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateGetVersionRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _GET_VERSION_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateGetVersionRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        GET_VERSION_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x84U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            GET_VERSION_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _GET_VERSION_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateGetVersionRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _GET_VERSION_REQUEST_MESSAGE_Param2 */
    return ValidateGetVersionRequestMessageParam2(Input, positionAfterParam1);
}

static inline uint64_t
ValidateVersionNumberEntryBitfield0(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VersionNumberEntry___bitfield_0
        of type _VersionNumberEntry
--*/
{
    /* Validating field __bitfield_0 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VERSIONNUMBERENTRY__UPDATEVERSIONNUMBER);
}

static inline uint64_t
ValidateVersionNumberEntryBitfield1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VersionNumberEntry___bitfield_1
        of type _VersionNumberEntry
--*/
{
    /* Validating field __bitfield_1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, VERSIONNUMBERENTRY__MAJORVERSION);
}

uint64_t
SpdmValidateVersionNumberEntry(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _VersionNumberEntry___bitfield_0 */
    uint64_t positionAfterBitfield0 =
        ValidateVersionNumberEntryBitfield0(Input, StartPosition);
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    /* Field _VersionNumberEntry___bitfield_1 */
    return ValidateVersionNumberEntryBitfield1(Input, positionAfterBitfield0);
}

static inline uint64_t
ValidateSuccessfulVersionResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_SPDMVersion
        of type _SUCCESSFUL_VERSION_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulVersionResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_VERSION_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulVersionResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_VERSION_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulVersionResponseMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_Reserved
        of type _SUCCESSFUL_VERSION_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__RESERVED);
}

static inline uint64_t
ValidateSuccessfulVersionResponseMessageVersionNumberEntryCount(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_VERSION_RESPONSE_MESSAGE_VersionNumberEntryCount of type
_SUCCESSFUL_VERSION_RESPONSE_MESSAGE
--*/
{
    /* Validating field VersionNumberEntryCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__VERSIONNUMBERENTRYCOUNT);
}

static inline uint64_t
ValidateSuccessfulVersionResponseMessageVersionNumberEntries(
    uint8_t VersionNumberEntryCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_VERSION_RESPONSE_MESSAGE_VersionNumberEntries of type
_SUCCESSFUL_VERSION_RESPONSE_MESSAGE
--*/
{
    /* Validating field VersionNumberEntries */
    uint64_t endPositionOrError;
    if ((uint32_t)2U * (uint32_t)VersionNumberEntryCount % (uint32_t)2U ==
        (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)2U * (uint32_t)VersionNumberEntryCount))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)((uint32_t)2U * (uint32_t)VersionNumberEntryCount);
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__VERSIONNUMBERENTRIES);
}

uint64_t
SpdmValidateSuccessfulVersionResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulVersionResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_VERSION_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x04U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_VERSION_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulVersionResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulVersionResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_Reserved */
    uint64_t positionAfterReserved =
        ValidateSuccessfulVersionResponseMessageReserved(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_VersionNumberEntryCount */
    uint64_t positionAfterVersionNumberEntryCount =
        ValidateSuccessfulVersionResponseMessageVersionNumberEntryCount(
            Input, positionAfterReserved);
    if (EverParseIsError(positionAfterVersionNumberEntryCount))
    {
        return positionAfterVersionNumberEntryCount;
    }
    uint8_t versionNumberEntryCount =
        Input.base[(uint32_t)positionAfterReserved];
    /* Field _SUCCESSFUL_VERSION_RESPONSE_MESSAGE_VersionNumberEntries */
    return ValidateSuccessfulVersionResponseMessageVersionNumberEntries(
        versionNumberEntryCount, Input, positionAfterVersionNumberEntryCount);
}

static inline uint64_t
ValidateRequesterFlagBitfield0(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _REQUESTER_FLAG___bitfield_0
        of type _REQUESTER_FLAG
--*/
{
    /* Validating field __bitfield_0 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQUESTER_FLAG__MAC_CAP);
}

static inline uint64_t
ValidateRequesterFlagBitfield1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _REQUESTER_FLAG___bitfield_1
        of type _REQUESTER_FLAG
--*/
{
    /* Validating field __bitfield_1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        REQUESTER_FLAG__HANDSHAKE_IN_THE_CLEAR_CAP);
}

static inline uint64_t
ValidateRequesterFlagBitfield2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _REQUESTER_FLAG___bitfield_2
        of type _REQUESTER_FLAG
--*/
{
    /* Validating field __bitfield_2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQUESTER_FLAG__RESERVED1);
}

static inline uint64_t
ValidateRequesterFlagBitfield3(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _REQUESTER_FLAG___bitfield_3
        of type _REQUESTER_FLAG
--*/
{
    /* Validating field __bitfield_3 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQUESTER_FLAG__RESERVED2);
}

uint64_t
SpdmValidateRequesterFlag(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _REQUESTER_FLAG___bitfield_0 */
    uint64_t positionAfterBitfield0 =
        ValidateRequesterFlagBitfield0(Input, StartPosition);
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    /* Field _REQUESTER_FLAG___bitfield_1 */
    uint64_t positionAfterBitfield1 =
        ValidateRequesterFlagBitfield1(Input, positionAfterBitfield0);
    if (EverParseIsError(positionAfterBitfield1))
    {
        return positionAfterBitfield1;
    }
    /* Field _REQUESTER_FLAG___bitfield_2 */
    uint64_t positionAfterBitfield2 =
        ValidateRequesterFlagBitfield2(Input, positionAfterBitfield1);
    if (EverParseIsError(positionAfterBitfield2))
    {
        return positionAfterBitfield2;
    }
    /* Field _REQUESTER_FLAG___bitfield_3 */
    return ValidateRequesterFlagBitfield3(Input, positionAfterBitfield2);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_SPDMVersion
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CPABILITIES_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_Param1
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CPABILITIES_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_Param2
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CPABILITIES_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_Reserved
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CPABILITIES_REQUEST_MESSAGE__RESERVED);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageCtexponent(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_CTExponent
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field CTExponent */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CPABILITIES_REQUEST_MESSAGE__CTEXPONENT);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageReserved1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_Reserved1
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field Reserved1 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CPABILITIES_REQUEST_MESSAGE__RESERVED1);
}

static inline uint64_t
ValidateGetCpabilitiesRequestMessageFlags(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CPABILITIES_REQUEST_MESSAGE_Flags
        of type _GET_CPABILITIES_REQUEST_MESSAGE
--*/
{
    /* Validating field Flags */
    return SpdmValidateRequesterFlag(Input, StartPosition);
}

uint64_t
SpdmValidateGetCpabilitiesRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateGetCpabilitiesRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        GET_CPABILITIES_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE1U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            GET_CPABILITIES_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateGetCpabilitiesRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateGetCpabilitiesRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_Reserved */
    uint64_t positionAfterReserved =
        ValidateGetCpabilitiesRequestMessageReserved(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_CTExponent */
    uint64_t positionAfterCtexponent =
        ValidateGetCpabilitiesRequestMessageCtexponent(
            Input, positionAfterReserved);
    if (EverParseIsError(positionAfterCtexponent))
    {
        return positionAfterCtexponent;
    }
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_Reserved1 */
    uint64_t positionAfterReserved1 =
        ValidateGetCpabilitiesRequestMessageReserved1(
            Input, positionAfterCtexponent);
    if (EverParseIsError(positionAfterReserved1))
    {
        return positionAfterReserved1;
    }
    /* Field _GET_CPABILITIES_REQUEST_MESSAGE_Flags */
    return ValidateGetCpabilitiesRequestMessageFlags(
        Input, positionAfterReserved1);
}

static inline uint64_t
ValidateResponderFlagBitfield0(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONDER_FLAG___bitfield_0
        of type _RESPONDER_FLAG
--*/
{
    /* Validating field __bitfield_0 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, RESPONDER_FLAG__MAC_CAP);
}

static inline uint64_t
ValidateResponderFlagBitfield1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONDER_FLAG___bitfield_1
        of type _RESPONDER_FLAG
--*/
{
    /* Validating field __bitfield_1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPONDER_FLAG__HANDSHAKE_IN_THE_CLEAR_CAP);
}

static inline uint64_t
ValidateResponderFlagBitfield2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONDER_FLAG___bitfield_2
        of type _RESPONDER_FLAG
--*/
{
    /* Validating field __bitfield_2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, RESPONDER_FLAG__RESERVED1);
}

static inline uint64_t
ValidateResponderFlagBitfield3(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONDER_FLAG___bitfield_3
        of type _RESPONDER_FLAG
--*/
{
    /* Validating field __bitfield_3 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, RESPONDER_FLAG__RESERVED2);
}

uint64_t
SpdmValidateResponderFlag(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _RESPONDER_FLAG___bitfield_0 */
    uint64_t positionAfterBitfield0 =
        ValidateResponderFlagBitfield0(Input, StartPosition);
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    /* Field _RESPONDER_FLAG___bitfield_1 */
    uint64_t positionAfterBitfield1 =
        ValidateResponderFlagBitfield1(Input, positionAfterBitfield0);
    if (EverParseIsError(positionAfterBitfield1))
    {
        return positionAfterBitfield1;
    }
    /* Field _RESPONDER_FLAG___bitfield_2 */
    uint64_t positionAfterBitfield2 =
        ValidateResponderFlagBitfield2(Input, positionAfterBitfield1);
    if (EverParseIsError(positionAfterBitfield2))
    {
        return positionAfterBitfield2;
    }
    /* Field _RESPONDER_FLAG___bitfield_3 */
    return ValidateResponderFlagBitfield3(Input, positionAfterBitfield2);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_SPDMVersion
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Reserved
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__RESERVED);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageCtexponent(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_CTExponent
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field CTExponent */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__CTEXPONENT);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageReserved1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Reserved1
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved1 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__RESERVED1);
}

static inline uint64_t
ValidateSuccessfulCpabilitiesResponseMessageFlags(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Flags
        of type _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE
--*/
{
    /* Validating field Flags */
    return SpdmValidateResponderFlag(Input, StartPosition);
}

uint64_t
SpdmValidateSuccessfulCpabilitiesResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulCpabilitiesResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x61U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulCpabilitiesResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulCpabilitiesResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Reserved */
    uint64_t positionAfterReserved =
        ValidateSuccessfulCpabilitiesResponseMessageReserved(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_CTExponent */
    uint64_t positionAfterCtexponent =
        ValidateSuccessfulCpabilitiesResponseMessageCtexponent(
            Input, positionAfterReserved);
    if (EverParseIsError(positionAfterCtexponent))
    {
        return positionAfterCtexponent;
    }
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Reserved1 */
    uint64_t positionAfterReserved1 =
        ValidateSuccessfulCpabilitiesResponseMessageReserved1(
            Input, positionAfterCtexponent);
    if (EverParseIsError(positionAfterReserved1))
    {
        return positionAfterReserved1;
    }
    /* Field _SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE_Flags */
    return ValidateSuccessfulCpabilitiesResponseMessageFlags(
        Input, positionAfterReserved1);
}

static inline uint64_t
ValidateExtendedAlgorithmFieldRegistryId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _EXTENDED_ALGORITHM_FIELD_RegistryID
        of type _EXTENDED_ALGORITHM_FIELD
--*/
{
    /* Validating field RegistryID */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        EXTENDED_ALGORITHM_FIELD__REGISTRYID);
}

static inline uint64_t
ValidateExtendedAlgorithmFieldReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _EXTENDED_ALGORITHM_FIELD_Reserved
        of type _EXTENDED_ALGORITHM_FIELD
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, EXTENDED_ALGORITHM_FIELD__RESERVED);
}

static inline uint64_t
ValidateExtendedAlgorithmFieldAlgorithmId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _EXTENDED_ALGORITHM_FIELD_AlgorithmID
        of type _EXTENDED_ALGORITHM_FIELD
--*/
{
    /* Validating field AlgorithmID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        EXTENDED_ALGORITHM_FIELD__ALGORITHMID);
}

uint64_t
SpdmValidateExtendedAlgorithmField(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _EXTENDED_ALGORITHM_FIELD_RegistryID */
    uint64_t positionAfterRegistryId =
        ValidateExtendedAlgorithmFieldRegistryId(Input, StartPosition);
    if (EverParseIsError(positionAfterRegistryId))
    {
        return positionAfterRegistryId;
    }
    /* Field _EXTENDED_ALGORITHM_FIELD_Reserved */
    uint64_t positionAfterReserved =
        ValidateExtendedAlgorithmFieldReserved(Input, positionAfterRegistryId);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _EXTENDED_ALGORITHM_FIELD_AlgorithmID */
    return ValidateExtendedAlgorithmFieldAlgorithmId(
        Input, positionAfterReserved);
}

static inline uint64_t
ValidateDheAlgCount(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _DHE_AlgCount
        of type _DHE
--*/
{
    /* Validating field AlgCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, DHE__ALGCOUNT);
}

static inline uint64_t
ValidateDheAlgSupported(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _DHE_AlgSupported
        of type _DHE
--*/
{
    /* Validating field AlgSupported */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, DHE__ALGSUPPORTED);
}

static inline uint64_t
ValidateDheAlgExternal(
    uint8_t AlgCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _DHE_AlgExternal
        of type _DHE
--*/
{
    /* Validating field AlgExternal */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU) % (uint32_t)4U ==
        (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU)))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)(
                    (uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU));
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, DHE__ALGEXTERNAL);
}

uint64_t
SpdmValidateDhe(InputBuffer Input, uint64_t StartPosition)
{
    /* Validating field AlgType */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    uint64_t positionAfterAlgType = EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, DHE__ALGTYPE);
    if (EverParseIsError(positionAfterAlgType))
    {
        return positionAfterAlgType;
    }
    uint8_t algType = Input.base[(uint32_t)StartPosition];
    BOOLEAN algTypeConstraintIsOk = algType == (uint8_t)0x2U;
    uint64_t positionOrErrorAfterAlgType =
        EverParseCheckConstraintOkWithFieldId(
            algTypeConstraintIsOk,
            StartPosition,
            positionAfterAlgType,
            DHE__ALGTYPE);
    if (EverParseIsError(positionOrErrorAfterAlgType))
    {
        return positionOrErrorAfterAlgType;
    }
    /* Field _DHE_AlgCount */
    uint64_t positionAfterAlgCount =
        ValidateDheAlgCount(Input, positionOrErrorAfterAlgType);
    if (EverParseIsError(positionAfterAlgCount))
    {
        return positionAfterAlgCount;
    }
    uint8_t algCount = Input.base[(uint32_t)positionOrErrorAfterAlgType];
    /* Field _DHE_AlgSupported */
    uint64_t positionAfterAlgSupported =
        ValidateDheAlgSupported(Input, positionAfterAlgCount);
    if (EverParseIsError(positionAfterAlgSupported))
    {
        return positionAfterAlgSupported;
    }
    /* Field _DHE_AlgExternal */
    return ValidateDheAlgExternal(algCount, Input, positionAfterAlgSupported);
}

static inline uint64_t
ValidateAeadAlgCount(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _AEAD_AlgCount
        of type _AEAD
--*/
{
    /* Validating field AlgCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, AEAD__ALGCOUNT);
}

static inline uint64_t
ValidateAeadAlgSupported(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _AEAD_AlgSupported
        of type _AEAD
--*/
{
    /* Validating field AlgSupported */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, AEAD__ALGSUPPORTED);
}

static inline uint64_t
ValidateAeadAlgExternal(
    uint8_t AlgCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _AEAD_AlgExternal
        of type _AEAD
--*/
{
    /* Validating field AlgExternal */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU) % (uint32_t)4U ==
        (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU)))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)(
                    (uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU));
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, AEAD__ALGEXTERNAL);
}

uint64_t
SpdmValidateAead(InputBuffer Input, uint64_t StartPosition)
{
    /* Validating field AlgType */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    uint64_t positionAfterAlgType = EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, AEAD__ALGTYPE);
    if (EverParseIsError(positionAfterAlgType))
    {
        return positionAfterAlgType;
    }
    uint8_t algType = Input.base[(uint32_t)StartPosition];
    BOOLEAN algTypeConstraintIsOk = algType == (uint8_t)0x3U;
    uint64_t positionOrErrorAfterAlgType =
        EverParseCheckConstraintOkWithFieldId(
            algTypeConstraintIsOk,
            StartPosition,
            positionAfterAlgType,
            AEAD__ALGTYPE);
    if (EverParseIsError(positionOrErrorAfterAlgType))
    {
        return positionOrErrorAfterAlgType;
    }
    /* Field _AEAD_AlgCount */
    uint64_t positionAfterAlgCount =
        ValidateAeadAlgCount(Input, positionOrErrorAfterAlgType);
    if (EverParseIsError(positionAfterAlgCount))
    {
        return positionAfterAlgCount;
    }
    uint8_t algCount = Input.base[(uint32_t)positionOrErrorAfterAlgType];
    /* Field _AEAD_AlgSupported */
    uint64_t positionAfterAlgSupported =
        ValidateAeadAlgSupported(Input, positionAfterAlgCount);
    if (EverParseIsError(positionAfterAlgSupported))
    {
        return positionAfterAlgSupported;
    }
    /* Field _AEAD_AlgExternal */
    return ValidateAeadAlgExternal(algCount, Input, positionAfterAlgSupported);
}

static inline uint64_t
ValidateReqBaseAsymAlgAlgCount(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ReqBaseAsymAlg_AlgCount
        of type _ReqBaseAsymAlg
--*/
{
    /* Validating field AlgCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQBASEASYMALG__ALGCOUNT);
}

static inline uint64_t
ValidateReqBaseAsymAlgAlgSupported(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ReqBaseAsymAlg_AlgSupported
        of type _ReqBaseAsymAlg
--*/
{
    /* Validating field AlgSupported */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQBASEASYMALG__ALGSUPPORTED);
}

static inline uint64_t
ValidateReqBaseAsymAlgAlgExternal(
    uint8_t AlgCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ReqBaseAsymAlg_AlgExternal
        of type _ReqBaseAsymAlg
--*/
{
    /* Validating field AlgExternal */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU) % (uint32_t)4U ==
        (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU)))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)(
                    (uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU));
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQBASEASYMALG__ALGEXTERNAL);
}

uint64_t
SpdmValidateReqBaseAsymAlg(InputBuffer Input, uint64_t StartPosition)
{
    /* Validating field AlgType */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    uint64_t positionAfterAlgType = EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, REQBASEASYMALG__ALGTYPE);
    if (EverParseIsError(positionAfterAlgType))
    {
        return positionAfterAlgType;
    }
    uint8_t algType = Input.base[(uint32_t)StartPosition];
    BOOLEAN algTypeConstraintIsOk = algType == (uint8_t)0x4U;
    uint64_t positionOrErrorAfterAlgType =
        EverParseCheckConstraintOkWithFieldId(
            algTypeConstraintIsOk,
            StartPosition,
            positionAfterAlgType,
            REQBASEASYMALG__ALGTYPE);
    if (EverParseIsError(positionOrErrorAfterAlgType))
    {
        return positionOrErrorAfterAlgType;
    }
    /* Field _ReqBaseAsymAlg_AlgCount */
    uint64_t positionAfterAlgCount =
        ValidateReqBaseAsymAlgAlgCount(Input, positionOrErrorAfterAlgType);
    if (EverParseIsError(positionAfterAlgCount))
    {
        return positionAfterAlgCount;
    }
    uint8_t algCount = Input.base[(uint32_t)positionOrErrorAfterAlgType];
    /* Field _ReqBaseAsymAlg_AlgSupported */
    uint64_t positionAfterAlgSupported =
        ValidateReqBaseAsymAlgAlgSupported(Input, positionAfterAlgCount);
    if (EverParseIsError(positionAfterAlgSupported))
    {
        return positionAfterAlgSupported;
    }
    /* Field _ReqBaseAsymAlg_AlgExternal */
    return ValidateReqBaseAsymAlgAlgExternal(
        algCount, Input, positionAfterAlgSupported);
}

static inline uint64_t
ValidateKeyScheduleAlgCount(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KeySchedule_AlgCount
        of type _KeySchedule
--*/
{
    /* Validating field AlgCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, KEYSCHEDULE__ALGCOUNT);
}

static inline uint64_t
ValidateKeyScheduleAlgSupported(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KeySchedule_AlgSupported
        of type _KeySchedule
--*/
{
    /* Validating field AlgSupported */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, KEYSCHEDULE__ALGSUPPORTED);
}

static inline uint64_t
ValidateKeyScheduleAlgExternal(
    uint8_t AlgCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KeySchedule_AlgExternal
        of type _KeySchedule
--*/
{
    /* Validating field AlgExternal */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU) % (uint32_t)4U ==
        (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU)))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)(
                    (uint32_t)4U * (uint32_t)(AlgCount & (uint8_t)0x0FU));
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, KEYSCHEDULE__ALGEXTERNAL);
}

uint64_t
SpdmValidateKeySchedule(InputBuffer Input, uint64_t StartPosition)
{
    /* Validating field AlgType */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    uint64_t positionAfterAlgType = EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, KEYSCHEDULE__ALGTYPE);
    if (EverParseIsError(positionAfterAlgType))
    {
        return positionAfterAlgType;
    }
    uint8_t algType = Input.base[(uint32_t)StartPosition];
    BOOLEAN algTypeConstraintIsOk = algType == (uint8_t)0x5U;
    uint64_t positionOrErrorAfterAlgType =
        EverParseCheckConstraintOkWithFieldId(
            algTypeConstraintIsOk,
            StartPosition,
            positionAfterAlgType,
            KEYSCHEDULE__ALGTYPE);
    if (EverParseIsError(positionOrErrorAfterAlgType))
    {
        return positionOrErrorAfterAlgType;
    }
    /* Field _KeySchedule_AlgCount */
    uint64_t positionAfterAlgCount =
        ValidateKeyScheduleAlgCount(Input, positionOrErrorAfterAlgType);
    if (EverParseIsError(positionAfterAlgCount))
    {
        return positionAfterAlgCount;
    }
    uint8_t algCount = Input.base[(uint32_t)positionOrErrorAfterAlgType];
    /* Field _KeySchedule_AlgSupported */
    uint64_t positionAfterAlgSupported =
        ValidateKeyScheduleAlgSupported(Input, positionAfterAlgCount);
    if (EverParseIsError(positionAfterAlgSupported))
    {
        return positionAfterAlgSupported;
    }
    /* Field _KeySchedule_AlgExternal */
    return ValidateKeyScheduleAlgExternal(
        algCount, Input, positionAfterAlgSupported);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_SPDMVersion
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Param1
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Param2
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Length
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field Length */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__LENGTH);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageMeasurementSpecification(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_MeasurementSpecification of type
_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field MeasurementSpecification */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__MEASUREMENTSPECIFICATION);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Reserved
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__RESERVED);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageBaseAsymAlgo(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_BaseAsymAlgo
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field BaseAsymAlgo */
    /* Checking that we have enough space for a ULONG, i.e., 4 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)4U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)4U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__BASEASYMALGO);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageBaseHashAlgo(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_BaseHashAlgo
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field BaseHashAlgo */
    /* Checking that we have enough space for a ULONG, i.e., 4 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)4U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)4U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__BASEHASHALGO);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageReserved1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Reserved1
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field Reserved1 */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)12U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)12U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__RESERVED1);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageExtAsymCount(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtAsymCount
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field ExtAsymCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTASYMCOUNT);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageExtHashCount(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtHashCount
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field ExtHashCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTHASHCOUNT);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageReserved2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Reserved2
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field Reserved2 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__RESERVED2);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageExtAsym(
    uint8_t ExtAsymCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtAsym
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field ExtAsym */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)ExtAsymCount % (uint32_t)4U == (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)ExtAsymCount))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)((uint32_t)4U * (uint32_t)ExtAsymCount);
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTASYM);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageExtHash(
    uint8_t ExtHashCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtHash
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field ExtHash */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)ExtHashCount % (uint32_t)4U == (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)ExtHashCount))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)((uint32_t)4U * (uint32_t)ExtHashCount);
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__EXTHASH);
}

static inline uint64_t
ValidateNegotiateAlgorithmsRequestMessageReqAlgStruct(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ReqAlgStruct
        of type _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE
--*/
{
    /* Validating field ReqAlgStruct */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)16U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)16U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__REQALGSTRUCT);
}

uint64_t
SpdmValidateNegotiateAlgorithmsRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateNegotiateAlgorithmsRequestMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE3U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateNegotiateAlgorithmsRequestMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateNegotiateAlgorithmsRequestMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Length */
    uint64_t positionAfterLength =
        ValidateNegotiateAlgorithmsRequestMessageLength(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterLength))
    {
        return positionAfterLength;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_MeasurementSpecification */
    uint64_t positionAfterMeasurementSpecification =
        ValidateNegotiateAlgorithmsRequestMessageMeasurementSpecification(
            Input, positionAfterLength);
    if (EverParseIsError(positionAfterMeasurementSpecification))
    {
        return positionAfterMeasurementSpecification;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Reserved */
    uint64_t positionAfterReserved =
        ValidateNegotiateAlgorithmsRequestMessageReserved(
            Input, positionAfterMeasurementSpecification);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_BaseAsymAlgo */
    uint64_t positionAfterBaseAsymAlgo =
        ValidateNegotiateAlgorithmsRequestMessageBaseAsymAlgo(
            Input, positionAfterReserved);
    if (EverParseIsError(positionAfterBaseAsymAlgo))
    {
        return positionAfterBaseAsymAlgo;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_BaseHashAlgo */
    uint64_t positionAfterBaseHashAlgo =
        ValidateNegotiateAlgorithmsRequestMessageBaseHashAlgo(
            Input, positionAfterBaseAsymAlgo);
    if (EverParseIsError(positionAfterBaseHashAlgo))
    {
        return positionAfterBaseHashAlgo;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Reserved1 */
    uint64_t positionAfterReserved1 =
        ValidateNegotiateAlgorithmsRequestMessageReserved1(
            Input, positionAfterBaseHashAlgo);
    if (EverParseIsError(positionAfterReserved1))
    {
        return positionAfterReserved1;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtAsymCount */
    uint64_t positionAfterExtAsymCount =
        ValidateNegotiateAlgorithmsRequestMessageExtAsymCount(
            Input, positionAfterReserved1);
    if (EverParseIsError(positionAfterExtAsymCount))
    {
        return positionAfterExtAsymCount;
    }
    uint8_t extAsymCount = Input.base[(uint32_t)positionAfterReserved1];
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtHashCount */
    uint64_t positionAfterExtHashCount =
        ValidateNegotiateAlgorithmsRequestMessageExtHashCount(
            Input, positionAfterExtAsymCount);
    if (EverParseIsError(positionAfterExtHashCount))
    {
        return positionAfterExtHashCount;
    }
    uint8_t extHashCount = Input.base[(uint32_t)positionAfterExtAsymCount];
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_Reserved2 */
    uint64_t positionAfterReserved2 =
        ValidateNegotiateAlgorithmsRequestMessageReserved2(
            Input, positionAfterExtHashCount);
    if (EverParseIsError(positionAfterReserved2))
    {
        return positionAfterReserved2;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtAsym */
    uint64_t positionAfterExtAsym =
        ValidateNegotiateAlgorithmsRequestMessageExtAsym(
            extAsymCount, Input, positionAfterReserved2);
    if (EverParseIsError(positionAfterExtAsym))
    {
        return positionAfterExtAsym;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ExtHash */
    uint64_t positionAfterExtHash =
        ValidateNegotiateAlgorithmsRequestMessageExtHash(
            extHashCount, Input, positionAfterExtAsym);
    if (EverParseIsError(positionAfterExtHash))
    {
        return positionAfterExtHash;
    }
    /* Field _NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_ReqAlgStruct */
    return ValidateNegotiateAlgorithmsRequestMessageReqAlgStruct(
        Input, positionAfterExtHash);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_SPDMVersion
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Length
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Length */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__LENGTH);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageMeasurementSpecificationSel(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_MeasurementSpecificationSel of type
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field MeasurementSpecificationSel */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__MEASUREMENTSPECIFICATIONSEL);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Reserved
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__RESERVED);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageMeasurementHashAlgo(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_MeasurementHashAlgo of type
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field MeasurementHashAlgo */
    /* Checking that we have enough space for a ULONG, i.e., 4 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)4U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)4U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__MEASUREMENTHASHALGO);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageBaseAsymSel(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_BaseAsymSel
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field BaseAsymSel */
    /* Checking that we have enough space for a ULONG, i.e., 4 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)4U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)4U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__BASEASYMSEL);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageBaseHashSel(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_BaseHashSel
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field BaseHashSel */
    /* Checking that we have enough space for a ULONG, i.e., 4 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)4U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)4U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__BASEHASHSEL);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageReserved1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Reserved1
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved1 */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)12U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)12U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__RESERVED1);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageExtAsymSelCount(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtAsymSelCount of type
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field ExtAsymSelCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTASYMSELCOUNT);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageExtHashSelCount(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtHashSelCount of type
_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field ExtHashSelCount */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTHASHSELCOUNT);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageReserved2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Reserved2
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved2 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__RESERVED2);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageExtAsym(
    uint8_t ExtAsymSelCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtAsym
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field ExtAsym */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)ExtAsymSelCount % (uint32_t)4U == (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)ExtAsymSelCount))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)((uint32_t)4U * (uint32_t)ExtAsymSelCount);
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTASYM);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageExtHash(
    uint8_t ExtHashSelCount,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtHash
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field ExtHash */
    uint64_t endPositionOrError;
    if ((uint32_t)4U * (uint32_t)ExtHashSelCount % (uint32_t)4U == (uint32_t)0U)
    {
        if (((uint64_t)Input.len - StartPosition) <
            (uint64_t)((uint32_t)4U * (uint32_t)ExtHashSelCount))
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            endPositionOrError =
                StartPosition +
                (uint64_t)((uint32_t)4U * (uint32_t)ExtHashSelCount);
        }
    }
    else
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__EXTHASH);
}

static inline uint64_t
ValidateSuccessfulAlgorithmsResponseMessageReqAlgStruct(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ReqAlgStruct
        of type _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE
--*/
{
    /* Validating field ReqAlgStruct */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)16U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)16U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__REQALGSTRUCT);
}

uint64_t
SpdmValidateSuccessfulAlgorithmsResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulAlgorithmsResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x63U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulAlgorithmsResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulAlgorithmsResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Length */
    uint64_t positionAfterLength =
        ValidateSuccessfulAlgorithmsResponseMessageLength(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterLength))
    {
        return positionAfterLength;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_MeasurementSpecificationSel
     */
    uint64_t positionAfterMeasurementSpecificationSel =
        ValidateSuccessfulAlgorithmsResponseMessageMeasurementSpecificationSel(
            Input, positionAfterLength);
    if (EverParseIsError(positionAfterMeasurementSpecificationSel))
    {
        return positionAfterMeasurementSpecificationSel;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Reserved */
    uint64_t positionAfterReserved =
        ValidateSuccessfulAlgorithmsResponseMessageReserved(
            Input, positionAfterMeasurementSpecificationSel);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_MeasurementHashAlgo */
    uint64_t positionAfterMeasurementHashAlgo =
        ValidateSuccessfulAlgorithmsResponseMessageMeasurementHashAlgo(
            Input, positionAfterReserved);
    if (EverParseIsError(positionAfterMeasurementHashAlgo))
    {
        return positionAfterMeasurementHashAlgo;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_BaseAsymSel */
    uint64_t positionAfterBaseAsymSel =
        ValidateSuccessfulAlgorithmsResponseMessageBaseAsymSel(
            Input, positionAfterMeasurementHashAlgo);
    if (EverParseIsError(positionAfterBaseAsymSel))
    {
        return positionAfterBaseAsymSel;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_BaseHashSel */
    uint64_t positionAfterBaseHashSel =
        ValidateSuccessfulAlgorithmsResponseMessageBaseHashSel(
            Input, positionAfterBaseAsymSel);
    if (EverParseIsError(positionAfterBaseHashSel))
    {
        return positionAfterBaseHashSel;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Reserved1 */
    uint64_t positionAfterReserved1 =
        ValidateSuccessfulAlgorithmsResponseMessageReserved1(
            Input, positionAfterBaseHashSel);
    if (EverParseIsError(positionAfterReserved1))
    {
        return positionAfterReserved1;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtAsymSelCount */
    uint64_t positionAfterExtAsymSelCount =
        ValidateSuccessfulAlgorithmsResponseMessageExtAsymSelCount(
            Input, positionAfterReserved1);
    if (EverParseIsError(positionAfterExtAsymSelCount))
    {
        return positionAfterExtAsymSelCount;
    }
    uint8_t extAsymSelCount = Input.base[(uint32_t)positionAfterReserved1];
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtHashSelCount */
    uint64_t positionAfterExtHashSelCount =
        ValidateSuccessfulAlgorithmsResponseMessageExtHashSelCount(
            Input, positionAfterExtAsymSelCount);
    if (EverParseIsError(positionAfterExtHashSelCount))
    {
        return positionAfterExtHashSelCount;
    }
    uint8_t extHashSelCount =
        Input.base[(uint32_t)positionAfterExtAsymSelCount];
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_Reserved2 */
    uint64_t positionAfterReserved2 =
        ValidateSuccessfulAlgorithmsResponseMessageReserved2(
            Input, positionAfterExtHashSelCount);
    if (EverParseIsError(positionAfterReserved2))
    {
        return positionAfterReserved2;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtAsym */
    uint64_t positionAfterExtAsym =
        ValidateSuccessfulAlgorithmsResponseMessageExtAsym(
            extAsymSelCount, Input, positionAfterReserved2);
    if (EverParseIsError(positionAfterExtAsym))
    {
        return positionAfterExtAsym;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ExtHash */
    uint64_t positionAfterExtHash =
        ValidateSuccessfulAlgorithmsResponseMessageExtHash(
            extHashSelCount, Input, positionAfterExtAsym);
    if (EverParseIsError(positionAfterExtHash))
    {
        return positionAfterExtHash;
    }
    /* Field _SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE_ReqAlgStruct */
    return ValidateSuccessfulAlgorithmsResponseMessageReqAlgStruct(
        Input, positionAfterExtHash);
}

static inline uint64_t
ValidateGetDigestsRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_DIGESTS_REQUEST_MESSAGE_SPDMVersion
        of type _GET_DIGESTS_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_DIGESTS_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateGetDigestsRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_DIGESTS_REQUEST_MESSAGE_Param1
        of type _GET_DIGESTS_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, GET_DIGESTS_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateGetDigestsRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_DIGESTS_REQUEST_MESSAGE_Param2
        of type _GET_DIGESTS_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, GET_DIGESTS_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateGetDigestsRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _GET_DIGESTS_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateGetDigestsRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        GET_DIGESTS_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x81U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            GET_DIGESTS_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _GET_DIGESTS_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateGetDigestsRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _GET_DIGESTS_REQUEST_MESSAGE_Param2 */
    return ValidateGetDigestsRequestMessageParam2(Input, positionAfterParam1);
}

static inline uint64_t
ValidateSuccessfulDigestsResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_SPDMVersion
        of type _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulDigestsResponseMessageRequestResponseCode(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_RequestResponseCode of type
_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
}

static inline uint64_t
ValidateSuccessfulDigestsResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulDigestsResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulDigestsResponseMessageDigest(
    uint8_t Param2,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_Digest
        of type _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Digest */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(H * (uint16_t)Param2))
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError =
            StartPosition + (uint64_t)(uint32_t)(H * (uint16_t)Param2);
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE__DIGEST);
}

uint64_t
SpdmValidateSuccessfulDigestsResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulDigestsResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_RequestResponseCode */
    uint64_t positionAfterRequestResponseCode =
        ValidateSuccessfulDigestsResponseMessageRequestResponseCode(
            Input, positionAfterSpdmversion);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulDigestsResponseMessageParam1(
            Input, positionAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulDigestsResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    uint8_t param2 = Input.base[(uint32_t)positionAfterParam1];
    /* Field _SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE_Digest */
    return ValidateSuccessfulDigestsResponseMessageDigest(
        param2, Input, positionAfterParam2);
}

static inline uint64_t
ValidateGetCertificateRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CERTIFICATE_REQUEST_MESSAGE_SPDMVersion
        of type _GET_CERTIFICATE_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CERTIFICATE_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateGetCertificateRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CERTIFICATE_REQUEST_MESSAGE_Param1
        of type _GET_CERTIFICATE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CERTIFICATE_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateGetCertificateRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CERTIFICATE_REQUEST_MESSAGE_Param2
        of type _GET_CERTIFICATE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CERTIFICATE_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateGetCertificateRequestMessageOffset(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CERTIFICATE_REQUEST_MESSAGE_Offset
        of type _GET_CERTIFICATE_REQUEST_MESSAGE
--*/
{
    /* Validating field Offset */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CERTIFICATE_REQUEST_MESSAGE__OFFSET);
}

static inline uint64_t
ValidateGetCertificateRequestMessageLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_CERTIFICATE_REQUEST_MESSAGE_Length
        of type _GET_CERTIFICATE_REQUEST_MESSAGE
--*/
{
    /* Validating field Length */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_CERTIFICATE_REQUEST_MESSAGE__LENGTH);
}

uint64_t
SpdmValidateGetCertificateRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _GET_CERTIFICATE_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateGetCertificateRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        GET_CERTIFICATE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x82U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            GET_CERTIFICATE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _GET_CERTIFICATE_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateGetCertificateRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _GET_CERTIFICATE_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateGetCertificateRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _GET_CERTIFICATE_REQUEST_MESSAGE_Offset */
    uint64_t positionAfterOffset =
        ValidateGetCertificateRequestMessageOffset(Input, positionAfterParam2);
    if (EverParseIsError(positionAfterOffset))
    {
        return positionAfterOffset;
    }
    /* Field _GET_CERTIFICATE_REQUEST_MESSAGE_Length */
    return ValidateGetCertificateRequestMessageLength(
        Input, positionAfterOffset);
}

static inline uint64_t
ValidateSuccessfulCertificateResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_SPDMVersion
        of type _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulCertificateResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulCertificateResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulCertificateResponseMessagePortionLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_PortionLength of type
_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE
--*/
{
    /* Validating field PortionLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__PORTIONLENGTH);
}

static inline uint64_t
ValidateSuccessfulCertificateResponseMessageCertChain(
    uint16_t PortionLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_CertChain
        of type _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE
--*/
{
    /* Validating field CertChain */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)PortionLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)PortionLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__CERTCHAIN);
}

uint64_t
SpdmValidateSuccessfulCertificateResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulCertificateResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x02U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulCertificateResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulCertificateResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_PortionLength */
    uint64_t positionAfterPortionLength =
        ValidateSuccessfulCertificateResponseMessagePortionLength(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterPortionLength))
    {
        return positionAfterPortionLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterParam2);
    uint16_t portionLength = (uint16_t)(uint32_t)r;
    /* Field _SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE_CertChain */
    return ValidateSuccessfulCertificateResponseMessageCertChain(
        portionLength, Input, positionAfterPortionLength);
}

static inline uint64_t
ValidateChallengeRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _CHALLENGE_REQUEST_MESSAGE_SPDMVersion
        of type _CHALLENGE_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        CHALLENGE_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateChallengeRequestMessageParam1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _CHALLENGE_REQUEST_MESSAGE_Param1
        of type _CHALLENGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, CHALLENGE_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateChallengeRequestMessageParam2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _CHALLENGE_REQUEST_MESSAGE_Param2
        of type _CHALLENGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, CHALLENGE_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateChallengeRequestMessageNonce(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _CHALLENGE_REQUEST_MESSAGE_Nonce
        of type _CHALLENGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Nonce */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, CHALLENGE_REQUEST_MESSAGE__NONCE);
}

uint64_t
SpdmValidateChallengeRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _CHALLENGE_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateChallengeRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        CHALLENGE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x83U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            CHALLENGE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _CHALLENGE_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateChallengeRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _CHALLENGE_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateChallengeRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _CHALLENGE_REQUEST_MESSAGE_Nonce */
    return ValidateChallengeRequestMessageNonce(Input, positionAfterParam2);
}

static inline uint64_t
ValidateChallengeAuthResponseAttributeBitfield0(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _CHALLENGE_AUTH_RESPONSE_ATTRIBUTE___bitfield_0
        of type _CHALLENGE_AUTH_RESPONSE_ATTRIBUTE
--*/
{
    /* Validating field __bitfield_0 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        CHALLENGE_AUTH_RESPONSE_ATTRIBUTE__BASICMUTAUTHREQ);
}

uint64_t
SpdmValidateChallengeAuthResponseAttribute(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _CHALLENGE_AUTH_RESPONSE_ATTRIBUTE___bitfield_0 */
    return ValidateChallengeAuthResponseAttributeBitfield0(
        Input, StartPosition);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_SPDMVersion of type
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        return EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    return StartPosition + (uint64_t)1U;
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageCertChainHash(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_CertChainHash of type
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field CertChainHash */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__CERTCHAINHASH);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageNonce(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Nonce
        of type _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field Nonce */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__NONCE);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageMeasurementSummaryHash(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_MeasurementSummaryHash of type
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field MeasurementSummaryHash */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__MEASUREMENTSUMMARYHASH);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageOpaqueLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_OpaqueLength of type
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__OPAQUELENGTH);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageOpaqueData(
    uint16_t OpaqueLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_OpaqueData of type
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)OpaqueLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)OpaqueLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__OPAQUEDATA);
}

static inline uint64_t
ValidateSuccessfulChallengeAuthResponseMessageSignature(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Signature of type
_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE
--*/
{
    /* Validating field Signature */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)S)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)S;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__SIGNATURE);
}

uint64_t
SpdmValidateSuccessfulChallengeAuthResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulChallengeAuthResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x03U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulChallengeAuthResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulChallengeAuthResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_CertChainHash */
    uint64_t positionAfterCertChainHash =
        ValidateSuccessfulChallengeAuthResponseMessageCertChainHash(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterCertChainHash))
    {
        return positionAfterCertChainHash;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Nonce */
    uint64_t positionAfterNonce =
        ValidateSuccessfulChallengeAuthResponseMessageNonce(
            Input, positionAfterCertChainHash);
    if (EverParseIsError(positionAfterNonce))
    {
        return positionAfterNonce;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_MeasurementSummaryHash
     */
    uint64_t positionAfterMeasurementSummaryHash =
        ValidateSuccessfulChallengeAuthResponseMessageMeasurementSummaryHash(
            Input, positionAfterNonce);
    if (EverParseIsError(positionAfterMeasurementSummaryHash))
    {
        return positionAfterMeasurementSummaryHash;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_OpaqueLength */
    uint64_t positionAfterOpaqueLength =
        ValidateSuccessfulChallengeAuthResponseMessageOpaqueLength(
            Input, positionAfterMeasurementSummaryHash);
    if (EverParseIsError(positionAfterOpaqueLength))
    {
        return positionAfterOpaqueLength;
    }
    uint16_t r =
        Load16Le(Input.base + (uint32_t)positionAfterMeasurementSummaryHash);
    uint16_t opaqueLength = (uint16_t)(uint32_t)r;
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_OpaqueData */
    uint64_t positionAfterOpaqueData =
        ValidateSuccessfulChallengeAuthResponseMessageOpaqueData(
            opaqueLength, Input, positionAfterOpaqueLength);
    if (EverParseIsError(positionAfterOpaqueData))
    {
        return positionAfterOpaqueData;
    }
    /* Field _SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE_Signature */
    return ValidateSuccessfulChallengeAuthResponseMessageSignature(
        Input, positionAfterOpaqueData);
}

static inline uint64_t
ValidateGetMeasurementsRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_MEASUREMENTS_REQUEST_MESSAGE_SPDMVersion
        of type _GET_MEASUREMENTS_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_MEASUREMENTS_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateGetMeasurementsRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_MEASUREMENTS_REQUEST_MESSAGE_Param1
        of type _GET_MEASUREMENTS_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_MEASUREMENTS_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateGetMeasurementsRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_MEASUREMENTS_REQUEST_MESSAGE_Param2
        of type _GET_MEASUREMENTS_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_MEASUREMENTS_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateGetMeasurementsRequestMessageNonce(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_MEASUREMENTS_REQUEST_MESSAGE_Nonce
        of type _GET_MEASUREMENTS_REQUEST_MESSAGE
--*/
{
    /* Validating field Nonce */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_MEASUREMENTS_REQUEST_MESSAGE__NONCE);
}

static inline uint64_t
ValidateGetMeasurementsRequestMessageSlotIdparam(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_MEASUREMENTS_REQUEST_MESSAGE_SlotIDParam
        of type _GET_MEASUREMENTS_REQUEST_MESSAGE
--*/
{
    /* Validating field SlotIDParam */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_MEASUREMENTS_REQUEST_MESSAGE__SLOTIDPARAM);
}

uint64_t
SpdmValidateGetMeasurementsRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _GET_MEASUREMENTS_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateGetMeasurementsRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        GET_MEASUREMENTS_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE0U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            GET_MEASUREMENTS_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _GET_MEASUREMENTS_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateGetMeasurementsRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _GET_MEASUREMENTS_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateGetMeasurementsRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _GET_MEASUREMENTS_REQUEST_MESSAGE_Nonce */
    uint64_t positionAfterNonce =
        ValidateGetMeasurementsRequestMessageNonce(Input, positionAfterParam2);
    if (EverParseIsError(positionAfterNonce))
    {
        return positionAfterNonce;
    }
    /* Field _GET_MEASUREMENTS_REQUEST_MESSAGE_SlotIDParam */
    return ValidateGetMeasurementsRequestMessageSlotIdparam(
        Input, positionAfterNonce);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_SPDMVersion of type
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageNumberOfBlocks(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_NumberOfBlocks of type
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field NumberOfBlocks */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__NUMBEROFBLOCKS);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageMeasurementRecordLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_MeasurementRecordLength of type
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field MeasurementRecordLength */
    /* Checking that we have enough space for a ULONG, i.e., 4 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)4U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)4U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__MEASUREMENTRECORDLENGTH);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageMeasurementRecord(
    uint32_t MeasurementRecordLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_MeasurementRecord of type
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* it should be UINT24, but 3D doesn't support UINT24 */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)MeasurementRecordLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)MeasurementRecordLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__MEASUREMENTRECORD);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageNonce(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Nonce
        of type _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Nonce */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__NONCE);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageOpaqueLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_OpaqueLength of type
_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__OPAQUELENGTH);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageOpaqueData(
    uint16_t OpaqueLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_OpaqueData
        of type _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)OpaqueLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)OpaqueLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__OPAQUEDATA);
}

static inline uint64_t
ValidateSuccessfulMeasurementsResponseMessageSignature(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Signature
        of type _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE
--*/
{
    /* Validating field Signature */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)S)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)S;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__SIGNATURE);
}

uint64_t
SpdmValidateSuccessfulMeasurementsResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulMeasurementsResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x60U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulMeasurementsResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulMeasurementsResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_NumberOfBlocks */
    uint64_t positionAfterNumberOfBlocks =
        ValidateSuccessfulMeasurementsResponseMessageNumberOfBlocks(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterNumberOfBlocks))
    {
        return positionAfterNumberOfBlocks;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_MeasurementRecordLength
     */
    uint64_t positionAfterMeasurementRecordLength =
        ValidateSuccessfulMeasurementsResponseMessageMeasurementRecordLength(
            Input, positionAfterNumberOfBlocks);
    if (EverParseIsError(positionAfterMeasurementRecordLength))
    {
        return positionAfterMeasurementRecordLength;
    }
    uint32_t measurementRecordLength =
        Load32Le(Input.base + (uint32_t)positionAfterNumberOfBlocks);
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_MeasurementRecord */
    uint64_t positionAfterMeasurementRecord =
        ValidateSuccessfulMeasurementsResponseMessageMeasurementRecord(
            measurementRecordLength,
            Input,
            positionAfterMeasurementRecordLength);
    if (EverParseIsError(positionAfterMeasurementRecord))
    {
        return positionAfterMeasurementRecord;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Nonce */
    uint64_t positionAfterNonce =
        ValidateSuccessfulMeasurementsResponseMessageNonce(
            Input, positionAfterMeasurementRecord);
    if (EverParseIsError(positionAfterNonce))
    {
        return positionAfterNonce;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_OpaqueLength */
    uint64_t positionAfterOpaqueLength =
        ValidateSuccessfulMeasurementsResponseMessageOpaqueLength(
            Input, positionAfterNonce);
    if (EverParseIsError(positionAfterOpaqueLength))
    {
        return positionAfterOpaqueLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterNonce);
    uint16_t opaqueLength = (uint16_t)(uint32_t)r;
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_OpaqueData */
    uint64_t positionAfterOpaqueData =
        ValidateSuccessfulMeasurementsResponseMessageOpaqueData(
            opaqueLength, Input, positionAfterOpaqueLength);
    if (EverParseIsError(positionAfterOpaqueData))
    {
        return positionAfterOpaqueData;
    }
    /* Field _SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE_Signature */
    return ValidateSuccessfulMeasurementsResponseMessageSignature(
        Input, positionAfterOpaqueData);
}

static inline uint64_t
ValidateErrorResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ERROR_RESPONSE_MESSAGE_SPDMVersion
        of type _ERROR_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, ERROR_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateErrorResponseMessageParam1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ERROR_RESPONSE_MESSAGE_Param1
        of type _ERROR_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, ERROR_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateErrorResponseMessageParam2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ERROR_RESPONSE_MESSAGE_Param2
        of type _ERROR_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, ERROR_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateErrorResponseMessageExtendedErrorData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ERROR_RESPONSE_MESSAGE_ExtendedErrorData
        of type _ERROR_RESPONSE_MESSAGE
--*/
{
    /* Validating field ExtendedErrorData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
        uint64_t positionAfterContents;
        if (((uint64_t)(
                 (InputBuffer){
                     .base = Input.base,
                     .len = (uint32_t)StartPosition + (uint32_t)(uint8_t)32U})
                 .len -
             StartPosition) < (uint64_t)1U)
        {
            positionAfterContents = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            positionAfterContents = StartPosition + (uint64_t)1U;
        }
        if (EverParseIsError(positionAfterContents))
        {
            endPositionOrError = positionAfterContents;
        }
        else
        {
            endPositionOrError =
                StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
        }
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ERROR_RESPONSE_MESSAGE__EXTENDEDERRORDATA);
}

uint64_t
SpdmValidateErrorResponseMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _ERROR_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateErrorResponseMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        ERROR_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x7FU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            ERROR_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _ERROR_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateErrorResponseMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _ERROR_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateErrorResponseMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _ERROR_RESPONSE_MESSAGE_ExtendedErrorData */
    return ValidateErrorResponseMessageExtendedErrorData(
        Input, positionAfterParam2);
}

static inline uint64_t
ValidateResponsenotreadyExtendedErrorDataRdtexponent(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_RDTExponent
        of type _RESPONSENOTREADY_EXTENDED_ERROR_DATA
--*/
{
    /* Validating field RDTExponent */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPONSENOTREADY_EXTENDED_ERROR_DATA__RDTEXPONENT);
}

static inline uint64_t
ValidateResponsenotreadyExtendedErrorDataRequestCode(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_RequestCode
        of type _RESPONSENOTREADY_EXTENDED_ERROR_DATA
--*/
{
    /* Validating field RequestCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPONSENOTREADY_EXTENDED_ERROR_DATA__REQUESTCODE);
}

static inline uint64_t
ValidateResponsenotreadyExtendedErrorDataToken(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_Token
        of type _RESPONSENOTREADY_EXTENDED_ERROR_DATA
--*/
{
    /* Validating field Token */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPONSENOTREADY_EXTENDED_ERROR_DATA__TOKEN);
}

static inline uint64_t
ValidateResponsenotreadyExtendedErrorDataRdtm(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_RDTM
        of type _RESPONSENOTREADY_EXTENDED_ERROR_DATA
--*/
{
    /* Validating field RDTM */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPONSENOTREADY_EXTENDED_ERROR_DATA__RDTM);
}

uint64_t
SpdmValidateResponsenotreadyExtendedErrorData(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_RDTExponent */
    uint64_t positionAfterRdtexponent =
        ValidateResponsenotreadyExtendedErrorDataRdtexponent(
            Input, StartPosition);
    if (EverParseIsError(positionAfterRdtexponent))
    {
        return positionAfterRdtexponent;
    }
    /* Field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_RequestCode */
    uint64_t positionAfterRequestCode =
        ValidateResponsenotreadyExtendedErrorDataRequestCode(
            Input, positionAfterRdtexponent);
    if (EverParseIsError(positionAfterRequestCode))
    {
        return positionAfterRequestCode;
    }
    /* Field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_Token */
    uint64_t positionAfterToken =
        ValidateResponsenotreadyExtendedErrorDataToken(
            Input, positionAfterRequestCode);
    if (EverParseIsError(positionAfterToken))
    {
        return positionAfterToken;
    }
    /* Field _RESPONSENOTREADY_EXTENDED_ERROR_DATA_RDTM */
    return ValidateResponsenotreadyExtendedErrorDataRdtm(
        Input, positionAfterToken);
}

static inline uint64_t
ValidateExtenderrordataForVendorLen(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _EXTENDERRORDATA_FOR_VENDOR_Len
        of type _EXTENDERRORDATA_FOR_VENDOR
--*/
{
    /* Validating field Len */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, EXTENDERRORDATA_FOR_VENDOR__LEN);
}

static inline uint64_t
ValidateExtenderrordataForVendorVendorId(
    uint8_t Len,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _EXTENDERRORDATA_FOR_VENDOR_VendorID
        of type _EXTENDERRORDATA_FOR_VENDOR
--*/
{
    /* Validating field VendorID */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)Len)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)Len;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        EXTENDERRORDATA_FOR_VENDOR__VENDORID);
}

static inline uint64_t
ValidateExtenderrordataForVendorOpaqueErrorData(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _EXTENDERRORDATA_FOR_VENDOR_OpaqueErrorData
        of type _EXTENDERRORDATA_FOR_VENDOR
--*/
{
    /* Validating field OpaqueErrorData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)Variable)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
        uint64_t positionAfterContents;
        if (((uint64_t)((InputBuffer){
                            .base = Input.base,
                            .len = (uint32_t)StartPosition + Variable})
                 .len -
             StartPosition) < (uint64_t)1U)
        {
            positionAfterContents = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            positionAfterContents = StartPosition + (uint64_t)1U;
        }
        if (EverParseIsError(positionAfterContents))
        {
            endPositionOrError = positionAfterContents;
        }
        else if (
            (uint32_t)positionAfterContents !=
            ((InputBuffer){
                 .base = Input.base, .len = (uint32_t)StartPosition + Variable})
                .len)
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_UNEXPECTED_PADDING;
        }
        else
        {
            endPositionOrError = StartPosition + (uint64_t)Variable;
        }
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        EXTENDERRORDATA_FOR_VENDOR__OPAQUEERRORDATA);
}

uint64_t
SpdmValidateExtenderrordataForVendor(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _EXTENDERRORDATA_FOR_VENDOR_Len */
    uint64_t positionAfterLen =
        ValidateExtenderrordataForVendorLen(Input, StartPosition);
    if (EverParseIsError(positionAfterLen))
    {
        return positionAfterLen;
    }
    uint8_t len = Input.base[(uint32_t)StartPosition];
    /* Field _EXTENDERRORDATA_FOR_VENDOR_VendorID */
    uint64_t positionAfterVendorId =
        ValidateExtenderrordataForVendorVendorId(len, Input, positionAfterLen);
    if (EverParseIsError(positionAfterVendorId))
    {
        return positionAfterVendorId;
    }
    /* Field _EXTENDERRORDATA_FOR_VENDOR_OpaqueErrorData */
    return ValidateExtenderrordataForVendorOpaqueErrorData(
        Variable, Input, positionAfterVendorId);
}

static inline uint64_t
ValidateRespondIfReadyRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPOND_IF_READY_REQUEST_MESSAGE_SPDMVersion
        of type _RESPOND_IF_READY_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPOND_IF_READY_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateRespondIfReadyRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPOND_IF_READY_REQUEST_MESSAGE_Param1
        of type _RESPOND_IF_READY_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPOND_IF_READY_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateRespondIfReadyRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _RESPOND_IF_READY_REQUEST_MESSAGE_Param2
        of type _RESPOND_IF_READY_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        RESPOND_IF_READY_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateRespondIfReadyRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _RESPOND_IF_READY_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateRespondIfReadyRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        RESPOND_IF_READY_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xFFU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            RESPOND_IF_READY_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _RESPOND_IF_READY_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateRespondIfReadyRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _RESPOND_IF_READY_REQUEST_MESSAGE_Param2 */
    return ValidateRespondIfReadyRequestMessageParam2(
        Input, positionAfterParam1);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_SPDMVersion
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_Param1
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_Param2
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageStandardId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_StandardID
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field StandardID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__STANDARDID);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageLen(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_Len
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field Len */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__LEN);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageVendorId(
    uint8_t Len,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_VendorID
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field VendorID */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)Len)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)Len;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__VENDORID);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageReqLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_ReqLength
        of type _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field ReqLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__REQLENGTH);
}

static inline uint64_t
ValidateVendorDefinedRequestRequestMessageVendorDefinedReqPayload(
    uint16_t ReqLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_VendorDefinedReqPayload of type
_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field VendorDefinedReqPayload */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)ReqLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)ReqLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__VENDORDEFINEDREQPAYLOAD);
}

uint64_t
SpdmValidateVendorDefinedRequestRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateVendorDefinedRequestRequestMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xFEU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateVendorDefinedRequestRequestMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateVendorDefinedRequestRequestMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_StandardID */
    uint64_t positionAfterStandardId =
        ValidateVendorDefinedRequestRequestMessageStandardId(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterStandardId))
    {
        return positionAfterStandardId;
    }
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_Len */
    uint64_t positionAfterLen = ValidateVendorDefinedRequestRequestMessageLen(
        Input, positionAfterStandardId);
    if (EverParseIsError(positionAfterLen))
    {
        return positionAfterLen;
    }
    uint8_t len = Input.base[(uint32_t)positionAfterStandardId];
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_VendorID */
    uint64_t positionAfterVendorId =
        ValidateVendorDefinedRequestRequestMessageVendorId(
            len, Input, positionAfterLen);
    if (EverParseIsError(positionAfterVendorId))
    {
        return positionAfterVendorId;
    }
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_ReqLength */
    uint64_t positionAfterReqLength =
        ValidateVendorDefinedRequestRequestMessageReqLength(
            Input, positionAfterVendorId);
    if (EverParseIsError(positionAfterReqLength))
    {
        return positionAfterReqLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterVendorId);
    uint16_t reqLength = (uint16_t)(uint32_t)r;
    /* Field _VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE_VendorDefinedReqPayload */
    return ValidateVendorDefinedRequestRequestMessageVendorDefinedReqPayload(
        reqLength, Input, positionAfterReqLength);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_SPDMVersion of type
_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_Param1
        of type _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_Param2
        of type _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageStandardId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_StandardID
        of type _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field StandardID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__STANDARDID);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageLen(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_Len
        of type _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field Len */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__LEN);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageVendorId(
    uint8_t Len,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_VendorID
        of type _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field VendorID */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)Len)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)Len;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__VENDORID);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageRespLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_RespLength
        of type _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field RespLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__RESPLENGTH);
}

static inline uint64_t
ValidateVendorDefinedResponseResponseMessageVendorDefinedRespPayload(
    uint16_t RespLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_VendorDefinedRespPayload of type
_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE
--*/
{
    /* Validating field VendorDefinedRespPayload */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)RespLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)RespLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__VENDORDEFINEDRESPPAYLOAD);
}

uint64_t
SpdmValidateVendorDefinedResponseResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateVendorDefinedResponseResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x7EU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateVendorDefinedResponseResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateVendorDefinedResponseResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_StandardID */
    uint64_t positionAfterStandardId =
        ValidateVendorDefinedResponseResponseMessageStandardId(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterStandardId))
    {
        return positionAfterStandardId;
    }
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_Len */
    uint64_t positionAfterLen = ValidateVendorDefinedResponseResponseMessageLen(
        Input, positionAfterStandardId);
    if (EverParseIsError(positionAfterLen))
    {
        return positionAfterLen;
    }
    uint8_t len = Input.base[(uint32_t)positionAfterStandardId];
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_VendorID */
    uint64_t positionAfterVendorId =
        ValidateVendorDefinedResponseResponseMessageVendorId(
            len, Input, positionAfterLen);
    if (EverParseIsError(positionAfterVendorId))
    {
        return positionAfterVendorId;
    }
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_RespLength */
    uint64_t positionAfterRespLength =
        ValidateVendorDefinedResponseResponseMessageRespLength(
            Input, positionAfterVendorId);
    if (EverParseIsError(positionAfterRespLength))
    {
        return positionAfterRespLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterVendorId);
    uint16_t respLength = (uint16_t)(uint32_t)r;
    /* Field _VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE_VendorDefinedRespPayload
     */
    return ValidateVendorDefinedResponseResponseMessageVendorDefinedRespPayload(
        respLength, Input, positionAfterRespLength);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_SPDMVersion
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_Param1
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_Param2
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageReqSessionId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_ReqSessionID
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field ReqSessionID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__REQSESSIONID);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_Reserved
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__RESERVED);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageRandomData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_RandomData
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field RandomData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__RANDOMDATA);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageExchangeData(
    uint32_t D,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_ExchangeData
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field ExchangeData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)D)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)D;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__EXCHANGEDATA);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageOpaqueDataLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_OpaqueDataLength
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field OpaqueDataLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATALENGTH);
}

static inline uint64_t
ValidateKeyExchangeRequestMessageOpaqueData(
    uint16_t OpaqueDataLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_EXCHANGE_REQUEST_MESSAGE_OpaqueData
        of type _KEY_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field OpaqueData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)OpaqueDataLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError =
            StartPosition + (uint64_t)(uint32_t)OpaqueDataLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATA);
}

uint64_t
SpdmValidateKeyExchangeRequestMessage(
    uint32_t D,
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateKeyExchangeRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        KEY_EXCHANGE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE4U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            KEY_EXCHANGE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateKeyExchangeRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateKeyExchangeRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_ReqSessionID */
    uint64_t positionAfterReqSessionId =
        ValidateKeyExchangeRequestMessageReqSessionId(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterReqSessionId))
    {
        return positionAfterReqSessionId;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_Reserved */
    uint64_t positionAfterReserved = ValidateKeyExchangeRequestMessageReserved(
        Input, positionAfterReqSessionId);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_RandomData */
    uint64_t positionAfterRandomData =
        ValidateKeyExchangeRequestMessageRandomData(
            Input, positionAfterReserved);
    if (EverParseIsError(positionAfterRandomData))
    {
        return positionAfterRandomData;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_ExchangeData */
    uint64_t positionAfterExchangeData =
        ValidateKeyExchangeRequestMessageExchangeData(
            D, Input, positionAfterRandomData);
    if (EverParseIsError(positionAfterExchangeData))
    {
        return positionAfterExchangeData;
    }
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_OpaqueDataLength */
    uint64_t positionAfterOpaqueDataLength =
        ValidateKeyExchangeRequestMessageOpaqueDataLength(
            Input, positionAfterExchangeData);
    if (EverParseIsError(positionAfterOpaqueDataLength))
    {
        return positionAfterOpaqueDataLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterExchangeData);
    uint16_t opaqueDataLength = (uint16_t)(uint32_t)r;
    /* Field _KEY_EXCHANGE_REQUEST_MESSAGE_OpaqueData */
    return ValidateKeyExchangeRequestMessageOpaqueData(
        opaqueDataLength, Input, positionAfterOpaqueDataLength);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_SPDMVersion of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageReqSessionId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_ReqSessionID of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field ReqSessionID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__REQSESSIONID);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageMutAuthRequested(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_MutAuthRequested of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field MutAuthRequested */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__MUTAUTHREQUESTED);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageSlotIdparam(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_SlotIDParam of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field SlotIDParam */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__SLOTIDPARAM);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageRandomData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_RandomData of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field RandomData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)(uint8_t)32U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)(uint8_t)32U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__RANDOMDATA);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageExchangeData(
    uint32_t D,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_ExchangeData of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field ExchangeData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)D)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)D;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__EXCHANGEDATA);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageMeasurementSummaryHash(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_MeasurementSummaryHash of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field MeasurementSummaryHash */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__MEASUREMENTSUMMARYHASH);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageOpaqueDataLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueDataLength of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueDataLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATALENGTH);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageOpaqueData(
    uint16_t OpaqueDataLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueData of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)OpaqueDataLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError =
            StartPosition + (uint64_t)(uint32_t)OpaqueDataLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATA);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageSignature(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_Signature of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Signature */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)S)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)S;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__SIGNATURE);
}

static inline uint64_t
ValidateSuccessfulKeyExchangeRspResponseMessageResponderVerifyData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_ResponderVerifyData of type
_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field ResponderVerifyData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__RESPONDERVERIFYDATA);
}

uint64_t
SpdmValidateSuccessfulKeyExchangeRspResponseMessage(
    uint32_t D,
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulKeyExchangeRspResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x64U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulKeyExchangeRspResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulKeyExchangeRspResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_ReqSessionID */
    uint64_t positionAfterReqSessionId =
        ValidateSuccessfulKeyExchangeRspResponseMessageReqSessionId(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterReqSessionId))
    {
        return positionAfterReqSessionId;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_MutAuthRequested */
    uint64_t positionAfterMutAuthRequested =
        ValidateSuccessfulKeyExchangeRspResponseMessageMutAuthRequested(
            Input, positionAfterReqSessionId);
    if (EverParseIsError(positionAfterMutAuthRequested))
    {
        return positionAfterMutAuthRequested;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_SlotIDParam */
    uint64_t positionAfterSlotIdparam =
        ValidateSuccessfulKeyExchangeRspResponseMessageSlotIdparam(
            Input, positionAfterMutAuthRequested);
    if (EverParseIsError(positionAfterSlotIdparam))
    {
        return positionAfterSlotIdparam;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_RandomData */
    uint64_t positionAfterRandomData =
        ValidateSuccessfulKeyExchangeRspResponseMessageRandomData(
            Input, positionAfterSlotIdparam);
    if (EverParseIsError(positionAfterRandomData))
    {
        return positionAfterRandomData;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_ExchangeData */
    uint64_t positionAfterExchangeData =
        ValidateSuccessfulKeyExchangeRspResponseMessageExchangeData(
            D, Input, positionAfterRandomData);
    if (EverParseIsError(positionAfterExchangeData))
    {
        return positionAfterExchangeData;
    }
    /* Field
     * _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_MeasurementSummaryHash */
    uint64_t positionAfterMeasurementSummaryHash =
        ValidateSuccessfulKeyExchangeRspResponseMessageMeasurementSummaryHash(
            Input, positionAfterExchangeData);
    if (EverParseIsError(positionAfterMeasurementSummaryHash))
    {
        return positionAfterMeasurementSummaryHash;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueDataLength */
    uint64_t positionAfterOpaqueDataLength =
        ValidateSuccessfulKeyExchangeRspResponseMessageOpaqueDataLength(
            Input, positionAfterMeasurementSummaryHash);
    if (EverParseIsError(positionAfterOpaqueDataLength))
    {
        return positionAfterOpaqueDataLength;
    }
    uint16_t r =
        Load16Le(Input.base + (uint32_t)positionAfterMeasurementSummaryHash);
    uint16_t opaqueDataLength = (uint16_t)(uint32_t)r;
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueData */
    uint64_t positionAfterOpaqueData =
        ValidateSuccessfulKeyExchangeRspResponseMessageOpaqueData(
            opaqueDataLength, Input, positionAfterOpaqueDataLength);
    if (EverParseIsError(positionAfterOpaqueData))
    {
        return positionAfterOpaqueData;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_Signature */
    uint64_t positionAfterSignature =
        ValidateSuccessfulKeyExchangeRspResponseMessageSignature(
            Input, positionAfterOpaqueData);
    if (EverParseIsError(positionAfterSignature))
    {
        return positionAfterSignature;
    }
    /* Field _SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_ResponderVerifyData
     */
    return ValidateSuccessfulKeyExchangeRspResponseMessageResponderVerifyData(
        Input, positionAfterSignature);
}

static inline uint64_t
ValidateFinishRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _FINISH_REQUEST_MESSAGE_SPDMVersion
        of type _FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, FINISH_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateFinishRequestMessageParam1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _FINISH_REQUEST_MESSAGE_Param1
        of type _FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, FINISH_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateFinishRequestMessageParam2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _FINISH_REQUEST_MESSAGE_Param2
        of type _FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, FINISH_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateFinishRequestMessageSignature(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _FINISH_REQUEST_MESSAGE_Signature
        of type _FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field Signature */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)S)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)S;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, FINISH_REQUEST_MESSAGE__SIGNATURE);
}

static inline uint64_t
ValidateFinishRequestMessageRequesterVerifyData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _FINISH_REQUEST_MESSAGE_RequesterVerifyData
        of type _FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field RequesterVerifyData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        FINISH_REQUEST_MESSAGE__REQUESTERVERIFYDATA);
}

uint64_t
SpdmValidateFinishRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _FINISH_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateFinishRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        FINISH_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE5U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            FINISH_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _FINISH_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateFinishRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _FINISH_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateFinishRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _FINISH_REQUEST_MESSAGE_Signature */
    uint64_t positionAfterSignature =
        ValidateFinishRequestMessageSignature(Input, positionAfterParam2);
    if (EverParseIsError(positionAfterSignature))
    {
        return positionAfterSignature;
    }
    /* Field _FINISH_REQUEST_MESSAGE_RequesterVerifyData */
    return ValidateFinishRequestMessageRequesterVerifyData(
        Input, positionAfterSignature);
}

static inline uint64_t
ValidateSuccessfulFinishResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_SPDMVersion
        of type _SUCCESSFUL_FINISH_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_FINISH_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulFinishResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_FINISH_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_FINISH_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulFinishResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_FINISH_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_FINISH_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateSuccessfulFinishResponseMessageRequesterVerifyData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_FINISH_RESPONSE_MESSAGE_RequesterVerifyData of type
_SUCCESSFUL_FINISH_RESPONSE_MESSAGE
--*/
{
    /* Validating field RequesterVerifyData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_FINISH_RESPONSE_MESSAGE__REQUESTERVERIFYDATA);
}

uint64_t
SpdmValidateSuccessfulFinishResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulFinishResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_FINISH_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x65U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_FINISH_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulFinishResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateSuccessfulFinishResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _SUCCESSFUL_FINISH_RESPONSE_MESSAGE_RequesterVerifyData */
    return ValidateSuccessfulFinishResponseMessageRequesterVerifyData(
        Input, positionAfterParam2);
}

static inline uint64_t
ValidatePskExchangeRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_SPDMVersion
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidatePskExchangeRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_Param1
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidatePskExchangeRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_Param2
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidatePskExchangeRequestMessageReqSessionId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_ReqSessionID
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field ReqSessionID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__REQSESSIONID);
}

static inline uint64_t
ValidatePskExchangeRequestMessageP(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_P
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field P */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, PSK_EXCHANGE_REQUEST_MESSAGE__P);
}

static inline uint64_t
ValidatePskExchangeRequestMessageR(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_R
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field R */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, PSK_EXCHANGE_REQUEST_MESSAGE__R);
}

static inline uint64_t
ValidatePskExchangeRequestMessageOpaqueDataLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_OpaqueDataLength
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field OpaqueDataLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATALENGTH);
}

static inline uint64_t
ValidatePskExchangeRequestMessagePskhint(
    uint16_t P,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_PSKHint
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field PSKHint */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)P)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)P;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__PSKHINT);
}

static inline uint64_t
ValidatePskExchangeRequestMessageRequesterContext(
    uint16_t R,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_RequesterContext
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field RequesterContext */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)R)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)R;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__REQUESTERCONTEXT);
}

static inline uint64_t
ValidatePskExchangeRequestMessageOpaqueData(
    uint16_t OpaqueDataLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_REQUEST_MESSAGE_OpaqueData
        of type _PSK_EXCHANGE_REQUEST_MESSAGE
--*/
{
    /* Validating field OpaqueData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)OpaqueDataLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError =
            StartPosition + (uint64_t)(uint32_t)OpaqueDataLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_REQUEST_MESSAGE__OPAQUEDATA);
}

uint64_t
SpdmValidatePskExchangeRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidatePskExchangeRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        PSK_EXCHANGE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE6U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            PSK_EXCHANGE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidatePskExchangeRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidatePskExchangeRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_ReqSessionID */
    uint64_t positionAfterReqSessionId =
        ValidatePskExchangeRequestMessageReqSessionId(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterReqSessionId))
    {
        return positionAfterReqSessionId;
    }
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_P */
    uint64_t positionAfterP =
        ValidatePskExchangeRequestMessageP(Input, positionAfterReqSessionId);
    if (EverParseIsError(positionAfterP))
    {
        return positionAfterP;
    }
    uint16_t r0 = Load16Le(Input.base + (uint32_t)positionAfterReqSessionId);
    uint16_t p = (uint16_t)(uint32_t)r0;
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_R */
    uint64_t positionAfterR =
        ValidatePskExchangeRequestMessageR(Input, positionAfterP);
    if (EverParseIsError(positionAfterR))
    {
        return positionAfterR;
    }
    uint16_t r1 = Load16Le(Input.base + (uint32_t)positionAfterP);
    uint16_t r2 = (uint16_t)(uint32_t)r1;
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_OpaqueDataLength */
    uint64_t positionAfterOpaqueDataLength =
        ValidatePskExchangeRequestMessageOpaqueDataLength(
            Input, positionAfterR);
    if (EverParseIsError(positionAfterOpaqueDataLength))
    {
        return positionAfterOpaqueDataLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterR);
    uint16_t opaqueDataLength = (uint16_t)(uint32_t)r;
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_PSKHint */
    uint64_t positionAfterPskhint = ValidatePskExchangeRequestMessagePskhint(
        p, Input, positionAfterOpaqueDataLength);
    if (EverParseIsError(positionAfterPskhint))
    {
        return positionAfterPskhint;
    }
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_RequesterContext */
    uint64_t positionAfterRequesterContext =
        ValidatePskExchangeRequestMessageRequesterContext(
            r2, Input, positionAfterPskhint);
    if (EverParseIsError(positionAfterRequesterContext))
    {
        return positionAfterRequesterContext;
    }
    /* Field _PSK_EXCHANGE_REQUEST_MESSAGE_OpaqueData */
    return ValidatePskExchangeRequestMessageOpaqueData(
        opaqueDataLength, Input, positionAfterRequesterContext);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_SPDMVersion
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Param1
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Param2
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageRspSessionId(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_RspSessionID
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field RspSessionID */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RSPSESSIONID);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageReserved(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Reserved
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Reserved */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RESERVED);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageQ(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Q
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Q */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__Q);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageOpaqueDataLength(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueDataLength
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueDataLength */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)2U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)2U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATALENGTH);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageMeasurementSummaryHash(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_MeasurementSummaryHash of type
_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field MeasurementSummaryHash */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__MEASUREMENTSUMMARYHASH);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageResponderContext(
    uint16_t Q,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_ResponderContext
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field ResponderContext */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)Q)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)Q;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RESPONDERCONTEXT);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageOpaqueData(
    uint16_t OpaqueDataLength,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueData
        of type _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field OpaqueData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) <
        (uint64_t)(uint32_t)OpaqueDataLength)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError =
            StartPosition + (uint64_t)(uint32_t)OpaqueDataLength;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__OPAQUEDATA);
}

static inline uint64_t
ValidatePskExchangeRspResponseMessageResponderVerifyData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_ResponderVerifyData of type
_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field ResponderVerifyData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__RESPONDERVERIFYDATA);
}

uint64_t
SpdmValidatePskExchangeRspResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidatePskExchangeRspResponseMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x66U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            PSK_EXCHANGE_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidatePskExchangeRspResponseMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidatePskExchangeRspResponseMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_RspSessionID */
    uint64_t positionAfterRspSessionId =
        ValidatePskExchangeRspResponseMessageRspSessionId(
            Input, positionAfterParam2);
    if (EverParseIsError(positionAfterRspSessionId))
    {
        return positionAfterRspSessionId;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Reserved */
    uint64_t positionAfterReserved =
        ValidatePskExchangeRspResponseMessageReserved(
            Input, positionAfterRspSessionId);
    if (EverParseIsError(positionAfterReserved))
    {
        return positionAfterReserved;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_Q */
    uint64_t positionAfterQ =
        ValidatePskExchangeRspResponseMessageQ(Input, positionAfterReserved);
    if (EverParseIsError(positionAfterQ))
    {
        return positionAfterQ;
    }
    uint16_t r0 = Load16Le(Input.base + (uint32_t)positionAfterReserved);
    uint16_t q = (uint16_t)(uint32_t)r0;
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueDataLength */
    uint64_t positionAfterOpaqueDataLength =
        ValidatePskExchangeRspResponseMessageOpaqueDataLength(
            Input, positionAfterQ);
    if (EverParseIsError(positionAfterOpaqueDataLength))
    {
        return positionAfterOpaqueDataLength;
    }
    uint16_t r = Load16Le(Input.base + (uint32_t)positionAfterQ);
    uint16_t opaqueDataLength = (uint16_t)(uint32_t)r;
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_MeasurementSummaryHash */
    uint64_t positionAfterMeasurementSummaryHash =
        ValidatePskExchangeRspResponseMessageMeasurementSummaryHash(
            Input, positionAfterOpaqueDataLength);
    if (EverParseIsError(positionAfterMeasurementSummaryHash))
    {
        return positionAfterMeasurementSummaryHash;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_ResponderContext */
    uint64_t positionAfterResponderContext =
        ValidatePskExchangeRspResponseMessageResponderContext(
            q, Input, positionAfterMeasurementSummaryHash);
    if (EverParseIsError(positionAfterResponderContext))
    {
        return positionAfterResponderContext;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_OpaqueData */
    uint64_t positionAfterOpaqueData =
        ValidatePskExchangeRspResponseMessageOpaqueData(
            opaqueDataLength, Input, positionAfterResponderContext);
    if (EverParseIsError(positionAfterOpaqueData))
    {
        return positionAfterOpaqueData;
    }
    /* Field _PSK_EXCHANGE_RSP_RESPONSE_MESSAGE_ResponderVerifyData */
    return ValidatePskExchangeRspResponseMessageResponderVerifyData(
        Input, positionAfterOpaqueData);
}

static inline uint64_t
ValidatePskFinishRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_FINISH_REQUEST_MESSAGE_SPDMVersion
        of type _PSK_FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_FINISH_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidatePskFinishRequestMessageParam1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_FINISH_REQUEST_MESSAGE_Param1
        of type _PSK_FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, PSK_FINISH_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidatePskFinishRequestMessageParam2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_FINISH_REQUEST_MESSAGE_Param2
        of type _PSK_FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, PSK_FINISH_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidatePskFinishRequestMessageRequesterVerifyData(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _PSK_FINISH_REQUEST_MESSAGE_RequesterVerifyData
        of type _PSK_FINISH_REQUEST_MESSAGE
--*/
{
    /* Validating field RequesterVerifyData */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)(uint32_t)H)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)(uint32_t)H;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        PSK_FINISH_REQUEST_MESSAGE__REQUESTERVERIFYDATA);
}

uint64_t
SpdmValidatePskFinishRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _PSK_FINISH_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidatePskFinishRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        PSK_FINISH_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE7U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            PSK_FINISH_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _PSK_FINISH_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidatePskFinishRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _PSK_FINISH_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidatePskFinishRequestMessageParam2(Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _PSK_FINISH_REQUEST_MESSAGE_RequesterVerifyData */
    return ValidatePskFinishRequestMessageRequesterVerifyData(
        Input, positionAfterParam2);
}

static inline uint64_t
ValidateSuccessfulPskFinishRspResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE_SPDMVersion of type
_SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateSuccessfulPskFinishRspResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE_Param1
        of type _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateSuccessfulPskFinishRspResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE_Param2
        of type _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateSuccessfulPskFinishRspResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateSuccessfulPskFinishRspResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x67U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateSuccessfulPskFinishRspResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE_Param2 */
    return ValidateSuccessfulPskFinishRspResponseMessageParam2(
        Input, positionAfterParam1);
}

static inline uint64_t
ValidateHeartbeatRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _HEARTBEAT_REQUEST_MESSAGE_SPDMVersion
        of type _HEARTBEAT_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        HEARTBEAT_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateHeartbeatRequestMessageParam1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _HEARTBEAT_REQUEST_MESSAGE_Param1
        of type _HEARTBEAT_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, HEARTBEAT_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateHeartbeatRequestMessageParam2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _HEARTBEAT_REQUEST_MESSAGE_Param2
        of type _HEARTBEAT_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, HEARTBEAT_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateHeartbeatRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _HEARTBEAT_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateHeartbeatRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        HEARTBEAT_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE8U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            HEARTBEAT_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _HEARTBEAT_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateHeartbeatRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _HEARTBEAT_REQUEST_MESSAGE_Param2 */
    return ValidateHeartbeatRequestMessageParam2(Input, positionAfterParam1);
}

static inline uint64_t
ValidateHeartbeatAckResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _HEARTBEAT_ACK_RESPONSE_MESSAGE_SPDMVersion
        of type _HEARTBEAT_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        HEARTBEAT_ACK_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateHeartbeatAckResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _HEARTBEAT_ACK_RESPONSE_MESSAGE_Param1
        of type _HEARTBEAT_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        HEARTBEAT_ACK_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateHeartbeatAckResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _HEARTBEAT_ACK_RESPONSE_MESSAGE_Param2
        of type _HEARTBEAT_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        HEARTBEAT_ACK_RESPONSE_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateHeartbeatAckResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _HEARTBEAT_ACK_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateHeartbeatAckResponseMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        HEARTBEAT_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x68U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            HEARTBEAT_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _HEARTBEAT_ACK_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateHeartbeatAckResponseMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _HEARTBEAT_ACK_RESPONSE_MESSAGE_Param2 */
    return ValidateHeartbeatAckResponseMessageParam2(
        Input, positionAfterParam1);
}

static inline uint64_t
ValidateKeyUpdateRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_UPDATE_REQUEST_MESSAGE_SPDMVersion
        of type _KEY_UPDATE_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_UPDATE_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateKeyUpdateRequestMessageParam1(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_UPDATE_REQUEST_MESSAGE_Param1
        of type _KEY_UPDATE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, KEY_UPDATE_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateKeyUpdateRequestMessageParam2(InputBuffer Input, uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_UPDATE_REQUEST_MESSAGE_Param2
        of type _KEY_UPDATE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, KEY_UPDATE_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateKeyUpdateRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _KEY_UPDATE_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateKeyUpdateRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        KEY_UPDATE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xE9U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            KEY_UPDATE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _KEY_UPDATE_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateKeyUpdateRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _KEY_UPDATE_REQUEST_MESSAGE_Param2 */
    return ValidateKeyUpdateRequestMessageParam2(Input, positionAfterParam1);
}

static inline uint64_t
ValidateKeyUpdateAckResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_UPDATE_ACK_RESPONSE_MESSAGE_SPDMVersion
        of type _KEY_UPDATE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_UPDATE_ACK_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateKeyUpdateAckResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_UPDATE_ACK_RESPONSE_MESSAGE_Param1
        of type _KEY_UPDATE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_UPDATE_ACK_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateKeyUpdateAckResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _KEY_UPDATE_ACK_RESPONSE_MESSAGE_Param2
        of type _KEY_UPDATE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        KEY_UPDATE_ACK_RESPONSE_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateKeyUpdateAckResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _KEY_UPDATE_ACK_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateKeyUpdateAckResponseMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        KEY_UPDATE_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x69U;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            KEY_UPDATE_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _KEY_UPDATE_ACK_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateKeyUpdateAckResponseMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _KEY_UPDATE_ACK_RESPONSE_MESSAGE_Param2 */
    return ValidateKeyUpdateAckResponseMessageParam2(
        Input, positionAfterParam1);
}

static inline uint64_t
ValidateGetEncapsulatedRequestRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE_SPDMVersion of type
_GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateGetEncapsulatedRequestRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE_Param1
        of type _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateGetEncapsulatedRequestRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE_Param2
        of type _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateGetEncapsulatedRequestRequestMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateGetEncapsulatedRequestRequestMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xEAU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateGetEncapsulatedRequestRequestMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE_Param2 */
    return ValidateGetEncapsulatedRequestRequestMessageParam2(
        Input, positionAfterParam1);
}

static inline uint64_t
ValidateEncapsulatedRequestResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_SPDMVersion
        of type _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateEncapsulatedRequestResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_Param1
        of type _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateEncapsulatedRequestResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_Param2
        of type _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateEncapsulatedRequestResponseMessageEncapsulatedRequest(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_EncapsulatedRequest of type
_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE
--*/
{
    /* Validating field EncapsulatedRequest */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)Variable)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
        uint64_t positionAfterContents;
        if (((uint64_t)((InputBuffer){
                            .base = Input.base,
                            .len = (uint32_t)StartPosition + Variable})
                 .len -
             StartPosition) < (uint64_t)1U)
        {
            positionAfterContents = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            positionAfterContents = StartPosition + (uint64_t)1U;
        }
        if (EverParseIsError(positionAfterContents))
        {
            endPositionOrError = positionAfterContents;
        }
        else if (
            (uint32_t)positionAfterContents !=
            ((InputBuffer){
                 .base = Input.base, .len = (uint32_t)StartPosition + Variable})
                .len)
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_UNEXPECTED_PADDING;
        }
        else
        {
            endPositionOrError = StartPosition + (uint64_t)Variable;
        }
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__ENCAPSULATEDREQUEST);
}

uint64_t
SpdmValidateEncapsulatedRequestResponseMessage(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateEncapsulatedRequestResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x6AU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            ENCAPSULATED_REQUEST_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateEncapsulatedRequestResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateEncapsulatedRequestResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _ENCAPSULATED_REQUEST_RESPONSE_MESSAGE_EncapsulatedRequest */
    return ValidateEncapsulatedRequestResponseMessageEncapsulatedRequest(
        Variable, Input, positionAfterParam2);
}

static inline uint64_t
ValidateDeliverEncapsulatedResponseRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_SPDMVersion of type
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateDeliverEncapsulatedResponseRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_Param1 of type
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateDeliverEncapsulatedResponseRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_Param2 of type
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateDeliverEncapsulatedResponseRequestMessageEncapsulatedResponse(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_EncapsulatedResponse of type
_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE
--*/
{
    /* Validating field EncapsulatedResponse */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)Variable)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
        uint64_t positionAfterContents;
        if (((uint64_t)((InputBuffer){
                            .base = Input.base,
                            .len = (uint32_t)StartPosition + Variable})
                 .len -
             StartPosition) < (uint64_t)1U)
        {
            positionAfterContents = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            positionAfterContents = StartPosition + (uint64_t)1U;
        }
        if (EverParseIsError(positionAfterContents))
        {
            endPositionOrError = positionAfterContents;
        }
        else if (
            (uint32_t)positionAfterContents !=
            ((InputBuffer){
                 .base = Input.base, .len = (uint32_t)StartPosition + Variable})
                .len)
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_UNEXPECTED_PADDING;
        }
        else
        {
            endPositionOrError = StartPosition + (uint64_t)Variable;
        }
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__ENCAPSULATEDRESPONSE);
}

uint64_t
SpdmValidateDeliverEncapsulatedResponseRequestMessage(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateDeliverEncapsulatedResponseRequestMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xEBU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateDeliverEncapsulatedResponseRequestMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateDeliverEncapsulatedResponseRequestMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE_EncapsulatedResponse
     */
    return ValidateDeliverEncapsulatedResponseRequestMessageEncapsulatedResponse(
        Variable, Input, positionAfterParam2);
}

static inline uint64_t
ValidateEncapsulatedResponseAckResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_SPDMVersion of type
_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateEncapsulatedResponseAckResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_Param1
        of type _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateEncapsulatedResponseAckResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_Param2
        of type _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__PARAM2);
}

static inline uint64_t
ValidateEncapsulatedResponseAckResponseMessageEncapsulatedRequest(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field
_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_EncapsulatedRequest of type
_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field EncapsulatedRequest */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)Variable)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
        uint64_t positionAfterContents;
        if (((uint64_t)((InputBuffer){
                            .base = Input.base,
                            .len = (uint32_t)StartPosition + Variable})
                 .len -
             StartPosition) < (uint64_t)1U)
        {
            positionAfterContents = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
        }
        else
        {
            positionAfterContents = StartPosition + (uint64_t)1U;
        }
        if (EverParseIsError(positionAfterContents))
        {
            endPositionOrError = positionAfterContents;
        }
        else if (
            (uint32_t)positionAfterContents !=
            ((InputBuffer){
                 .base = Input.base, .len = (uint32_t)StartPosition + Variable})
                .len)
        {
            endPositionOrError = EVERPARSE_VALIDATOR_ERROR_UNEXPECTED_PADDING;
        }
        else
        {
            endPositionOrError = StartPosition + (uint64_t)Variable;
        }
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__ENCAPSULATEDREQUEST);
}

uint64_t
SpdmValidateEncapsulatedResponseAckResponseMessage(
    uint32_t Variable,
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateEncapsulatedResponseAckResponseMessageSpdmversion(
            Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x6BU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 =
        ValidateEncapsulatedResponseAckResponseMessageParam1(
            Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_Param2 */
    uint64_t positionAfterParam2 =
        ValidateEncapsulatedResponseAckResponseMessageParam2(
            Input, positionAfterParam1);
    if (EverParseIsError(positionAfterParam2))
    {
        return positionAfterParam2;
    }
    /* Field _ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE_EncapsulatedRequest */
    return ValidateEncapsulatedResponseAckResponseMessageEncapsulatedRequest(
        Variable, Input, positionAfterParam2);
}

static inline uint64_t
ValidateEndSessionRequestMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _END_SESSION_REQUEST_MESSAGE_SPDMVersion
        of type _END_SESSION_REQUEST_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        END_SESSION_REQUEST_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateEndSessionRequestMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _END_SESSION_REQUEST_MESSAGE_Param1
        of type _END_SESSION_REQUEST_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, END_SESSION_REQUEST_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateEndSessionRequestMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _END_SESSION_REQUEST_MESSAGE_Param2
        of type _END_SESSION_REQUEST_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError, StartPosition, END_SESSION_REQUEST_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateEndSessionRequestMessage(InputBuffer Input, uint64_t StartPosition)
{
    /* Field _END_SESSION_REQUEST_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateEndSessionRequestMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        END_SESSION_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0xECU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            END_SESSION_REQUEST_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _END_SESSION_REQUEST_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateEndSessionRequestMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _END_SESSION_REQUEST_MESSAGE_Param2 */
    return ValidateEndSessionRequestMessageParam2(Input, positionAfterParam1);
}

static inline uint64_t
ValidateEndSessionAckResponseMessageSpdmversion(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _END_SESSION_ACK_RESPONSE_MESSAGE_SPDMVersion
        of type _END_SESSION_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field SPDMVersion */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        END_SESSION_ACK_RESPONSE_MESSAGE__SPDMVERSION);
}

static inline uint64_t
ValidateEndSessionAckResponseMessageParam1(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _END_SESSION_ACK_RESPONSE_MESSAGE_Param1
        of type _END_SESSION_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        END_SESSION_ACK_RESPONSE_MESSAGE__PARAM1);
}

static inline uint64_t
ValidateEndSessionAckResponseMessageParam2(
    InputBuffer Input,
    uint64_t StartPosition)
/*++
    Internal helper function:
        Validator for field _END_SESSION_ACK_RESPONSE_MESSAGE_Param2
        of type _END_SESSION_ACK_RESPONSE_MESSAGE
--*/
{
    /* Validating field Param2 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - StartPosition) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = StartPosition + (uint64_t)1U;
    }
    return EverParseMaybeSetErrorCode(
        endPositionOrError,
        StartPosition,
        END_SESSION_ACK_RESPONSE_MESSAGE__PARAM2);
}

uint64_t
SpdmValidateEndSessionAckResponseMessage(
    InputBuffer Input,
    uint64_t StartPosition)
{
    /* Field _END_SESSION_ACK_RESPONSE_MESSAGE_SPDMVersion */
    uint64_t positionAfterSpdmversion =
        ValidateEndSessionAckResponseMessageSpdmversion(Input, StartPosition);
    if (EverParseIsError(positionAfterSpdmversion))
    {
        return positionAfterSpdmversion;
    }
    /* Validating field RequestResponseCode */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    uint64_t endPositionOrError;
    if (((uint64_t)Input.len - positionAfterSpdmversion) < (uint64_t)1U)
    {
        endPositionOrError = EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA;
    }
    else
    {
        endPositionOrError = positionAfterSpdmversion + (uint64_t)1U;
    }
    uint64_t positionAfterRequestResponseCode = EverParseMaybeSetErrorCode(
        endPositionOrError,
        positionAfterSpdmversion,
        END_SESSION_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionAfterRequestResponseCode))
    {
        return positionAfterRequestResponseCode;
    }
    uint8_t requestResponseCode =
        Input.base[(uint32_t)positionAfterSpdmversion];
    BOOLEAN requestResponseCodeConstraintIsOk =
        requestResponseCode == (uint8_t)0x6CU;
    uint64_t positionOrErrorAfterRequestResponseCode =
        EverParseCheckConstraintOkWithFieldId(
            requestResponseCodeConstraintIsOk,
            positionAfterSpdmversion,
            positionAfterRequestResponseCode,
            END_SESSION_ACK_RESPONSE_MESSAGE__REQUESTRESPONSECODE);
    if (EverParseIsError(positionOrErrorAfterRequestResponseCode))
    {
        return positionOrErrorAfterRequestResponseCode;
    }
    /* Field _END_SESSION_ACK_RESPONSE_MESSAGE_Param1 */
    uint64_t positionAfterParam1 = ValidateEndSessionAckResponseMessageParam1(
        Input, positionOrErrorAfterRequestResponseCode);
    if (EverParseIsError(positionAfterParam1))
    {
        return positionAfterParam1;
    }
    /* Field _END_SESSION_ACK_RESPONSE_MESSAGE_Param2 */
    return ValidateEndSessionAckResponseMessageParam2(
        Input, positionAfterParam1);
}
