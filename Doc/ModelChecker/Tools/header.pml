// function code
#define GET_DIGESTS 129//0x81
#define GET_CERTIFICATE 130//0x82
#define CHALLENGE 131//0x83
#define GET_VERSION 132//0x84
#define GET_MEASUREMENTS 224//0xE0
#define GET_CAPABILITIES 225//0xE1
#define NEGOTIATE_ALGORITHMS 227//0xE3
#define KEY_EXCHANGE 228//0xE4
#define FINISH 229//0xE5
#define PSK_EXCHANGE 230//0xE6
#define PSK_FINISH 231//0xE7
#define HEARTBEAT 232//0xE8
#define KEY_UPDATE 233//0xE9
#define GET_ENCAPSULATED_REQUEST 234//0xEA
#define DELIVER_ENCAPSULATED_RESPONSE 235//0xEB
#define END_SESSION 236//0xEC
#define RESPOND_IF_READY 255//0xFF
#define VENDOR_DEFINED_REQUEST 254//0xFE
#define DIGESTS 1//0x01
#define CERTIFICATE 2//0x02
#define CHALLENGE_AUTH 3//0x03
#define VERSION 4//0x04
#define MEASUREMENTS 96//0x60
#define CAPABILITIES 97//0x61
#define ALGORITHMS 99//0x63
#define KEY_EXCHANGE_RSP 100//0x64
#define FINISH_RSP 101//0x65
#define PSK_EXCHANGE_RSP 102//0x66
#define PSK_FINISH_RSP 103//0x67
#define HEARTBEAT_ACK 104//0x68
#define KEY_UPDATE_ACK 105//0x69
#define ENCAPSULATED_REQUEST 106//0x6A
#define ENCAPSULATED_RESPONSE_ACK 107//0x6B
#define END_SESSION_ACK 108//0x6C
#define VENDOR_DEFINED_RESPONSE 126//0x7E
#define ERROR 127//0x7F

#define channelType 1

#define ResponseNotReady 66 //0x42
#define InvalidSessionID 2 // 0x02
#define RequestInFlight 8 //0x08

#define UpdateKey 1
#define UpdateAllKeys 2
#define VerifyNewKey 3

#define MAX_LENGTH 100


typedef requester_cache {
    byte version;
    byte capabilities;
    byte algorithms;
    byte digests;
    byte certificate;
    byte challenge_auth;
    byte measurements;
    byte vendor_defined_response;
    byte key_exchange_rsp;
    byte finish_rsp;
    byte psk_exchange_rsp;
    byte psk_finish_rsp;
    byte heartbeat_ack;
    byte key_update_ack;
    byte encapsulated_request;
    byte encapsulated_response_ack;
    byte end_session_ack;
    byte version_match;
    byte capabilities_match;
    byte algorithms_match;
    byte digests_match;
    byte certificate_match;
    byte challenge_auth_match;
    byte measurements_match;
    byte vendor_defined_response_match;
    byte key_exchange_rsp_match;
    byte finish_rsp_match;
    byte psk_exchange_rsp_match;
    byte psk_finish_rsp_match;
    byte heartbeat_ack_match;
    byte key_update_ack_match;
    byte encapsulated_request_match;
    byte encapsulated_response_ack_match;
    byte end_session_ack_match;

}

typedef responder_cache {
    byte version;
    byte capabilities;
    byte algorithms;
    byte error;
    byte digests;
    byte certificate;
    byte challenge_auth;
    byte measurements;
    byte vendor_defined_response;
    byte key_exchange_rsp;
    byte finish_rsp;
    byte psk_exchange_rsp;
    byte psk_finish_rsp;
    byte heartbeat_ack;
    byte key_update_ack;
    byte encapsulated_request;
    byte encapsulated_response_ack;
    byte end_session_ack;
}

byte cur_phase=0;
chan spdm1Que = [2] of { byte, byte, byte, byte, byte, byte };
chan spdm1Spd = [2] of { byte, byte, byte, byte, byte, byte };
// channelType, variable length payload, Param2, Param1, function code, major|minor version

requester_cache Requester_Cache;
responder_cache Responder_Cache;

bit global_error;
byte if_error=0;

byte response_toEncapRsp=0;

byte version_match=0;
byte capabilities_match=0;
byte algorithms_match=0;
byte digests_match=0;
byte certificate_match=0;
byte challenge_auth_match=0;
byte measurements_match=0;
byte vendor_defined_response_match=0;
byte key_exchange_rsp_match=0;
byte finish_rsp_match=0;
byte psk_exchange_rsp_match=0;
byte psk_finish_rsp_match=0;
byte heartbeat_ack_match=0;
byte key_update_ack_match=0;
byte encapsulated_request_match=0;
byte encapsulated_response_ack_match=0;
byte end_session_ack_match=0;

byte signal;
byte signal2;
byte param1;
byte param2;
byte payload=0;

byte response_signal;
byte response_signal2;
byte response_param1;
byte response_param2;
byte response_payload=0;

byte RESPOND_IF_READY_response_code;
byte ERROR_response_code;

byte support_measurements=0;

byte MEAS_FRESH_CAP=0;
byte MEAS_CAP=1;

byte PSK_CAP=2;
