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

#define MAX_LENGTH 78//100//140
#define REQUE_ARR_COUNT 4

#define H 8//2//4//64//4//8// 64 seems to be too large, change to smaller one //64 // referenced from SHA3-512

typedef chain {
    byte Length[2]; //16 //21
    byte Reserved[2];
    byte RootHash[H];
    byte Certificates[21];//2];//21];//8];//21];//8];//16];//21];//Length]; // To avoid initiation problem
}


typedef requester_cache {
    byte version[10];
    byte capabilities[4];
    byte diffendpoint_capabilities[4];
    byte algorithms[MAX_LENGTH];
    byte diffendpoint_algorithms[MAX_LENGTH];
    byte digests;
    byte certificate;
    chain certificate_chain[8];
    chain diffendpoint_certificate_chain[8];
    chain diffendpoint_certificate_chain_buffer[8];
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
    byte version[10];
    byte capabilities[4];
    byte diffendpoint_capabilities[4];
    byte algorithms[MAX_LENGTH];
    byte diffendpoint_algorithms[MAX_LENGTH];
    byte error;
    byte digests;
    byte certificate;
    chain certificate_chain[8];
    chain diffendpoint_certificate_chain[8];
    chain diffendpoint_certificate_chain_buffer[8];
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

typedef payload_message {                                                           
    byte payload_content[MAX_LENGTH];                                                       
}  

byte cur_phase=0;
chan spdm1Que = [2] of { byte, payload_message, byte, byte, byte, byte };
chan spdm1Spd = [2] of { byte, payload_message, byte, byte, byte, byte };
// channelType, variable length payload, Param2, Param1, function code, major|minor version
// channelType, major|minor version, function code, Param1, Param2, variable length payload
// currently only the GET_VERSION payload byte-ordering is msb, others are lsb

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
payload_message payload;
// byte payload[MAX_LENGTH]=0;

byte response_signal;
byte response_signal2;
byte response_param1;
byte response_param2;
payload_message response_payload;
// byte response_payload[MAX_LENGTH]=0;

byte RESPOND_IF_READY_response_code;
byte ERROR_response_code;

byte support_measurements=0;

byte MEAS_FRESH_CAP=0;
byte MEAS_CAP=0;

byte PSK_CAP=2;
bit CERT_CAP=0;
bit CHAL_CAP=0;

int global_length_num=0;
int global_length_num_2=0;                                                              
// By default this number is 4. Will be larger if the message has payload.          
// This length is for model-only use to define the message length to solve the one-size channel problem 

byte MeasurementSpecificationSel=0;
short BaseAsymSel=0;
short BaseHashSel=0;

byte pre_portionlength=0;

#define M_length 600//8//10 // 60 // 100 // 400 //600
#define range_length 50//3//5 // 15 // 20 // 35 // 50
int challenge_M1[M_length];
int challenge_M2[M_length];
int challenge_range_1[range_length];
int challenge_range_2[range_length];
// byte length_reference[20]={4, 26, 12, 11, 72, 64, 4, 36, 8, 18, 8, 18, 8, 9, 36, 50}
byte length_reference[20]={4, 26, 12, 11, 72, 64, 4, 36, 8, 10, 8, 10, 8, 10, 36, 50}

byte ResponseNotReady_length=4;

byte max_version=0;

bit new_received_flag=0;

proctype Party2_Responder(chan Que, Spd)
{
    int i=0,j=0;
    byte portionlength, reminderlength;
    payload_message buffered_payload_message;
    byte buffered_param1=0;
    byte first_certificate_flag=0;
    // for RespondNotReady
    byte RFTExponent=10;
    byte RequestCode;
    byte Token=10;//Randomly set TODO
    byte RDTM=10;// Randomly set TODO
    payload_message ResponseNotReady_payload;
    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-1]=RFTExponent;
    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-2]=RequestCode;
    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-3]=Token;
    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-4]=RDTM;
START:   
    response_signal=0;
    new_received_flag=1;
    if
    :: 1==0 ->
        { printf("to nego in responder\n"); /*goto NEGOTIATE_ALGORITHMS_2;*/}
    :: else ->
    atomic{
        printf("to wait for reque\n");// goto START;} 
        Que?channelType(response_payload, response_param2, response_param1, response_signal, response_signal2);
        if 
        :: skip->global_error=0;
        // :: skip->global_error=1;
        :: response_signal==GET_VERSION || (response_signal==RESPOND_IF_READY && response_param1==GET_VERSION) || \
        response_signal==GET_CAPABILITIES || (response_signal==RESPOND_IF_READY && response_param1==GET_CAPABILITIES) || \
         response_signal==NEGOTIATE_ALGORITHMS || (response_signal==RESPOND_IF_READY && response_param1==NEGOTIATE_ALGORITHMS) || \
         response_signal==GET_DIGESTS || (response_signal==RESPOND_IF_READY && response_param1==GET_DIGESTS) //|| \
        // response_signal==GET_CERTIFICATE || (response_signal==RESPOND_IF_READY && response_param1==GET_CERTIFICATE) 
         ->global_error=1;
        fi
        printf("Enter Responder\n");
        if 
        :: response_signal==GET_MEASUREMENTS -> { printf("to get measurements\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto MEASUREMENTS_2};
        :: response_signal==RESPOND_IF_READY && response_param1==GET_MEASUREMENTS -> { printf("to get measurements after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto MEASUREMENTS_2};
        :: response_signal==CHALLENGE -> { printf("to get challenge_auth\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto CHALLENGE_AUTH_2};
        :: response_signal==RESPOND_IF_READY && response_param1==CHALLENGE -> { printf("to get challenge_auth after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto CHALLENGE_AUTH_2};
        :: response_signal==GET_CERTIFICATE -> { printf("to get certificate\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto CERTIFICATE_2};
        :: response_signal==RESPOND_IF_READY && response_param1==GET_CERTIFICATE -> { printf("to get certificate after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto CERTIFICATE_2};
        :: response_signal==GET_DIGESTS -> { printf("to get digests\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto DIGESTS_2};
        :: response_signal==RESPOND_IF_READY && response_param1==GET_DIGESTS -> { printf("to get digests after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto DIGESTS_2};
        :: response_signal==NEGOTIATE_ALGORITHMS -> { printf("to get algorithms\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto ALGORITHMS_2};
        :: response_signal==RESPOND_IF_READY && response_param1==NEGOTIATE_ALGORITHMS -> { printf("to get algorithms after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto ALGORITHMS_2};
        :: response_signal==GET_CAPABILITIES -> { printf("to get capabilities\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto CAPABILITIES_2};
        :: response_signal==RESPOND_IF_READY && response_param1==GET_CAPABILITIES -> { printf("to get capabilities after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto CAPABILITIES_2};
        :: response_signal==GET_VERSION -> { printf("to get version\n"); printf("1 response_signal=%d, global_error=%d\n",response_signal, global_error);goto VERSION_2};
        :: response_signal==RESPOND_IF_READY && response_param1==GET_VERSION -> { printf("to get version after error\n"); printf("2 response_signal=%d, global_error=%d\n",response_signal, global_error); goto VERSION_2};
        :: else -> { printf("will go to somewhere else\n"); }
        fi
    }
    fi
    new_received_flag=0;
VERSION_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
//    Responder_Cache.verson[10]={6, 13, 11};
//    byte respo_version_arr[10]={6, 13, 11};
    atomic{
        version_match=0;
        capabilities_match=0;
        algorithms_match=0;
        digests_match=0;
        certificate_match=0;
        challenge_auth_match=0;
        measurements_match=0;
        vendor_defined_response_match=0;
        key_exchange_rsp_match=0;
        finish_rsp_match=0;
        psk_exchange_rsp_match=0;
        psk_finish_rsp_match=0;
        heartbeat_ack_match=0;
        key_update_ack_match=0;
        encapsulated_request_match=0;
        encapsulated_response_ack_match=0;
        end_session_ack_match=0;
        Requester_Cache.version_match=0;
        Requester_Cache.capabilities_match=0;
        Requester_Cache.algorithms_match=0;
        Requester_Cache.digests_match=0;
        Requester_Cache.certificate_match=0;
        Requester_Cache.challenge_auth_match=0;
        Requester_Cache.measurements_match=0;
        Requester_Cache.vendor_defined_response_match=0;
        Requester_Cache.key_exchange_rsp_match=0;
        Requester_Cache.finish_rsp_match=0;
        Requester_Cache.psk_exchange_rsp_match=0;
        Requester_Cache.psk_finish_rsp_match=0;
        Requester_Cache.heartbeat_ack_match=0;
        Requester_Cache.key_update_ack_match=0;
        Requester_Cache.encapsulated_request_match=0;
        Requester_Cache.encapsulated_response_ack_match=0;
        Requester_Cache.end_session_ack_match=0;

        payload_message prepared_payload;
        prepared_payload.payload_content[1]=1; // count_number is 1
        prepared_payload.payload_content[2]=32;//0b0010000000000000 correspond to version 2
        prepared_payload.payload_content[3]=0;//0b0010000000000000 correspond to version 2//8192

        if
        :: (response_signal==GET_VERSION || (response_signal==RESPOND_IF_READY && response_param1==GET_VERSION)) && global_error!=1-> 
            atomic {
                    prepared_payload.payload_content[1]= 3; // count_number is 3
                    prepared_payload.payload_content[2]= 96;//0b0110000000000000 correspond to version 6//24576
                    prepared_payload.payload_content[3]= 0;//0b0110000000000000 correspond to version 6//24576
                    prepared_payload.payload_content[4]= 208;//0b1101000000000000 correspond to version 13//53248
                    prepared_payload.payload_content[5]= 0;//0b1101000000000000 correspond to version 13//53248
                    prepared_payload.payload_content[6]= 176;//0b1011000000000000 correspond to version 11//45056
                    prepared_payload.payload_content[7]= 0;//0b1011000000000000 correspond to version 11//45056
                    //prepared_payload.payload_content[5]= 4096;// 0b0001000000000000 correspond to version 2
                    Spd!channelType(prepared_payload, 0, 0, VERSION, response_signal2);
                    // prepare challenge M1
                    // for (i : 0 .. M_length-1){
                    //     challenge_M1[i]=0
                    // }
                    // for (i: 0 .. range_length-1){
                    //     challenge_range_1[i]=0
                    // }
                    // global_length_num=0;
                    challenge_M1[0]=response_signal2; challenge_M1[1]=response_signal; challenge_M1[2]=response_param1; challenge_M1[3]=response_param2;
                    challenge_range_1[(global_length_num)%range_length]=length_reference[0]
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=VERSION; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=0; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: length_reference[0]+4 .. length_reference[0]+4+length_reference[1]-1){
                        challenge_M1[(i)%M_length]=prepared_payload.payload_content[(i-length_reference[0]-4)]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[1]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   //ERROR 1 // respondIfReady 2
                   assert(global_error==0);
            }
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=VERSION;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("VERSION error\n");
        fi
        goto START;
    }
CAPABILITIES_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
    // start to prepare GET_CAPABILITIES
    payload_message prepared_payload;
    for (i : 0 .. MAX_LENGTH-1){
        prepared_payload.payload_content[i]=0
    }
    prepared_payload.payload_content[MAX_LENGTH-1-1]=0 // Reserved
    prepared_payload.payload_content[MAX_LENGTH-1-2]=10 // CTExponent
    prepared_payload.payload_content[MAX_LENGTH-1-3]=0 // Reserved
    prepared_payload.payload_content[MAX_LENGTH-1-4]=Responder_Cache.capabilities[3] // flag LSB byte
    prepared_payload.payload_content[MAX_LENGTH-1-5]=Responder_Cache.capabilities[2] // flag 
    prepared_payload.payload_content[MAX_LENGTH-1-6]=Responder_Cache.capabilities[1] // flag 
    prepared_payload.payload_content[MAX_LENGTH-1-7]=Responder_Cache.capabilities[0] // flag
    Responder_Cache.diffendpoint_capabilities[3]=response_payload.payload_content[MAX_LENGTH-1-4]
    Responder_Cache.diffendpoint_capabilities[2]=response_payload.payload_content[MAX_LENGTH-1-5]
    Responder_Cache.diffendpoint_capabilities[1]=response_payload.payload_content[MAX_LENGTH-1-6]
    Responder_Cache.diffendpoint_capabilities[0]=response_payload.payload_content[MAX_LENGTH-1-7]
    atomic{
        if
        :: (response_signal==GET_CAPABILITIES || (response_signal==RESPOND_IF_READY && response_param1==GET_CAPABILITIES)) && global_error!=1-> 
            atomic{
                    Spd!channelType(prepared_payload, 0, 0, CAPABILITIES, response_signal2);
                    // prepare challenge M1
                    printf("global_length_num-1=%d in capabilities\n",(global_length_num-1)%range_length)
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    for (i: 0 .. length_reference[2]-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=response_payload.payload_content[MAX_LENGTH-(length_reference[2]-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[2]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;


                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=CAPABILITIES; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=0; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. length_reference[3]-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=prepared_payload.payload_content[MAX_LENGTH-(length_reference[3]-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[3]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   //ERROR 1 // respondIfReady 2
                   assert(global_error==0);}
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=CAPABILITIES;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("CAPABILITIES error\n");
        fi
        goto START;
    }
ALGORITHMS_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
    // start to prepare negotiate algorithms
    // now by default to support all or support the first one if only one is selected
    payload_message algorithms_payload;
    for (i : 0 .. MAX_LENGTH-1){// algorithms_payload.payload_content[MAX_LENGTH-1]-4-1){
        // Responder_Cache.algorithms[i]=algorithms_payload.payload_content[i]
        algorithms_payload.payload_content[i]=Responder_Cache.algorithms[i]
        // Responder_Cache.diffendpoint_algorithms[i]=response_payload.payload_content[i]
    } 
    // Responder_Cache.algorithms[MAX_LENGTH-1-64]=1// ExtAsym LSB // TCG
    // Responder_Cache.algorithms[MAX_LENGTH-1-65]=0// ExtAsym //Reserved
    // Responder_Cache.algorithms[MAX_LENGTH-1-66]=0// ExtAsym //algorithm ID TODO
    // Responder_Cache.algorithms[MAX_LENGTH-1-67]=0// ExtAsym
    // Responder_Cache.algorithms[MAX_LENGTH-1-68]=1// ExtHash LSB // TCG
    // Responder_Cache.algorithms[MAX_LENGTH-1-69]=0// ExtHash
    // Responder_Cache.algorithms[MAX_LENGTH-1-70]=0// ExtHash
    // Responder_Cache.algorithms[MAX_LENGTH-1-71]=0// ExtHash
    
    atomic{
        if
        :: (response_signal==NEGOTIATE_ALGORITHMS || (response_signal==RESPOND_IF_READY && response_param1==NEGOTIATE_ALGORITHMS)) && global_error!=1-> 
            atomic{
                    for (i : 0 .. MAX_LENGTH-1){// algorithms_payload.payload_content[MAX_LENGTH-1]-4-1){
                        Responder_Cache.diffendpoint_algorithms[i]=response_payload.payload_content[i]
                    } 
                    Spd!channelType(algorithms_payload, 0, 4, ALGORITHMS, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    for (i: 0 .. length_reference[4]-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=response_payload.payload_content[MAX_LENGTH-(length_reference[4]-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[4]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=ALGORITHMS; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=4; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. length_reference[5]-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=algorithms_payload.payload_content[MAX_LENGTH-(length_reference[5]-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[5]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   //ERROR 1 // respondIfReady 2
                   assert(global_error==0);}
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=ALGORITHMS;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("ALGORITHMS error\n");
        fi
        goto START;
    }
DIGESTS_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
   first_certificate_flag=0;
    atomic{
        if
        :: (response_signal==GET_DIGESTS || (response_signal==RESPOND_IF_READY && response_param1==GET_DIGESTS)) && global_error!=1-> 
            atomic{
                payload_message algorithms_payload_digest;
                byte Param2_local=3; //3 is because 0b00000011
                byte num=Param2_local&1 + Param2_local&2 + Param2_local&4 + Param2_local&8 + Param2_local&16 + Param2_local&32 + Param2_local&64 + Param2_local&128;
                for (i : 0 .. num-1){
                    for (j : 0 .. H-1){
                        algorithms_payload_digest.payload_content[MAX_LENGTH-(i+1)*H+j]=Responder_Cache.certificate_chain[i].RootHash[j]
                    }
                }
                Spd!channelType(algorithms_payload_digest, Param2_local, 0, DIGESTS, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    challenge_range_1[(global_length_num)%range_length]=length_reference[6]+challenge_range_1[(global_length_num-1)%range_length] // length_reference[6]=respondifready length=4
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=DIGESTS; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=0; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=Param2_local;
                    for (i: 0 .. length_reference[7]-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=algorithms_payload_digest.payload_content[MAX_LENGTH-(length_reference[7]-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[7]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   //ERROR 1 // respondIfReady 2
                   assert(global_error==0);}
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=DIGESTS;
                   //ERROR 1
                   assert(global_error==1);}
        :: global_error==1 ->
            atomic{ 
                    // byte RFTExponent=10;
                    RequestCode=GET_DIGESTS;
                    // byte Token=10;//Randomly set TODO
                    // byte RDTM=10;// Randomly set TODO
                    // byte ResponseNotReady_length=4;
                    // payload_message ResponseNotReady_payload;
                    // ResponseNotReady_payload.payload_content[MAX_LENGTH-1-1]=RFTExponent;
                    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-2]=RequestCode;
                    // ResponseNotReady_payload.payload_content[MAX_LENGTH-1-3]=Token;
                    // ResponseNotReady_payload.payload_content[MAX_LENGTH-1-4]=RDTM;
                    Spd!channelType(ResponseNotReady_payload, 0, ResponseNotReady, ERROR, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    challenge_range_1[(global_length_num)%range_length]=length_reference[6]+challenge_range_1[(global_length_num-1)%range_length]
                    // global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=ERROR; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=ResponseNotReady; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. ResponseNotReady_length-1){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=ResponseNotReady_payload.payload_content[MAX_LENGTH-(ResponseNotReady_length-1-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=ResponseNotReady_length+4+challenge_range_1[(global_length_num-1)%range_length]
                    // global_length_num++;
                   RESPOND_IF_READY_response_code=DIGESTS;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("DIGESTS error\n");
        fi
        goto START;
    }
CERTIFICATE_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
    atomic{
        byte send_buffer_size=10; // randomly set a number less than 21
        if
        ::(first_certificate_flag==0 && (response_signal==GET_CERTIFICATE || (response_signal==RESPOND_IF_READY && response_param1==GET_CERTIFICATE)) && global_error!=1)->
            atomic{
                for (i : 0 .. MAX_LENGTH-1){
                   buffered_payload_message.payload_content[i]=response_payload.payload_content[i]
                }
                buffered_param1=response_param1;
                first_certificate_flag=1;
                pre_portionlength=0;
                printf("Sampling certificate requests\n")
            }
        :: else -> skip;
        fi  
        byte certificate_length1=0;
        byte certificate_length2=0;   
        if
        :: (response_signal==GET_CERTIFICATE) && global_error!=1-> 
            atomic{
                    // update buffered data
                    for (i : 0 .. MAX_LENGTH-1){
                        buffered_payload_message.payload_content[i]=response_payload.payload_content[i]
                    }
                    buffered_param1=response_param1;
                    payload_message certificate_payload;
                    if
                    :: send_buffer_size>response_payload.payload_content[MAX_LENGTH-4]*256+response_payload.payload_content[MAX_LENGTH-3]->
                        portionlength=response_payload.payload_content[MAX_LENGTH-4]*256+response_payload.payload_content[MAX_LENGTH-3];
                        reminderlength=0;
                        certificate_length1=length_reference[12]
                        certificate_length2=length_reference[13]
                    :: else ->
                        portionlength=send_buffer_size;
                        reminderlength=response_payload.payload_content[MAX_LENGTH-4]*256+response_payload.payload_content[MAX_LENGTH-3]-send_buffer_size;
                        certificate_length1=length_reference[8]
                        certificate_length2=length_reference[9]
                    fi
                    certificate_payload.payload_content[MAX_LENGTH-2]=portionlength>>8;
                    certificate_payload.payload_content[MAX_LENGTH-1]=portionlength&255;
                    certificate_payload.payload_content[MAX_LENGTH-4]=reminderlength>>8;
                    certificate_payload.payload_content[MAX_LENGTH-3]=reminderlength&255;
                    printf("reminderlength=%d, portionlength=%d, size=%d, buffered_param1=%d, pre_portionlength=%d\n", reminderlength, portionlength, response_payload.payload_content[MAX_LENGTH-4]*256+response_payload.payload_content[MAX_LENGTH-3], buffered_param1, pre_portionlength)
                    // printf("1 is %d, 2 is %d\n", )
                    if 
                    :: portionlength==1 ->
                        certificate_payload.payload_content[MAX_LENGTH-5-reminderlength]=Responder_Cache.certificate_chain[buffered_param1].Certificates[pre_portionlength-1]
                    :: portionlength>1 ->
                        for (i : portionlength-1 .. 0){
                            certificate_payload.payload_content[MAX_LENGTH-5-i-reminderlength]=Responder_Cache.certificate_chain[buffered_param1].Certificates[pre_portionlength+portionlength-1-i]
                        }
                    :: else -> {printf("portionlength error\n"); assert(0)}
                    fi
                    Spd!channelType(certificate_payload, 0, buffered_param1, CERTIFICATE, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    for (i: 0 .. certificate_length1-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=response_payload.payload_content[MAX_LENGTH-(certificate_length1-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=certificate_length1+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=CERTIFICATE; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=buffered_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. certificate_length2-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=certificate_payload.payload_content[MAX_LENGTH-(certificate_length2-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=certificate_length2+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   //ERROR 1 // respondIfReady 2
                   pre_portionlength=pre_portionlength+portionlength
                   assert(global_error==0);}
        :: (/*response_signal==GET_CERTIFICATE||*/(response_signal==RESPOND_IF_READY && response_param1==GET_CERTIFICATE)) && global_error!=1-> 
            atomic{
                    payload_message certificate_payload;
                    if
                    :: send_buffer_size>buffered_payload_message.payload_content[MAX_LENGTH-4]*256+buffered_payload_message.payload_content[MAX_LENGTH-3]->
                        portionlength=buffered_payload_message.payload_content[MAX_LENGTH-4]*256+buffered_payload_message.payload_content[MAX_LENGTH-3];
                        reminderlength=0;
                        certificate_length1=length_reference[12]
                        certificate_length2=length_reference[13]
                    :: else ->
                        portionlength=send_buffer_size;
                        reminderlength=buffered_payload_message.payload_content[MAX_LENGTH-4]*256+buffered_payload_message.payload_content[MAX_LENGTH-3]-send_buffer_size;
                        certificate_length1=length_reference[8]
                        certificate_length2=length_reference[9]
                    fi
                    certificate_payload.payload_content[MAX_LENGTH-2]=portionlength>>8;
                    certificate_payload.payload_content[MAX_LENGTH-1]=portionlength&255;
                    certificate_payload.payload_content[MAX_LENGTH-4]=reminderlength>>8;
                    certificate_payload.payload_content[MAX_LENGTH-3]=reminderlength&255;
                    printf("RDRe: portionlength=%d, size=%d, buffered_param1=%d, pre_portionlength=%d\n", portionlength, buffered_payload_message.payload_content[MAX_LENGTH-4]*256+buffered_payload_message.payload_content[MAX_LENGTH-3], buffered_param1, pre_portionlength)
                    if 
                    :: portionlength==1 ->
                        certificate_payload.payload_content[MAX_LENGTH-5-reminderlength]=Responder_Cache.certificate_chain[buffered_param1].Certificates[pre_portionlength-1]
                    :: portionlength>1 ->
                        for (i : portionlength-1 .. 0){
                            certificate_payload.payload_content[MAX_LENGTH-5-i-reminderlength]=Responder_Cache.certificate_chain[buffered_param1].Certificates[pre_portionlength+portionlength-1-i]
                        }
                    fi
                    Spd!channelType(certificate_payload, 0, buffered_param1, CERTIFICATE, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2; // TODO: should categorize non respondIfReady or respondIfReady
                    // for (i: 0 .. certificate_length1-1-4){
                    //     challenge_M1[challenge_range_1[(global_length_num-1)%range_length]+4+i]=buffered_payload_message[MAX_LENGTH-(certificate_length1-1-4-i)-1]
                    // }
                    challenge_range_1[(global_length_num)%range_length]=/*certificate_length1*/4+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=CERTIFICATE; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=buffered_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. certificate_length2-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=certificate_payload.payload_content[MAX_LENGTH-(certificate_length2-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=certificate_length2+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   //ERROR 1 // respondIfReady 2
                   pre_portionlength=pre_portionlength+portionlength
                   assert(global_error==0);}
        :: global_error==1 ->
            atomic{ if
                    :: (response_signal==GET_CERTIFICATE)-> 
                    for (i : 0 .. MAX_LENGTH-1){
                        buffered_payload_message.payload_content[i]=response_payload.payload_content[i]
                    }
                    buffered_param1=response_param1;
                    :: else -> skip
                    fi
                    Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=CERTIFICATE;
                   //ERROR 1
                   assert(global_error==1);}
        :: global_error==1 ->
            atomic{ if
                    :: (response_signal==GET_CERTIFICATE)-> 
                    for (i : 0 .. MAX_LENGTH-1){
                        buffered_payload_message.payload_content[i]=response_payload.payload_content[i]
                    }
                    buffered_param1=response_param1;
                    :: else -> skip
                    fi
                    if
                    :: send_buffer_size>response_payload.payload_content[MAX_LENGTH-4]*256+response_payload.payload_content[MAX_LENGTH-3]->
                        certificate_length1=length_reference[12]
                        certificate_length2=length_reference[13]
                    :: else ->
                        certificate_length1=length_reference[8]
                        certificate_length2=length_reference[9]
                    fi
                    // prepare challenge M1
                    RequestCode=GET_CERTIFICATE;
                    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-2]=RequestCode;
                    Spd!channelType(ResponseNotReady_payload, 0, ResponseNotReady, ERROR, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    // for (i: 0 .. length_reference[8]-1-4){
                    //     challenge_M1[challenge_range_1[(global_length_num-1)%range_length]+4+i]=response_payload.payload_content[MAX_LENGTH-(length_reference[8]-1-4-i)-1]
                    // }
                    // challenge_range_1[(global_length_num)%range_length]=length_reference[8]+challenge_range_1[(global_length_num-1)%range_length]
                    // global_length_num++;
                    if 
                    :: response_signal!=RESPOND_IF_READY->{
                        for (i: 0 .. certificate_length1-1-4){
                            challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=response_payload.payload_content[MAX_LENGTH-(certificate_length1-1-4-i)-1]
                        }
                        challenge_range_1[(global_length_num)%range_length]=certificate_length1+challenge_range_1[(global_length_num-1)%range_length]
                        printf("1 Send %d for length and now the total length is %d, before is %d\n", length_reference[8], challenge_range_1[(global_length_num)%range_length], challenge_range_1[(global_length_num-1)%range_length])
                    }
                    :: else ->{challenge_range_1[(global_length_num)%range_length]=4+challenge_range_1[(global_length_num-1)%range_length]; printf("2 Send 4 for length and now the total length is %d, before is %d\n", challenge_range_1[(global_length_num)%range_length], challenge_range_1[(global_length_num-1)%range_length])}
                    fi  
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=ERROR; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=ResponseNotReady; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. ResponseNotReady_length-1){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=ResponseNotReady_payload.payload_content[MAX_LENGTH-(ResponseNotReady_length-1-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=ResponseNotReady_length+4+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   RESPOND_IF_READY_response_code=CERTIFICATE;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("CERTIFICATE error\n");
            assert(0);
        fi
        goto START;
    }
CHALLENGE_AUTH_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
    atomic{
        first_certificate_flag=0;
        if
        :: (response_signal==CHALLENGE || (response_signal==RESPOND_IF_READY && response_param1==CHALLENGE)) && global_error!=1-> 
            atomic{
                    byte BasicMutAuthReq = 0 // currently not support mutual anthentatication until ENCAPSULATED request
                    byte param1_local = BasicMutAuthReq*128+response_param1&15
                    byte param2_local = 0
                    if
                    :: buffered_param1==1 -> param2_local=2
                    :: buffered_param1==0 -> param2_local=1
                    :: else-> printf("Wrong in response_param1 for now\n"); assert(0)
                    fi
                    payload_message payload_challenge_auth;
                    byte challenge_auth_nr;
                    for (i : 0 .. H+32+H-1){
                        payload_challenge_auth.payload_content[MAX_LENGTH-1-i]=challenge_auth_nr;
                        challenge_auth_nr++ // CertChainHash, Nonce, MeasurementSummaryHash
                    }
                    // OpaqueLength assmue length is 4 because of the scalability
                    payload_challenge_auth.payload_content[MAX_LENGTH-1-(H+32+H)]=4
                    for (i : 0 .. payload_challenge_auth.payload_content[MAX_LENGTH-1-(H+32+H)]-1){
                        payload_challenge_auth.payload_content[MAX_LENGTH-1-(H+32+H)-1-i]=challenge_auth_nr;
                        challenge_auth_nr++ // CertChainHash, Nonce, MeasurementSummaryHash
                    }
                    // Signature //S // TODO
                    // payload_challenge_auth[MAX_LENGTH-1-(H+32+H)-5]
                    // for (i : 0 .. challenge_range_1[global_length_num]-1){
                    //     payload_challenge_auth[MAX_LENGTH-1-(H+32+H)-1-5-i]=challenge_range_1[i];
                    // }
                    // cannot send by channel because of the very side length, set as global variables
                    Spd!channelType(payload_challenge_auth, param2_local, param1_local, CHALLENGE_AUTH, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    if 
                    :: response_signal!=RESPOND_IF_READY->{
                        for (i: 0 .. length_reference[14]-1-4){
                            challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=response_payload.payload_content[MAX_LENGTH-(length_reference[14]-1-4-i)-1]
                        }
                        challenge_range_1[(global_length_num)%range_length]=length_reference[14]+challenge_range_1[(global_length_num-1)%range_length]
                        printf("1 Send %d for length and now the total length is %d, before is %d\n", length_reference[14], challenge_range_1[(global_length_num)%range_length], challenge_range_1[(global_length_num-1)%range_length])
                    }
                    :: else ->{challenge_range_1[(global_length_num)%range_length]=4+challenge_range_1[(global_length_num-1)%range_length]; printf("2 Send 4 for length and now the total length is %d, before is %d\n", challenge_range_1[(global_length_num)%range_length], challenge_range_1[(global_length_num-1)%range_length])}
                    fi       
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=CHALLENGE_AUTH; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=param1_local; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=param2_local;
                    for (i: 0 .. length_reference[15]-1-4){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=payload_challenge_auth.payload_content[MAX_LENGTH-(length_reference[15]-1-4-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=length_reference[15]+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                    // for (i : 0 .. challenge_range_1[(global_length_num-1)%range_length]-1){
                    //     payload_challenge_auth[MAX_LENGTH-1-(H+32+H)-1-5-i]=challenge_range_1[i];
                    // }
                    // Spd!channelType(payload_challenge_auth, param2_local, param1_local, CHALLENGE_AUTH, response_signal2);
                   //ERROR 1 // respondIfReady 2
                   assert(global_error==0);}
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=CHALLENGE_AUTH;
                   //ERROR 1
                   assert(global_error==1);}
        :: global_error==1 ->
            atomic{// prepare challenge M1
                    RequestCode=GET_CERTIFICATE;
                    ResponseNotReady_payload.payload_content[MAX_LENGTH-1-2]=RequestCode;
                    Spd!channelType(ResponseNotReady_payload, 0, ResponseNotReady, ERROR, response_signal2);
                    // prepare challenge M1
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+0)%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=response_signal; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=response_param1; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=response_param2;
                    if 
                    :: response_signal!=RESPOND_IF_READY->{
                        for (i: 0 .. length_reference[14]-1-4){
                            challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=response_payload.payload_content[MAX_LENGTH-(length_reference[14]-1-4-i)-1]
                        }
                        challenge_range_1[(global_length_num)%range_length]=length_reference[14]+challenge_range_1[(global_length_num-1)%range_length]
                        printf("3 Send %d for length and now the total length is %d, before is %d\n", length_reference[14], challenge_range_1[(global_length_num)%range_length], challenge_range_1[(global_length_num-1)%range_length])
                    }
                    :: else ->{challenge_range_1[(global_length_num)%range_length]=4+challenge_range_1[(global_length_num-1)%range_length]; printf("4 Send 4 for length and now the total length is %d, before is %d\n", challenge_range_1[(global_length_num)%range_length], challenge_range_1[(global_length_num-1)%range_length])}
                    fi 
                    global_length_num++;
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length])%M_length]=response_signal2; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+1)%M_length]=ERROR; 
                    challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+2)%M_length]=ResponseNotReady; challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+3)%M_length]=0;
                    for (i: 0 .. ResponseNotReady_length-1){
                        challenge_M1[(challenge_range_1[(global_length_num-1)%range_length]+4+i)%M_length]=ResponseNotReady_payload.payload_content[MAX_LENGTH-(ResponseNotReady_length-1-i)-1]
                    }
                    challenge_range_1[(global_length_num)%range_length]=ResponseNotReady_length+4+challenge_range_1[(global_length_num-1)%range_length]
                    global_length_num++;
                   RESPOND_IF_READY_response_code=CHALLENGE_AUTH;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("CHALLENGE_AUTH error\n");
        fi
        goto START;
    }
MEASUREMENTS_2:
   printf("response_signal=%d, global_error=%d, response_param1=%d\n",response_signal, global_error,response_param1);
    atomic{
        if
        :: (response_signal==GET_MEASUREMENTS || (response_signal==RESPOND_IF_READY && response_param1==GET_MEASUREMENTS)) && global_error!=1-> 
            atomic{Spd!channelType(response_payload, 0, 0, MEASUREMENTS, Responder_Cache.measurements);
                   //ERROR 1 // respondIfReady 2
                   assert(global_error==0);}
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady+1, ERROR, 0);
                   ERROR_response_code=MEASUREMENTS;
                   //ERROR 1
                   assert(global_error==1);}
        :: global_error==1 ->
            atomic{Spd!channelType(response_payload, 0, ResponseNotReady, ERROR, 0);
                   RESPOND_IF_READY_response_code=MEASUREMENTS;
                   //ERROR 1
                   assert(global_error==1);}
        :: else ->
            printf("MEASUREMENTS error\n");
        fi
        goto START;
    }
}
proctype Party1_Requester(chan Que, Spd)
{
    // int REQUE_ARR_COUNT=4;
    // byte reque_version_arr[REQUE_ARR_COUNT]={2, 7, 11, 3};//{8, 7, 10, 2};//{8, 6, 11, 2};
    // Requester_Cache.verson[10]={2, 7, 11, 3};
    payload_message return_payload;
    
    byte diffendpoint_certificate_chain_buffer_index=0;
    payload_message algorithms_payload_certificate;
    byte portionlength, reminderlength;//, pre_portionlength;
    byte param1_in_certificate;
    int i,j;
#define buffer_length 75
    int buffer_challenge_M2[buffer_length];
    int buffer_challenge_range_2;
INI:
    goto GET_VERSION_1;
GET_VERSION_1:
atomic{
    // clear state
    // version_match=0;
    // capabilities_match=0;
    // algorithms_match=0;
    // digests_match=0;
    // certificate_match=0;
    // challenge_auth_match=0;
    // measurements_match=0;
    // vendor_defined_response_match=0;
    // key_exchange_rsp_match=0;
    // finish_rsp_match=0;
    // psk_exchange_rsp_match=0;
    // psk_finish_rsp_match=0;
    // heartbeat_ack_match=0;
    // key_update_ack_match=0;
    // encapsulated_request_match=0;
    // encapsulated_response_ack_match=0;
    // end_session_ack_match=0;
    // Requester_Cache.version_match=0;
    // Requester_Cache.capabilities_match=0;
    // Requester_Cache.algorithms_match=0;
    // Requester_Cache.digests_match=0;
    // Requester_Cache.certificate_match=0;
    // Requester_Cache.challenge_auth_match=0;
    // Requester_Cache.measurements_match=0;
    // Requester_Cache.vendor_defined_response_match=0;
    // Requester_Cache.key_exchange_rsp_match=0;
    // Requester_Cache.finish_rsp_match=0;
    // Requester_Cache.psk_exchange_rsp_match=0;
    // Requester_Cache.psk_finish_rsp_match=0;
    // Requester_Cache.heartbeat_ack_match=0;
    // Requester_Cache.key_update_ack_match=0;
    // Requester_Cache.encapsulated_request_match=0;
    // Requester_Cache.encapsulated_response_ack_match=0;
    // Requester_Cache.end_session_ack_match=0;
    signal=0;

    


    Que!channelType(payload, 0, 0, GET_VERSION, 2);
    // prepare challenge M1
    for (i : 0 .. M_length-1){
        challenge_M1[i]=0
    }
    for (i: 0 .. range_length-1){
        challenge_range_1[i]=0
    }
    global_length_num=0;
    for (i : 0 .. M_length-1){
        challenge_M2[i]=0
    }
    for (i: 0 .. range_length-1){
        challenge_range_2[i]=0
    }
    global_length_num_2=0;
    
    buffer_challenge_M2[0]=2; buffer_challenge_M2[1]=GET_VERSION; 
    buffer_challenge_M2[2]=0; buffer_challenge_M2[3]=0;
    buffer_challenge_range_2=length_reference[0];

    // challenge_M2[challenge_range_2[global_length_num_2]+0]=2; challenge_M2[challenge_range_2[global_length_num_2]+1]=GET_VERSION; 
    // challenge_M2[challenge_range_2[global_length_num_2]+2]=0; challenge_M2[challenge_range_2[global_length_num_2]+3]=0;
    // challenge_range_2[global_length_num_2]=length_reference[0]
    // global_length_num_2++;
                    
   printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error, param1);
    goto GET_CAPABILITIES_1;
}
GET_CAPABILITIES_1:
    Spd?channelType(payload,param2,param1,signal,signal2);
    
    printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error, param1);
    assert(!(signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==CAPABILITIES ))
    byte limit = payload.payload_content[1];
    // start to prepare GET_CAPABILITIES
    for (i: 0 .. MAX_LENGTH-1){
        return_payload.payload_content[i]=0
    }
    return_payload.payload_content[MAX_LENGTH-1-1]=0 // Reserved
    return_payload.payload_content[MAX_LENGTH-1-2]=10 // CTExponent
    return_payload.payload_content[MAX_LENGTH-1-3]=0 // Reserved
    return_payload.payload_content[MAX_LENGTH-1-4]=Requester_Cache.capabilities[3] // flag LSB byte
    return_payload.payload_content[MAX_LENGTH-1-5]=Requester_Cache.capabilities[2] // flag 
    return_payload.payload_content[MAX_LENGTH-1-6]=Requester_Cache.capabilities[1] // flag 
    return_payload.payload_content[MAX_LENGTH-1-7]=Requester_Cache.capabilities[0] // flag
    if 
    :: limit>=1 ->
    atomic {
        for (i : 0 .. REQUE_ARR_COUNT-1){
            for (j : 0 .. limit-1){//VersionNumberEntry){
                if 
                :: Requester_Cache.version[i]==payload.payload_content[1+2*j+1]>>4 && max_version>=Requester_Cache.version[i] -> 
                version_match=1; 
                printf("Version match, flag=%d, version=%d, max_version=%d\n", version_match, payload.payload_content[1+2*j+1]>>4, max_version); 
                :: Requester_Cache.version[i]==payload.payload_content[1+2*j+1]>>4 && max_version<Requester_Cache.version[i]-> 
                version_match=1;  
                max_version=Requester_Cache.version[i];
                printf("Version match, flag=%d, version=%d, max_version=%d\n", version_match, payload.payload_content[1+2*j+1]>>4, max_version); 
                :: else ->
                printf("Version checking, flag=%d, version=%d, checked=%d\n", version_match, payload.payload_content[1+2*j+1]>>4, Requester_Cache.version[i]);
                fi
            }
        }
        if
        :: version_match!=1->
        atomic {
                version_match=0;
                printf("Version not match, flag=%d\n", version_match); 
                version_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==VERSION);
                 // clear state
                // version_match=0;
                // capabilities_match=0;
                // algorithms_match=0;
                // digests_match=0;
                // certificate_match=0;
                // challenge_auth_match=0;
                // measurements_match=0;
                // vendor_defined_response_match=0;
                // key_exchange_rsp_match=0;
                // finish_rsp_match=0;
                // psk_exchange_rsp_match=0;
                // psk_finish_rsp_match=0;
                // heartbeat_ack_match=0;
                // key_update_ack_match=0;
                // encapsulated_request_match=0;
                // encapsulated_response_ack_match=0;
                // end_session_ack_match=0;
                // Requester_Cache.version_match=0;
                // Requester_Cache.capabilities_match=0;
                // Requester_Cache.algorithms_match=0;
                // Requester_Cache.digests_match=0;
                // Requester_Cache.certificate_match=0;
                // Requester_Cache.challenge_auth_match=0;
                // Requester_Cache.measurements_match=0;
                // Requester_Cache.vendor_defined_response_match=0;
                // Requester_Cache.key_exchange_rsp_match=0;
                // Requester_Cache.finish_rsp_match=0;
                // Requester_Cache.psk_exchange_rsp_match=0;
                // Requester_Cache.psk_finish_rsp_match=0;
                // Requester_Cache.heartbeat_ack_match=0;
                // Requester_Cache.key_update_ack_match=0;
                // Requester_Cache.encapsulated_request_match=0;
                // Requester_Cache.encapsulated_response_ack_match=0;
                // Requester_Cache.end_session_ack_match=0;
                Que!channelType(return_payload, 0, 0, GET_VERSION, 2);
                for (i : 0 .. M_length-1){
                    challenge_M1[i]=0
                }
                for (i: 0 .. range_length-1){
                    challenge_range_1[i]=0
                }
                global_length_num=0;
                for (i : 0 .. M_length-1){
                    challenge_M2[i]=0
                }
                for (i: 0 .. range_length-1){
                    challenge_range_2[i]=0
                }
                global_length_num_2=0;
                
                buffer_challenge_M2[0]=2; buffer_challenge_M2[1]=GET_VERSION; 
                buffer_challenge_M2[2]=0; buffer_challenge_M2[3]=0;
                buffer_challenge_range_2=length_reference[0];
                goto GET_CAPABILITIES_1;
        }; 
        :: else ->
            atomic{
                // timeout;
                // prepare challenge M2
                if
                :: global_length_num_2==0 ->
                    for (i: 0 .. buffer_challenge_range_2-1){
                        challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
                    }
                    challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
                    global_length_num_2++;
                :: else ->
                    for (i: 0 .. buffer_challenge_range_2-1){
                        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
                    }
                    challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
                    global_length_num_2++;
                fi
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
                for (i: length_reference[0]+4 .. length_reference[0]+4+length_reference[1]-1){
                    challenge_M2[(i)%M_length]=payload.payload_content[(i-length_reference[0]-4)]
                }
                challenge_range_2[(global_length_num_2)%range_length]=length_reference[1]+challenge_range_2[(global_length_num_2-1)%range_length]
                global_length_num_2++;
                printf("challenge_M2[0]=%d, challenge_M2[1]=%d, challenge_M2[2]=%d, challenge_M2[3]=%d\n", challenge_M2[0], challenge_M2[1], challenge_M2[2], challenge_M2[3])
                printf("							version 0 match\n");
                Requester_Cache.version_match=1;
                Que!channelType(return_payload, 0, 0, GET_CAPABILITIES, max_version);
                // prepare challenge M2
                buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=GET_CAPABILITIES; 
                buffer_challenge_M2[2]=0; buffer_challenge_M2[3]=0;
                for (i: 0 .. length_reference[2]-1-4){
                    buffer_challenge_M2[4+i]=return_payload.payload_content[MAX_LENGTH-(length_reference[2]-1-4-i)-1]
                }
                buffer_challenge_range_2=length_reference[2];

                // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=GET_CAPABILITIES; 
                // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=0; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=0;
                // printf("1 is %d, 2 is %d, 3 is %d, 4 is %d\n", challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]],\
                // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1], challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2],\
                // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3])
                // for (i: 0 .. length_reference[2]-1-4){
                //     challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+4+i]=return_payload.payload_content[MAX_LENGTH-(length_reference[2]-1-4-i)-1]
                // }
                // challenge_range_2[(global_length_num_2)%range_length]=length_reference[2]+challenge_range_2[(global_length_num_2-1)%range_length]
                // global_length_num_2++;
                if 
                :: skip -> goto NEGOTIATE_ALGORITHMS_1;
                fi
            }
        fi
    }
    :: else ->
    atomic {
        // version_match=0;
        printf("Version not match, flag=%d\n", version_match); 
        version_match=2;
        // KEY_UPDATE 6
        assert(ERROR_response_code==VERSION);
        // clear state
        // version_match=0;
        // capabilities_match=0;
        // algorithms_match=0;
        // digests_match=0;
        // certificate_match=0;
        // challenge_auth_match=0;
        // measurements_match=0;
        // vendor_defined_response_match=0;
        // key_exchange_rsp_match=0;
        // finish_rsp_match=0;
        // psk_exchange_rsp_match=0;
        // psk_finish_rsp_match=0;
        // heartbeat_ack_match=0;
        // key_update_ack_match=0;
        // encapsulated_request_match=0;
        // encapsulated_response_ack_match=0;
        // end_session_ack_match=0;
        // Requester_Cache.version_match=0;
        // Requester_Cache.capabilities_match=0;
        // Requester_Cache.algorithms_match=0;
        // Requester_Cache.digests_match=0;
        // Requester_Cache.certificate_match=0;
        // Requester_Cache.challenge_auth_match=0;
        // Requester_Cache.measurements_match=0;
        // Requester_Cache.vendor_defined_response_match=0;
        // Requester_Cache.key_exchange_rsp_match=0;
        // Requester_Cache.finish_rsp_match=0;
        // Requester_Cache.psk_exchange_rsp_match=0;
        // Requester_Cache.psk_finish_rsp_match=0;
        // Requester_Cache.heartbeat_ack_match=0;
        // Requester_Cache.key_update_ack_match=0;
        // Requester_Cache.encapsulated_request_match=0;
        // Requester_Cache.encapsulated_response_ack_match=0;
        // Requester_Cache.end_session_ack_match=0;
        Que!channelType(return_payload, 0, 0, GET_VERSION, 2);
        // TODO: no not matched M1 M2 message
        goto GET_CAPABILITIES_1;
        }
    fi
    //:: skip;//timeout


    if 
    :: signal==PSK_EXCHANGE_RSP && signal2==Requester_Cache.psk_exchange_rsp && PSK_CAP!=2 ->
        atomic{
        printf("							psk_exchange_rsp 1 match\n");
        Requester_Cache.psk_exchange_rsp_match=1;
        psk_exchange_rsp_match=1;
        // PSK_EXCHANGE 11
        assert(PSK_CAP==2 && GET_CAPABILITIES==PSK_FINISH||PSK_CAP!=2)
        Que!channelType(return_payload, 0, 0, GET_CAPABILITIES, max_version);
        if 
        :: skip -> goto NEGOTIATE_ALGORITHMS_1;
        fi 
        } 
    :: signal==PSK_FINISH_RSP && signal2==Requester_Cache.psk_finish_rsp && PSK_CAP==2 ->
        atomic{
        printf("							psk_finish_rsp 2 match\n");
        Requester_Cache.psk_finish_rsp_match=1;
        psk_finish_rsp_match=1;
        Que!channelType(return_payload, 0, 0, GET_CAPABILITIES, max_version);
        if 
        :: skip -> goto NEGOTIATE_ALGORITHMS_1;
        fi 
        } 
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==VERSION->
        atomic{
        printf("Has not ResponseNotReady error in VERSION 3\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==VERSION);
        // clear state
        // version_match=0;
        // capabilities_match=0;
        // algorithms_match=0;
        // digests_match=0;
        // certificate_match=0;
        // challenge_auth_match=0;
        // measurements_match=0;
        // vendor_defined_response_match=0;
        // key_exchange_rsp_match=0;
        // finish_rsp_match=0;
        // psk_exchange_rsp_match=0;
        // psk_finish_rsp_match=0;
        // heartbeat_ack_match=0;
        // key_update_ack_match=0;
        // encapsulated_request_match=0;
        // encapsulated_response_ack_match=0;
        // end_session_ack_match=0;
        // Requester_Cache.version_match=0;
        // Requester_Cache.capabilities_match=0;
        // Requester_Cache.algorithms_match=0;
        // Requester_Cache.digests_match=0;
        // Requester_Cache.certificate_match=0;
        // Requester_Cache.challenge_auth_match=0;
        // Requester_Cache.measurements_match=0;
        // Requester_Cache.vendor_defined_response_match=0;
        // Requester_Cache.key_exchange_rsp_match=0;
        // Requester_Cache.finish_rsp_match=0;
        // Requester_Cache.psk_exchange_rsp_match=0;
        // Requester_Cache.psk_finish_rsp_match=0;
        // Requester_Cache.heartbeat_ack_match=0;
        // Requester_Cache.key_update_ack_match=0;
        // Requester_Cache.encapsulated_request_match=0;
        // Requester_Cache.encapsulated_response_ack_match=0;
        // Requester_Cache.end_session_ack_match=0;
        Que!channelType(payload, 0, 0, GET_VERSION, 2);
        for (i : 0 .. M_length-1){
            challenge_M1[i]=0
        }
        for (i: 0 .. range_length-1){
            challenge_range_1[i]=0
        }
        global_length_num=0;
        for (i : 0 .. M_length-1){
            challenge_M2[i]=0
        }
        for (i: 0 .. range_length-1){
            challenge_range_2[i]=0
        }
        global_length_num_2=0;
        goto GET_CAPABILITIES_1;
        }
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==PSK_EXCHANGE_RSP->
        atomic{
        printf("Has not ResponseNotReady error in PSK_EXCHANGE_RSP 5\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==PSK_EXCHANGE_RSP);
        Que!channelType(payload, 0, 0, PSK_EXCHANGE, max_version);
        goto GET_CAPABILITIES_1;
        }
    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==PSK_EXCHANGE_RSP ->
        atomic{
        printf("ResponseNotReady error in PSK_EXCHANGE_RSP 6\n");
        goto RespondIfReady_1;
        }
    :: signal==PSK_EXCHANGE_RSP && signal2!=Requester_Cache.psk_exchange_rsp ->
        atomic{
        printf("psk_exchange_rsp 7 not match\n");
        psk_exchange_rsp_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==PSK_EXCHANGE_RSP);
        Que!channelType(payload, 0, 0, PSK_EXCHANGE, max_version);
        goto GET_CAPABILITIES_1;
        }
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==PSK_FINISH_RSP->
        atomic{
        printf("Has not ResponseNotReady error in PSK_FINISH_RSP 8\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==PSK_FINISH_RSP);
        Que!channelType(payload, 0, 0, PSK_FINISH, max_version);
        goto GET_CAPABILITIES_1;
        }
    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==PSK_FINISH_RSP ->
        atomic{
        printf("ResponseNotReady error in PSK_FINISH_RSP 9\n");
        goto RespondIfReady_1;
        }
    :: signal==PSK_FINISH_RSP && signal2!=Requester_Cache.psk_finish_rsp ->
        atomic{
        printf("psk_finish_rsp 10 not match\n");
        psk_finish_rsp_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==PSK_FINISH_RSP);
        Que!channelType(payload, 0, 0, PSK_FINISH, max_version);
        goto GET_CAPABILITIES_1;
        }
    :: else ->
        atomic{
        printf("GET_CAPABILITIES has error, signal=%d, param1=%d, ERROR_response_code=%d, RESPOND_IF_READY_response_code=%d\n", signal, param1, ERROR_response_code, RESPOND_IF_READY_response_code);
        }
    fi
NEGOTIATE_ALGORITHMS_1:
    Spd?channelType(payload,param2,param1,signal,signal2);
    printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error, param1);
    assert(!(signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==ALGORITHMS ))
    // start to prepare GET_CAPABILITIES
    for (i : 0 .. MAX_LENGTH-1){
        return_payload.payload_content[i]=0
    }
    return_payload.payload_content[MAX_LENGTH-1-1]=0 // Reserved
    return_payload.payload_content[MAX_LENGTH-1-2]=10 // CTExponent
    return_payload.payload_content[MAX_LENGTH-1-3]=0 // Reserved
    return_payload.payload_content[MAX_LENGTH-1-4]=Requester_Cache.capabilities[3] // flag LSB byte
    return_payload.payload_content[MAX_LENGTH-1-5]=Requester_Cache.capabilities[2] // flag 
    return_payload.payload_content[MAX_LENGTH-1-6]=Requester_Cache.capabilities[1] // flag 
    return_payload.payload_content[MAX_LENGTH-1-7]=Requester_Cache.capabilities[0] // flag
    if 
    :: signal==CAPABILITIES->
        if
        :: signal2==max_version ->
            atomic{
            Responder_Cache.diffendpoint_capabilities[3]=payload.payload_content[MAX_LENGTH-1-4]
            Responder_Cache.diffendpoint_capabilities[2]=payload.payload_content[MAX_LENGTH-1-5]
            Responder_Cache.diffendpoint_capabilities[1]=payload.payload_content[MAX_LENGTH-1-6]
            Responder_Cache.diffendpoint_capabilities[0]=payload.payload_content[MAX_LENGTH-1-7]
            // printf("payload.payload_content[MAX_LENGTH-1-4] is %d, then is %d, then is %d\n", payload.payload_content[MAX_LENGTH-1-4], payload.payload_content[MAX_LENGTH-1-4]&2, payload.payload_content[MAX_LENGTH-1-4]&4)
            CERT_CAP=(payload.payload_content[MAX_LENGTH-1-4]&2)>0
            CHAL_CAP=(payload.payload_content[MAX_LENGTH-1-4]&4)>0
            MEAS_CAP=(payload.payload_content[MAX_LENGTH-1-4]>>3)&3
            // prepare challenge M2
            if
            :: global_length_num_2==0 ->
                for (i: 0 .. buffer_challenge_range_2-1){
                    challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
                }
                challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
                global_length_num_2++;
            :: else ->
                for (i: 0 .. buffer_challenge_range_2-1){
                    challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
                }
                challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
                global_length_num_2++;
            fi
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
            for (i: 0 .. length_reference[3]-1-4){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(length_reference[3]-1-4-i)-1]
            }
            challenge_range_2[(global_length_num_2)%range_length]=length_reference[3]+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
            printf("							capabilities 11 match\n");
            Requester_Cache.capabilities_match=1;
            capabilities_match=1;
            // start to prepare negotiate algorithms
            // now by default to support all or support the first one if only one is selected
            payload_message algorithms_payload;
            for (i : 0 .. MAX_LENGTH-1){// algorithms_payload.payload_content[MAX_LENGTH-1]-4-1){
                algorithms_payload.payload_content[i]=Requester_Cache.algorithms[i]
            }

            Que!channelType(algorithms_payload, 0, 4, NEGOTIATE_ALGORITHMS, max_version);
            // Param 1: 4 // number of algorithms structure tables in this request using ReqAlgStruct
            // prepare challenge M2
            buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=NEGOTIATE_ALGORITHMS; 
            buffer_challenge_M2[2]=4; buffer_challenge_M2[3]=0;
            for (i: 0 .. length_reference[4]-1-4){
                buffer_challenge_M2[4+i]=algorithms_payload.payload_content[MAX_LENGTH-(length_reference[4]-1-4-i)-1]
            }
            buffer_challenge_range_2=length_reference[4];

            // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=NEGOTIATE_ALGORITHMS; 
            // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=4; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=0;
            // for (i: 0 .. length_reference[4]-1-4){
            //     challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+4+i]=algorithms_payload.payload_content[MAX_LENGTH-(length_reference[4]-1-4-i)-1]
            // }
            // challenge_range_2[(global_length_num_2)%range_length]=length_reference[4]+challenge_range_2[(global_length_num_2-1)%range_length]
            // global_length_num_2++;
            if 
            :: skip -> goto GET_DIGESTS_1;
            fi 
            } 
        :: else->
            atomic{
            printf("capabilities 13 not match\n");
            capabilities_match=2;
                    // KEY_UPDATE 6
                    assert(ERROR_response_code==CAPABILITIES);
            Que!channelType(return_payload, 0, 0, GET_CAPABILITIES, max_version);
            goto NEGOTIATE_ALGORITHMS_1;
            }
        fi
 
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==CAPABILITIES->
        atomic{
        printf("Has not ResponseNotReady error in CAPABILITIES 12\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==CAPABILITIES);
        Que!channelType(return_payload, 0, 0, GET_CAPABILITIES, max_version);
        goto NEGOTIATE_ALGORITHMS_1;
        }
    :: else ->
        atomic{
        printf("NEGOTIATE_ALGORITHMS has error, signal=%d, param1=%d, ERROR_response_code=%d, RESPOND_IF_READY_response_code=%d\n", signal, param1, ERROR_response_code, RESPOND_IF_READY_response_code);
        }
    fi
GET_DIGESTS_1:
    Spd?channelType(payload,param2,param1,signal,signal2);
    printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error, param1);
    // start to prepare negotiate algorithms
    // now by default to support all or support the first one if only one is selected
    payload_message algorithms_payload;
    for (i : 0 .. MAX_LENGTH-1){// algorithms_payload.payload_content[MAX_LENGTH-1]-4-1){
        algorithms_payload.payload_content[i]=Requester_Cache.algorithms[i]
    }
    algorithms_payload.payload_content[MAX_LENGTH-1-8]=32// LSB BaseAsymSel //00100000
    algorithms_payload.payload_content[MAX_LENGTH-1-9]=0// BaseAsymSel //00000001 
    algorithms_payload.payload_content[MAX_LENGTH-1-10]=0// BaseAsymSel 
    algorithms_payload.payload_content[MAX_LENGTH-1-11]=0// BaseAsymSel 
    // TPM_ALG_SHA3_512 is supported
    algorithms_payload.payload_content[MAX_LENGTH-1-12]=32// LSB BaseHashSel //00100000
    algorithms_payload.payload_content[MAX_LENGTH-1-13]=0// BaseHashSel //00000001 
    algorithms_payload.payload_content[MAX_LENGTH-1-14]=0// BaseHashSel 
    algorithms_payload.payload_content[MAX_LENGTH-1-15]=0// BaseHashSel
    if 
    :: signal==ALGORITHMS && signal2==max_version ->
        atomic{
        // prepare challenge M2
        if
        :: global_length_num_2==0 ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
            global_length_num_2++;
        :: else ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
        fi
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
        for (i: 0 .. length_reference[5]-1-4){
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(length_reference[5]-1-4-i)-1]
        }
        challenge_range_2[(global_length_num_2)%range_length]=length_reference[5]+challenge_range_2[(global_length_num_2-1)%range_length]
        global_length_num_2++;
        printf("							algorithms 14 match\n");
        MeasurementSpecificationSel=payload.payload_content[MAX_LENGTH-1-2]
        for (i : 0 .. MAX_LENGTH-1){// algorithms_payload.payload_content[MAX_LENGTH-1]-4-1){
            Requester_Cache.diffendpoint_algorithms[i]=response_payload.payload_content[i]
        }
        // NEGOTIATE_ALGORITHMS 9
        BaseAsymSel=payload.payload_content[MAX_LENGTH-1-11]*16777216+\
                payload.payload_content[MAX_LENGTH-1-10]*65536+\
                payload.payload_content[MAX_LENGTH-1-9]*256+\
                payload.payload_content[MAX_LENGTH-1-8]
        BaseHashSel=payload.payload_content[MAX_LENGTH-1-15]*16777216+\
                payload.payload_content[MAX_LENGTH-1-14]*65536+\
                payload.payload_content[MAX_LENGTH-1-13]*256+\
                payload.payload_content[MAX_LENGTH-1-12]
        Requester_Cache.algorithms_match=1;
        algorithms_match=1;
        // start to prepare GET_DIGESTS
        Que!channelType(payload, 0, 0, GET_DIGESTS, max_version);
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=GET_DIGESTS; 
        buffer_challenge_M2[2]=0; buffer_challenge_M2[3]=0;
        buffer_challenge_range_2=length_reference[6];
        // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=GET_DIGESTS; 
        // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=4; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=0;
        // challenge_range_2[(global_length_num_2)%range_length]=length_reference[6]+challenge_range_2[(global_length_num_2-1)%range_length]
        // global_length_num_2++;
        if 
        :: skip -> goto GET_CERTIFICATE_1;
        fi 
        } 
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==ALGORITHMS->//RequestResynch
        atomic{
        printf("Has not ResponseNotReady error in NEGOTIATE_ALGORITHMS (RequestResynch) and will go to GET_VERSION again\n");
        // clear state
        response_signal=0;
        version_match=0;
        capabilities_match=0;
        algorithms_match=0;
        digests_match=0;
        certificate_match=0;
        challenge_auth_match=0;
        measurements_match=0;
        vendor_defined_response_match=0;
        key_exchange_rsp_match=0;
        finish_rsp_match=0;
        psk_exchange_rsp_match=0;
        psk_finish_rsp_match=0;
        heartbeat_ack_match=0;
        key_update_ack_match=0;
        encapsulated_request_match=0;
        encapsulated_response_ack_match=0;
        end_session_ack_match=0;
        Requester_Cache.version_match=0;
        Requester_Cache.capabilities_match=0;
        Requester_Cache.algorithms_match=0;
        Requester_Cache.digests_match=0;
        Requester_Cache.certificate_match=0;
        Requester_Cache.challenge_auth_match=0;
        Requester_Cache.measurements_match=0;
        Requester_Cache.vendor_defined_response_match=0;
        Requester_Cache.key_exchange_rsp_match=0;
        Requester_Cache.finish_rsp_match=0;
        Requester_Cache.psk_exchange_rsp_match=0;
        Requester_Cache.psk_finish_rsp_match=0;
        Requester_Cache.heartbeat_ack_match=0;
        Requester_Cache.key_update_ack_match=0;
        Requester_Cache.encapsulated_request_match=0;
        Requester_Cache.encapsulated_response_ack_match=0;
        Requester_Cache.end_session_ack_match=0;
        Que!channelType(payload, 0, 0, GET_VERSION, 2);
        // prepare challenge M2
        for (i : 0 .. M_length-1){
            challenge_M1[i]=0
        }
        for (i: 0 .. range_length-1){
            challenge_range_1[i]=0
        }
        global_length_num=0;
        for (i : 0 .. M_length-1){
            challenge_M2[i]=0
        }
        for (i: 0 .. range_length-1){
            challenge_range_2[i]=0
        }
        global_length_num_2=0;
        buffer_challenge_M2[0]=2; buffer_challenge_M2[1]=GET_VERSION; 
        buffer_challenge_M2[2]=0; buffer_challenge_M2[3]=0;
        buffer_challenge_range_2=length_reference[0];
        goto GET_CAPABILITIES_1;
        }
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==ALGORITHMS->
        atomic{
        printf("Has not ResponseNotReady error in ALGORITHMS 15\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==ALGORITHMS);
        Que!channelType(algorithms_payload, 0, 4, NEGOTIATE_ALGORITHMS, max_version);
        // Param 1: 4 // number of algorithms structure tables in this request using ReqAlgStruct
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=NEGOTIATE_ALGORITHMS; 
        buffer_challenge_M2[2]=4; buffer_challenge_M2[3]=0;
        for (i: 0 .. length_reference[4]-1-4){
            buffer_challenge_M2[4+i]=algorithms_payload.payload_content[MAX_LENGTH-(length_reference[4]-1-4-i)-1]
        }
        buffer_challenge_range_2=length_reference[4];
        goto GET_DIGESTS_1;
        }
    :: signal==ALGORITHMS && signal2!=max_version ->
        atomic{
        printf("algorithms 16 not match\n");
        algorithms_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==ALGORITHMS);
        Que!channelType(algorithms_payload, 0, 4, NEGOTIATE_ALGORITHMS, max_version);
        goto GET_DIGESTS_1;
        }
    :: else ->
        atomic{
        printf("GET_DIGESTS has error, signal=%d, param1=%d, ERROR_response_code=%d, RESPOND_IF_READY_response_code=%d\n", signal, param1, ERROR_response_code, RESPOND_IF_READY_response_code);
        }
    fi
GET_CERTIFICATE_1:
    Spd?channelType(payload,param2,param1,signal,signal2);
    printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error, param1);
    if 
    :: signal==DIGESTS && signal2==max_version ->
        atomic{
        // prepare challenge M2
        if
        :: global_length_num_2==0 ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
            global_length_num_2++;
        :: else ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
        fi
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
        for (i: 0 .. length_reference[7]-1-4){
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(length_reference[7]-1-4-i)-1]
        }
        challenge_range_2[(global_length_num_2)%range_length]=length_reference[7]+challenge_range_2[(global_length_num_2-1)%range_length]
        global_length_num_2++;
        printf("							digests 17 match\n");
        byte num=param2&1 + param2&2 + param2&4 + param2&8 + param2&16 + param2&32 + param2&64 + param2&128;
        for (i : 0 .. num-1){
            for (j : 0 .. H-1){
                Requester_Cache.diffendpoint_certificate_chain[i].RootHash[j]=payload.payload_content[MAX_LENGTH-(i+1)*H+j]
            }
        }
        // GET_DIGESTS 14
        assert(payload.payload_content[MAX_LENGTH-(num+1)*H+0]==0)
        Requester_Cache.digests_match=1;
        digests_match=1;
        // start to prepare GET_CERTIFICATE
        byte param1_in=0
        if
        :: param2&2 != 0 -> param1_in=1
        :: param2&1 != 0 -> param1_in=0
        fi
        param1_in_certificate=param1_in
        // if
        // :: param2&2 != 0 -> param1_in_certificate=1
        // :: param2&1 != 0 -> param1_in_certificate=0
        // fi
        byte offset_value=0;
        algorithms_payload_certificate.payload_content[MAX_LENGTH-1]=offset_value;
        algorithms_payload_certificate.payload_content[MAX_LENGTH-3]=Requester_Cache.certificate_chain[param1_in].Length[0];
        algorithms_payload_certificate.payload_content[MAX_LENGTH-4]=Requester_Cache.certificate_chain[param1_in].Length[1];
        diffendpoint_certificate_chain_buffer_index=0;
        // for (i : 0 .. 7){
        //     if
        //     :: Requester_Cache.diffendpoint_certificate_chain_buffer[i].Length[0]==0->
        //         algorithms_payload_certificate.payload_content[MAX_LENGTH-1]=offset_value;
        //         algorithms_payload_certificate.payload_content[MAX_LENGTH-3]=Requester_Cache.certificate_chain[param1_in].Length[0];
        //         algorithms_payload_certificate.payload_content[MAX_LENGTH-4]=Requester_Cache.certificate_chain[param1_in].Length[1];
        //         diffendpoint_certificate_chain_buffer_index=i;
        //         break;
        //     :: else->
        //         offset_value = offset_value + Requester_Cache.diffendpoint_certificate_chain_buffer[i].Length[1]*256+ Requester_Cache.diffendpoint_certificate_chain_buffer[i].Length[0];
        //     fi
        // }
        printf("in requester, length1 is %d, length2 is %d\n", algorithms_payload_certificate.payload_content[MAX_LENGTH-3], algorithms_payload_certificate.payload_content[MAX_LENGTH-4])
        Que!channelType(algorithms_payload_certificate, 0, param1_in, GET_CERTIFICATE, max_version);
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=GET_CERTIFICATE; 
        buffer_challenge_M2[2]=param1_in; buffer_challenge_M2[3]=0;
        for (i: 0 .. length_reference[8]-1-4){
            buffer_challenge_M2[4+i]=algorithms_payload_certificate.payload_content[MAX_LENGTH-(length_reference[8]-1-4-i)-1]
        }
        buffer_challenge_range_2=length_reference[8];
        // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=GET_CERTIFICATE; 
        // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=param1_in; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=0;
        // for (i: 0 .. length_reference[8]-1-4){
        //     challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+4+i]=algorithms_payload_certificate.payload_content[MAX_LENGTH-(length_reference[8]-1-4-i)-1]
        // }
        // challenge_range_2[(global_length_num_2)%range_length]=length_reference[8]+challenge_range_2[(global_length_num_2-1)%range_length]
        // global_length_num_2++;
        if 
        :: skip -> goto CHALLENGE_1;
        fi 
        } 
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==DIGESTS->
        atomic{
        printf("Has not ResponseNotReady error in DIGESTS 18\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==DIGESTS);
        Que!channelType(payload, 0, 0, GET_DIGESTS, max_version);
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=GET_DIGESTS; 
        buffer_challenge_M2[2]=0; buffer_challenge_M2[3]=0;
        buffer_challenge_range_2=length_reference[6];
        goto GET_CERTIFICATE_1;
        }
    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==DIGESTS ->
        atomic{
        if
        :: global_length_num_2==0 ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
            // global_length_num_2++;
        :: else ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
            // global_length_num_2++;
        fi
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
        for (i: 0 .. ResponseNotReady_length-1){
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(ResponseNotReady_length-1-i)-1]
        }
        challenge_range_2[(global_length_num_2)%range_length]=ResponseNotReady_length+4+challenge_range_2[(global_length_num_2-1)%range_length]
        // global_length_num_2++;
        printf("ResponseNotReady error in DIGESTS 19\n");
        goto RespondIfReady_1;
        }
    :: signal==DIGESTS && signal2!=max_version ->
        atomic{
        printf("digests 20 not match\n");
        digests_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==DIGESTS);
        Que!channelType(payload, 0, 0, GET_DIGESTS, max_version);
        goto GET_CERTIFICATE_1;
        }
    :: else ->
        atomic{
        printf("GET_CERTIFICATE has error, signal=%d, param1=%d, ERROR_response_code=%d, RESPOND_IF_READY_response_code=%d\n", signal, param1, ERROR_response_code, RESPOND_IF_READY_response_code);
        }
    fi
CHALLENGE_1:
    Spd?channelType(payload,param2,param1,signal,signal2);
    printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error, param1);
    // start to prepare GET_CERTIFICATE
    
    
    byte offset_value=0;
    int response_certificate_length1;
    int response_certificate_length2;
    // if 
    // :: reminderlength==0 ->
    //     algorithms_payload.payload_content[MAX_LENGTH-1]=0;
    //     algorithms_payload.payload_content[MAX_LENGTH-3]=Requester_Cache.certificate_chain[param1_in].Length[0];
    //     algorithms_payload.payload_content[MAX_LENGTH-4]=Requester_Cache.certificate_chain[param1_in].Length[1];
    // fi
    // algorithms_payload_certificate.payload_content[MAX_LENGTH-1]+=portionlength;
    // algorithms_payload_certificate.payload_content[MAX_LENGTH-3]-=reminderlength/256;
    // algorithms_payload_certificate.payload_content[MAX_LENGTH-4]-=reminderlength&255;
    // for (i : 0 .. 7){
    //     if
    //     :: Requester_Cache.diffendpoint_certificate_chain_buffer[i].Length[0]==0->
    //         algorithms_payload_certificate.payload_content[MAX_LENGTH-1]=offset_value;
    //         algorithms_palgorithms_payload_certificateayload.payload_content[MAX_LENGTH-3]=Requester_Cache.certificate_chain[param1_in_certificate].Length[0];
    //         algorithms_payload_certificate.payload_content[MAX_LENGTH-4]=Requester_Cache.certificate_chain[param1_in_certificate].Length[1];
    //         break;
    //     :: else->
    //         offset_value = offset_value + Requester_Cache.diffendpoint_certificate_chain_buffer[i].Length[1]*256+ Requester_Cache.diffendpoint_certificate_chain_buffer[i].Length[0];
    //     fi
    // }
    if 
    :: signal==CERTIFICATE && signal2==max_version ->
        atomic{
        // byte portionlength=0,reminderlength=0;
        portionlength=payload.payload_content[MAX_LENGTH-2]*256+payload.payload_content[MAX_LENGTH-1];
        reminderlength=payload.payload_content[MAX_LENGTH-4]*256+payload.payload_content[MAX_LENGTH-3];
        // for (i : portionlength-1 .. 0){
        //     // payload.payload_content[MAX_LENGTH-5-i]=Responder_Cache.certificate_chain[param1].Certificates[portionlength-1-i]
        //     // payload.payload_content[MAX_LENGTH-5-i-reminderlength]=Responder_Cache.certificate_chain[param1].Certificates[pre_portionlength+portionlength-1-i]
        //     Requester_Cache.diffendpoint_certificate_chain_buffer[diffendpoint_certificate_chain_buffer_index].Certificates[pre_portionlength+portionlength-1-i]=payload.payload_content[MAX_LENGTH-5-i-reminderlength]
        // }
        printf("pre_portionlength is %d\n", pre_portionlength)
        if 
        :: portionlength==1 ->
            // certificate_payload.payload_content[MAX_LENGTH-5-reminderlength]=Responder_Cache.certificate_chain[buffered_param1].Certificates[pre_portionlength-1]
            Requester_Cache.diffendpoint_certificate_chain_buffer[diffendpoint_certificate_chain_buffer_index].Certificates[pre_portionlength-1]=payload.payload_content[MAX_LENGTH-5-reminderlength]
        :: portionlength>1 ->
            for (i : portionlength-1 .. 0){
                // certificate_payload.payload_content[MAX_LENGTH-5-i-reminderlength]=Responder_Cache.certificate_chain[buffered_param1].Certificates[pre_portionlength+portionlength-1-i]
                Requester_Cache.diffendpoint_certificate_chain_buffer[diffendpoint_certificate_chain_buffer_index].Certificates[pre_portionlength+portionlength-1-i]=payload.payload_content[MAX_LENGTH-5-i-reminderlength]
            }
        fi
        printf("							certificate 21 match\n");
        Requester_Cache.certificate_match=1;
        certificate_match=1;
        printf("in requester, remind is %d, portion is %d\n", reminderlength, portionlength)

        // prepare challenge M2
        if
        :: portionlength==1 -> {response_certificate_length1=length_reference[13];response_certificate_length2=length_reference[12]}
        :: portionlength>1 -> {response_certificate_length1=length_reference[9];response_certificate_length2=length_reference[8]}
        :: else -> {printf("portionlength error\n"); assert(0)}
        fi
        if
        :: global_length_num_2==0 ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
            global_length_num_2++;
        :: else ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
        fi
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
        for (i: 0 .. response_certificate_length1-1-4){
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(response_certificate_length1-1-4-i)-1]
        }
        challenge_range_2[(global_length_num_2)%range_length]=response_certificate_length1+challenge_range_2[(global_length_num_2-1)%range_length]
        global_length_num_2++;

        if 
        :: reminderlength==0 ->
            diffendpoint_certificate_chain_buffer_index++;
            // start to prepare CHALLENGE
            byte param2_local = MEAS_CAP==1 || MEAS_CAP==2
            payload_message challenge_nonce;
            byte challenge_nr=0;
            for (i: 0 .. 32-1){
                challenge_nonce.payload_content[MAX_LENGTH-1]=challenge_nr
                challenge_nr++
            }
            Que!channelType(challenge_nonce, param2_local, param1_in_certificate, CHALLENGE, max_version);
            printf("After sending challenge\n")
            // prepare challenge M2
            buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=CHALLENGE; 
            buffer_challenge_M2[2]=param1_in_certificate; buffer_challenge_M2[3]=param2_local;
            for (i: 0 .. length_reference[14]-1-4){
                buffer_challenge_M2[4+i]=challenge_nonce.payload_content[MAX_LENGTH-(length_reference[14]-1-4-i)-1]
            }
            buffer_challenge_range_2=length_reference[14];
            // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=CHALLENGE; 
            // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=param1_in_certificate; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=param2_local;
            // for (i: 0 .. length_reference[14]-1-4){
            //     challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+4+i]=challenge_nonce.payload_content[MAX_LENGTH-(length_reference[14]-1-4-i)-1]
            // }
            // challenge_range_2[(global_length_num_2)%range_length]=length_reference[14]+challenge_range_2[(global_length_num_2-1)%range_length]
            // global_length_num_2++;
            if 
            :: skip -> goto GET_MEASUREMENTS_1;
            fi 
        :: else ->
            algorithms_payload_certificate.payload_content[MAX_LENGTH-2]=algorithms_payload_certificate.payload_content[MAX_LENGTH-2]+portionlength/256;
            algorithms_payload_certificate.payload_content[MAX_LENGTH-1]=algorithms_payload_certificate.payload_content[MAX_LENGTH-1]+portionlength&255;
            algorithms_payload_certificate.payload_content[MAX_LENGTH-4]=reminderlength/256;//algorithms_payload_certificate.payload_content[MAX_LENGTH-4]-portionlength/256;//reminderlength/256;
            algorithms_payload_certificate.payload_content[MAX_LENGTH-3]=reminderlength%255;//algorithms_payload_certificate.payload_content[MAX_LENGTH-3]-portionlength&255;//reminderlength&255;
            printf("algorithms_payload_certificate.payload_content[MAX_LENGTH-1]=%d, algorithms_payload_certificate.payload_content[MAX_LENGTH-3]=%d\n",\
            algorithms_payload_certificate.payload_content[MAX_LENGTH-1], algorithms_payload_certificate.payload_content[MAX_LENGTH-3])
            Que!channelType(algorithms_payload_certificate, 0, param1_in_certificate, GET_CERTIFICATE, max_version);
            // pre_portionlength=pre_portionlength+portionlength;
            // prepare challenge M2
            buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=GET_CERTIFICATE; 
            buffer_challenge_M2[2]=param1_in_certificate; buffer_challenge_M2[3]=0;
            for (i: 0 .. response_certificate_length2-1-4){
                buffer_challenge_M2[4+i]=algorithms_payload_certificate.payload_content[MAX_LENGTH-(response_certificate_length2-1-4-i)-1]
            }
            buffer_challenge_range_2=response_certificate_length2;
            // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=GET_CERTIFICATE; 
            // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=param1_in_certificate; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=0;
            // for (i: 0 .. response_certificate_length2-1-4){
            //     challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+4+i]=algorithms_payload_certificate.payload_content[MAX_LENGTH-(response_certificate_length2-1-4-i)-1]
            // }
            // challenge_range_2[(global_length_num_2)%range_length]=response_certificate_length2+challenge_range_2[(global_length_num_2-1)%range_length]
            // global_length_num_2++;
            if 
            :: skip -> goto CHALLENGE_1;
            fi 
        fi
        } 
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==CERTIFICATE->
        atomic{
        printf("Has not ResponseNotReady error in CERTIFICATE 22\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==CERTIFICATE);
        printf("param1 certificate=%d\n", param1_in_certificate)
        byte local_response_certificate_length2;//=length_reference[8];
        if
        :: response_certificate_length2>0 -> local_response_certificate_length2=response_certificate_length2
        :: else -> local_response_certificate_length2=length_reference[8];
        fi
        Que!channelType(algorithms_payload_certificate, 0, param1_in_certificate, GET_CERTIFICATE, max_version);
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=GET_CERTIFICATE; 
        buffer_challenge_M2[2]=param1_in_certificate; buffer_challenge_M2[3]=0;
        for (i: 0 .. local_response_certificate_length2-1-4){
            buffer_challenge_M2[4+i]=algorithms_payload_certificate.payload_content[MAX_LENGTH-(local_response_certificate_length2-1-4-i)-1]
        }
        buffer_challenge_range_2=local_response_certificate_length2;
        goto CHALLENGE_1;
        }
    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==CERTIFICATE ->
        atomic{
            if
            :: global_length_num_2==0 ->
                for (i: 0 .. buffer_challenge_range_2-1){
                    challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
                }
                challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
                global_length_num_2++;
            :: else ->
                for (i: 0 .. buffer_challenge_range_2-1){
                    challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
                }
                challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
                global_length_num_2++;
            fi
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
            for (i: 0 .. ResponseNotReady_length-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(ResponseNotReady_length-1-i)-1]
            }
            challenge_range_2[(global_length_num_2)%range_length]=ResponseNotReady_length+4+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
        printf("ResponseNotReady error in CERTIFICATE 23\n");
        goto RespondIfReady_1;
        }
    :: signal==CERTIFICATE && signal2!=max_version ->
        atomic{
        printf("certificate 24 not match\n");
        certificate_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==CERTIFICATE);
        Que!channelType(algorithms_payload_certificate, 0, param1_in_certificate, GET_CERTIFICATE, max_version);
        goto CHALLENGE_1;
        }
    :: else ->
        atomic{
        printf("CHALLENGE has error, signal=%d, param1=%d, ERROR_response_code=%d, RESPOND_IF_READY_response_code=%d\n", signal, param1, ERROR_response_code, RESPOND_IF_READY_response_code);
        assert(0);
        }
    fi
RespondIfReady_1:
    // prepare challenge M2
    // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=max_version; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=RESPOND_IF_READY; 
    // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=RESPOND_IF_READY_response_code; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=0;
    // challenge_range_2[(global_length_num_2)%range_length]=4+challenge_range_2[(global_length_num_2-1)%range_length]
    // global_length_num_2++;

    buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=RESPOND_IF_READY; 
    // buffer_challenge_M2[2]=RESPOND_IF_READY_response_code; 
    buffer_challenge_M2[3]=0;
    buffer_challenge_range_2=4;
    if 
    :: param1==ResponseNotReady && RESPOND_IF_READY_response_code==DIGESTS ->
        atomic{
            // respondIfReady 1
            assert(RESPOND_IF_READY_response_code==DIGESTS);
            Que!channelType(payload, 0, GET_DIGESTS, RESPOND_IF_READY, max_version);
            printf("send RESPOND_IF_READY for GET_DIGESTS\n");
            buffer_challenge_M2[2]=GET_DIGESTS;
        if 
        :: skip -> goto GET_CERTIFICATE_1;
        fi 
        }
    :: param1==ResponseNotReady && RESPOND_IF_READY_response_code==CERTIFICATE ->
        atomic{
            // respondIfReady 1
            assert(RESPOND_IF_READY_response_code==CERTIFICATE);
            Que!channelType(payload, 0, GET_CERTIFICATE, RESPOND_IF_READY, max_version);
            printf("send RESPOND_IF_READY for GET_CERTIFICATE\n");
            buffer_challenge_M2[2]=GET_CERTIFICATE;
        if 
        :: skip -> goto CHALLENGE_1;
        fi 
        }
    :: param1==ResponseNotReady && RESPOND_IF_READY_response_code==CHALLENGE_AUTH ->
        atomic{
            // respondIfReady 1
            assert(RESPOND_IF_READY_response_code==CHALLENGE_AUTH);
            Que!channelType(payload, 0, CHALLENGE, RESPOND_IF_READY, max_version);
            printf("send RESPOND_IF_READY for CHALLENGE\n");
            buffer_challenge_M2[2]=CHALLENGE;
        if 
        :: skip -> goto GET_MEASUREMENTS_1;
        fi 
        }
    :: param1==ResponseNotReady && RESPOND_IF_READY_response_code==MEASUREMENTS ->
        atomic{
            // respondIfReady 1
            assert(RESPOND_IF_READY_response_code==MEASUREMENTS);
            Que!channelType(payload, 0, GET_MEASUREMENTS, RESPOND_IF_READY, max_version);
            printf("send RESPOND_IF_READY for GET_MEASUREMENTS\n");
            goto GET_MEASUREMENTS_11;
        }
    :: else->
        atomic{
        printf("respondIfReady parameter error, param1=%d, RESPOND_IF_READY_response_code=%d\n", param1, RESPOND_IF_READY_response_code);
        assert(0);
        /*goto;*/
        }
    fi
GET_MEASUREMENTS_11:
    if 
    :: support_measurements==1 ->{
        Spd?channelType(payload,param2,param1,signal,signal2);
        // // prepare challenge M2
        // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]]=signal2; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+1]=signal; 
        // challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+2]=param1; challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+3]=param2;
        // for (i: 0 .. length_reference[15]-1-4){
        //     challenge_M2[challenge_range_2[(global_length_num_2-1)%range_length]+4+i]=payload.payload_content[MAX_LENGTH-(length_reference[15]-1-4-i)-1]
        // }
        // challenge_range_2[(global_length_num_2)%range_length]=length_reference[15]+challenge_range_2[(global_length_num_2-1)%range_length]
        // global_length_num_2++;
        if 
        :: signal==MEASUREMENTS && signal2==Requester_Cache.measurements ->
           atomic{
           printf("							measurements match\n");
           Requester_Cache.measurements_match=1;
           measurements_match=1;
           printf("Keep requesting GET_MEASUREMENTS or GET_VERSION\n");
           if  
           :: skip -> atomic{//Que!channelType(payload, 0, 0, GET_MEASUREMENTS, 0); 
                             goto GET_MEASUREMENTS_12;} 
           :: skip -> atomic{goto GET_VERSION_1;} 
           fi 
           } 
	    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==MEASUREMENTS->
	        atomic{
	        printf("Has not ResponseNotReady error in MEASUREMENTS 25\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==MEASUREMENTS);
	        Que!channelType(payload, 0, 0, GET_MEASUREMENTS, max_version);
	        goto GET_MEASUREMENTS_11;
	        }
	    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==MEASUREMENTS ->
	        atomic{
	        printf("ResponseNotReady error in MEASUREMENTS 26\n");
	        goto RespondIfReady_1;
	        }
	    :: signal==MEASUREMENTS && signal2!=Requester_Cache.measurements ->
	        atomic{
	        printf("measurements 27 not match\n");
	        measurements_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==MEASUREMENTS);
	        Que!channelType(payload, 0, 0, GET_MEASUREMENTS, max_version);
	        goto GET_MEASUREMENTS_11;
	        }
        fi} 
    :: else ->
        printf("Measurement is not supported. \n");
        goto LEAVE;
    fi 
GET_MEASUREMENTS_12:
    if 
    :: MEAS_FRESH_CAP==0 ->
        atomic{
        Requester_Cache.measurements_match=0;
        measurements_match=0;
        printf("Send reset before GET_MEASUREMENTS\n");
        }
    fi 
        // GET_MEASUREMENTS 2
        assert(!(MEAS_FRESH_CAP==0 && measurements_match==1));
        atomic{
        Que!channelType(payload, 0, 0, GET_MEASUREMENTS, max_version);
        goto GET_MEASUREMENTS_11;
        }
GET_MEASUREMENTS_1:
    Spd?channelType(payload,param2,param1,signal,signal2);
    printf("In GET_MEASUREMENTS\n")
    printf("signal=%d, global_error=%d, param1=%d\n",signal, global_error,param1);
    if 
    :: signal==CHALLENGE_AUTH && signal2==max_version ->
        atomic{
        // prepare challenge M2
        if
        :: global_length_num_2==0 ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
            global_length_num_2++;
        :: else ->
            for (i: 0 .. buffer_challenge_range_2-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
            }
            challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
        fi
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
        challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
        for (i: 0 .. length_reference[15]-1-4){
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(length_reference[15]-1-4-i)-1]
        }
        challenge_range_2[(global_length_num_2)%range_length]=length_reference[15]+challenge_range_2[(global_length_num_2-1)%range_length]
        global_length_num_2++;
        bit message_match=1;
        for (i: 0 .. (challenge_range_2[(global_length_num_2-1)%range_length])%M_length){
            if
            :: challenge_M1[(i)%M_length]!=challenge_M2[(i)%M_length] -> message_match=0; printf("%d is different\n", i); break;
            :: else -> skip;
            fi
        }
        printf("challenge_range_1[(global_length_num-1)range_length] is %d, challenge_range_2[(global_length_num_2-1)range_length] is %d\n", challenge_range_1[(global_length_num-1)%range_length], challenge_range_2[(global_length_num_2-1)%range_length])
        if 
        :: signal==CHALLENGE_AUTH && signal2==max_version ->
        for (i: 0 .. 49){//challenge_range_2[(global_length_num_2-1)%range_length]){
            printf("challenge_range_1[%d]=%d, challenge_range_2[%d]=%d\n", i, challenge_range_1[i], i, challenge_range_2[i])
        }
        for (i: 0 .. 500){//challenge_range_2[(global_length_num_2-1)%range_length]){
            printf("challenge_M1[%d]=%d, challenge_M2[%d]=%d\n", i, challenge_M1[i], i, challenge_M2[i])
        }
        :: else -> skip
        fi
        if 
        :: signal==CHALLENGE_AUTH && signal2==max_version && message_match==1 && challenge_range_1[(global_length_num-1)%range_length]==challenge_range_2[(global_length_num_2-1)%range_length] -> {
        printf("							challenge_auth match\n");
        Requester_Cache.challenge_auth_match=1;
        challenge_auth_match=1;
        if
        :: !(MEAS_CAP==1||MEAS_CAP==2)->
            goto GET_MEASUREMENTS_11;
        :: MEAS_CAP==1||MEAS_CAP==2->
            support_measurements=1;
            goto GET_MEASUREMENTS_12;
        fi
        }
        :: else ->
        {
        printf("challenge_auth 30 not match\n");
        // CHALLENGE 19
        assert(0);
        challenge_auth_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==CHALLENGE_AUTH);
        // prepare challenge M2
        byte param2_local = MEAS_CAP==1 || MEAS_CAP==2
        payload_message challenge_nonce;
        byte challenge_nr=0;
        for (i: 0 .. 32-1){
            challenge_nonce.payload_content[MAX_LENGTH-1]=challenge_nr
            challenge_nr++
        }
        Que!channelType(challenge_nonce, param2_local, param1_in_certificate, CHALLENGE, max_version);
        printf("After sending challenge\n")
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=CHALLENGE; 
        buffer_challenge_M2[2]=param1_in_certificate; buffer_challenge_M2[3]=param2_local;
        for (i: 0 .. length_reference[14]-1-4){
            buffer_challenge_M2[4+i]=challenge_nonce.payload_content[MAX_LENGTH-(length_reference[14]-1-4-i)-1]
        }
        buffer_challenge_range_2=length_reference[14];
        goto GET_MEASUREMENTS_1;
        }
        fi
        //Que!channelType(payload, 0, 0, CHALLENGE, 0);
        //goto GET_MEASUREMENTS_1;
        }  
    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==CHALLENGE_AUTH->
        atomic{
        printf("Has not ResponseNotReady error in CHALLENGE_AUTH 28\n");
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==CHALLENGE_AUTH);
        // prepare challenge M2
        byte param2_local = MEAS_CAP==1 || MEAS_CAP==2
        payload_message challenge_nonce;
        byte challenge_nr=0;
        for (i: 0 .. 32-1){
            challenge_nonce.payload_content[MAX_LENGTH-1]=challenge_nr
            challenge_nr++
        }
        Que!channelType(challenge_nonce, param2_local, param1_in_certificate, CHALLENGE, max_version);
        printf("After sending challenge\n")
        // prepare challenge M2
        buffer_challenge_M2[0]=max_version; buffer_challenge_M2[1]=CHALLENGE; 
        buffer_challenge_M2[2]=param1_in_certificate; buffer_challenge_M2[3]=param2_local;
        for (i: 0 .. length_reference[14]-1-4){
            buffer_challenge_M2[4+i]=challenge_nonce.payload_content[MAX_LENGTH-(length_reference[14]-1-4-i)-1]
        }
        buffer_challenge_range_2=length_reference[14];
        goto GET_MEASUREMENTS_1;
        }
    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code==CHALLENGE_AUTH ->
        atomic{
            if
            :: global_length_num_2==0 ->
                for (i: 0 .. buffer_challenge_range_2-1){
                    challenge_M2[(i)%M_length]=buffer_challenge_M2[i]
                }
                challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2
                global_length_num_2++;
            :: else ->
                for (i: 0 .. buffer_challenge_range_2-1){
                    challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+i)%M_length]=buffer_challenge_M2[i]
                }
                challenge_range_2[(global_length_num_2)%range_length]=buffer_challenge_range_2+challenge_range_2[(global_length_num_2-1)%range_length]
                global_length_num_2++;
            fi
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length])%M_length]=signal2; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+1)%M_length]=signal; 
            challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+2)%M_length]=param1; challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+3)%M_length]=param2;
            for (i: 0 .. ResponseNotReady_length-1){
                challenge_M2[(challenge_range_2[(global_length_num_2-1)%range_length]+4+i)%M_length]=payload.payload_content[MAX_LENGTH-(ResponseNotReady_length-1-i)-1]
            }
            challenge_range_2[(global_length_num_2)%range_length]=ResponseNotReady_length+4+challenge_range_2[(global_length_num_2-1)%range_length]
            global_length_num_2++;
            
        printf("ResponseNotReady error in CHALLENGE_AUTH 29\n");
        goto RespondIfReady_1;
        }
    :: signal==CHALLENGE_AUTH && signal2!=max_version ->
        atomic{
        printf("challenge_auth 30 not match\n");
        challenge_auth_match=2;
                 // KEY_UPDATE 6
                 assert(ERROR_response_code==CHALLENGE_AUTH);
        Que!channelType(payload, 0, 0, CHALLENGE, max_version);
        goto GET_MEASUREMENTS_1;
        }
    :: else ->
        atomic{
        printf("GET_MEASUREMENTS has error\n");
        }
    fi
LEAVE:
}

// active proctype randnr()
// {	/*
// 	 * don't call this rand()...
// 	 * to avoid a clash with the C library routine
// 	 */
// 	byte nr;	/* pick random value  */
// 	do
// 	:: nr++		/* randomly increment */
// 	:: nr--		/* or decrement       */
// 	:: break	/* or stop            */
// 	od;
// 	printf("nr: %d\n")	/* nr: 0..255 */
// }


init{
    atomic{
        byte i=0,j=0;
        Requester_Cache.measurements=3;
        Responder_Cache.measurements=3;
        Requester_Cache.challenge_auth=3;
        Responder_Cache.challenge_auth=3;
        Requester_Cache.certificate=3;
        Responder_Cache.certificate=3;
        Requester_Cache.digests=3;
        Responder_Cache.digests=3;
        // VERSION
        Requester_Cache.version[0]=2;
        Requester_Cache.version[1]=7;
        Requester_Cache.version[2]=11;
        Requester_Cache.version[3]=3;
        Responder_Cache.version[0]=6;
        Responder_Cache.version[1]=13;
        Responder_Cache.version[2]=11;
        // CAPABILITIES 
        //      Reserved    PUB_KEY_ID_CAP[1][0] HANDSHAKE_IN_THE_CLEAR_CAP[2][7] 
        // /              \
        // 00000000 00000000 00000000 00000000
        // requester
        // 0000 0000  0000 0000  0111 0111  1100 0110
        // responder
        // 0000 0000  0000 0000  0111 1011  1101 0111
        Requester_Cache.capabilities[0]=0;
        Requester_Cache.capabilities[1]=0;
        Requester_Cache.capabilities[2]=119;
        Requester_Cache.capabilities[3]=198;
        Responder_Cache.capabilities[0]=0;
        Responder_Cache.capabilities[1]=0;
        Responder_Cache.capabilities[2]=123;
        Responder_Cache.capabilities[3]=215;
        // ALGORITHMS
        Requester_Cache.algorithms[MAX_LENGTH-1]=72// Length LSB
        Requester_Cache.algorithms[MAX_LENGTH-1-1]=0// Length
        Requester_Cache.algorithms[MAX_LENGTH-1-2]=47// MeasurementSpecification//00101111
        // multiple measurement specification support
        Requester_Cache.algorithms[MAX_LENGTH-1-3]=0// Reserved
        // TPM_ALG_RSASSA_4096 is supported
        Requester_Cache.algorithms[MAX_LENGTH-1-4]=32// LSB BaseAsymAlgo //00100000
        Requester_Cache.algorithms[MAX_LENGTH-1-5]=0// BaseAsymAlgo //00000001 
        Requester_Cache.algorithms[MAX_LENGTH-1-6]=0// BaseAsymAlgo 
        Requester_Cache.algorithms[MAX_LENGTH-1-7]=0// BaseAsymAlgo 
        // TPM_ALG_SHA3_512 is supported
        Requester_Cache.algorithms[MAX_LENGTH-1-8]=32// LSB BaseHashAlgo //00100000
        Requester_Cache.algorithms[MAX_LENGTH-1-9]=0// BaseHashAlgo //00000001 
        Requester_Cache.algorithms[MAX_LENGTH-1-10]=0// BaseHashAlgo 
        Requester_Cache.algorithms[MAX_LENGTH-1-11]=0// BaseHashAlgo
        for (i : 1 .. 12){
            Requester_Cache.algorithms[MAX_LENGTH-1-11-i]=0
        }
        Requester_Cache.algorithms[MAX_LENGTH-1-24]=0// ExtAsymCount 
        Requester_Cache.algorithms[MAX_LENGTH-1-25]=0// ExtHashCount 
        Requester_Cache.algorithms[MAX_LENGTH-1-26]=0// Reserved
        Requester_Cache.algorithms[MAX_LENGTH-1-27]=0// Reserved
        Requester_Cache.algorithms[MAX_LENGTH-1-28]=1// ExtAsym LSB // TCG
        Requester_Cache.algorithms[MAX_LENGTH-1-29]=0// ExtAsym //Reserved
        Requester_Cache.algorithms[MAX_LENGTH-1-30]=0// ExtAsym //algorithm ID TODO
        Requester_Cache.algorithms[MAX_LENGTH-1-31]=0// ExtAsym
        Requester_Cache.algorithms[MAX_LENGTH-1-32]=1// ExtHash LSB // TCG
        Requester_Cache.algorithms[MAX_LENGTH-1-33]=0// ExtHash
        Requester_Cache.algorithms[MAX_LENGTH-1-34]=0// ExtHash
        Requester_Cache.algorithms[MAX_LENGTH-1-35]=0// ExtHash
        // ReqAlgStruct
        Requester_Cache.algorithms[MAX_LENGTH-1-36]=1// DHE
        Requester_Cache.algorithms[MAX_LENGTH-1-37]=33// DHE // 00100001 
        Requester_Cache.algorithms[MAX_LENGTH-1-38]=2// DHE //AlgSupported ffdhr3072 D=384 (bit 1)
        Requester_Cache.algorithms[MAX_LENGTH-1-39]=0// DHE
        Requester_Cache.algorithms[MAX_LENGTH-1-40]=1// DHE //AlgExternal // TCG
        Requester_Cache.algorithms[MAX_LENGTH-1-41]=0// DHE
        Requester_Cache.algorithms[MAX_LENGTH-1-42]=0// DHE 
        Requester_Cache.algorithms[MAX_LENGTH-1-43]=0// DHE
        Requester_Cache.algorithms[MAX_LENGTH-1-44]=3// AEAD
        Requester_Cache.algorithms[MAX_LENGTH-1-45]=33// AEAD // 00100001 
        Requester_Cache.algorithms[MAX_LENGTH-1-46]=2// AEAD // AlgExternal AES 256 (bit 1)
        Requester_Cache.algorithms[MAX_LENGTH-1-47]=0// AEAD
        Requester_Cache.algorithms[MAX_LENGTH-1-48]=1// AEAD //AlgExternal // TCG
        Requester_Cache.algorithms[MAX_LENGTH-1-49]=0// AEAD
        Requester_Cache.algorithms[MAX_LENGTH-1-50]=0// AEAD
        Requester_Cache.algorithms[MAX_LENGTH-1-51]=0// AEAD
        Requester_Cache.algorithms[MAX_LENGTH-1-52]=4// ReqBaseAsymAg
        Requester_Cache.algorithms[MAX_LENGTH-1-53]=33// ReqBaseAsymAg // 00100001
        Requester_Cache.algorithms[MAX_LENGTH-1-54]=32// ReqBaseAsymAg // AlgSupported TPM_ALG_RSASSA_4096 (bit5)
        Requester_Cache.algorithms[MAX_LENGTH-1-55]=0// ReqBaseAsymAg
        Requester_Cache.algorithms[MAX_LENGTH-1-56]=1// ReqBaseAsymAg //AlgExternal // TCG
        Requester_Cache.algorithms[MAX_LENGTH-1-57]=0// ReqBaseAsymAg
        Requester_Cache.algorithms[MAX_LENGTH-1-58]=0// ReqBaseAsymAg
        Requester_Cache.algorithms[MAX_LENGTH-1-59]=0// ReqBaseAsymAg
        Requester_Cache.algorithms[MAX_LENGTH-1-60]=5// KeySchedule
        Requester_Cache.algorithms[MAX_LENGTH-1-61]=33// KeySchedule // 00100001
        Requester_Cache.algorithms[MAX_LENGTH-1-62]=0// KeySchedule // AlgSupported Keyschedule (bit 0)
        Requester_Cache.algorithms[MAX_LENGTH-1-63]=0// KeySchedule
        Requester_Cache.algorithms[MAX_LENGTH-1-64]=1// KeySchedule //AlgExternal // TCG
        Requester_Cache.algorithms[MAX_LENGTH-1-65]=0// KeySchedule
        Requester_Cache.algorithms[MAX_LENGTH-1-66]=0// KeySchedule
        Requester_Cache.algorithms[MAX_LENGTH-1-67]=0// KeySchedule

        Responder_Cache.algorithms[MAX_LENGTH-1]=68//76// Length LSB
        Responder_Cache.algorithms[MAX_LENGTH-1-1]=0// Length
        Responder_Cache.algorithms[MAX_LENGTH-1-2]=1// MeasurementSpecificationSel//00101111//select 1
        // multiple measurement specification support
        Responder_Cache.algorithms[MAX_LENGTH-1-3]=0// Reserved
        Responder_Cache.algorithms[MAX_LENGTH-1-4]=32// MeasurementHashAlgo 00100000
        Responder_Cache.algorithms[MAX_LENGTH-1-5]=0// MeasurementHashAlgo
        Responder_Cache.algorithms[MAX_LENGTH-1-6]=0// MeasurementHashAlgo
        Responder_Cache.algorithms[MAX_LENGTH-1-7]=0// MeasurementHashAlgo
        // TPM_ALG_RSASSA_4096 is supported
        Responder_Cache.algorithms[MAX_LENGTH-1-8]=32// LSB BaseAsymSel //00100000
        Responder_Cache.algorithms[MAX_LENGTH-1-9]=0// BaseAsymSel //00000001 
        Responder_Cache.algorithms[MAX_LENGTH-1-10]=0// BaseAsymSel 
        Responder_Cache.algorithms[MAX_LENGTH-1-11]=0// BaseAsymSel 
        // TPM_ALG_SHA3_512 is supported
        Responder_Cache.algorithms[MAX_LENGTH-1-12]=32// LSB BaseHashSel //00100000
        Responder_Cache.algorithms[MAX_LENGTH-1-13]=0// BaseHashSel //00000001 
        Responder_Cache.algorithms[MAX_LENGTH-1-14]=0// BaseHashSel 
        Responder_Cache.algorithms[MAX_LENGTH-1-15]=0// BaseHashSel
        for (i : 1 .. 12){
            Responder_Cache.algorithms[MAX_LENGTH-1-15-i]=0
        }
        Responder_Cache.algorithms[MAX_LENGTH-1-28]=0// ExtAsymSelCount 
        Responder_Cache.algorithms[MAX_LENGTH-1-29]=0// ExtHashSelCount 
        Responder_Cache.algorithms[MAX_LENGTH-1-30]=0// Reserved
        Responder_Cache.algorithms[MAX_LENGTH-1-31]=0// Reserved
        // Responder_Cache.algorithms[MAX_LENGTH-1-32]=1// ExtAsymSel LSB // TCG
        // Responder_Cache.algorithms[MAX_LENGTH-1-33]=0// ExtAsymSel //Reserved
        // Responder_Cache.algorithms[MAX_LENGTH-1-34]=0// ExtAsymSel //algorithm ID TODO
        // Responder_Cache.algorithms[MAX_LENGTH-1-35]=0// ExtAsymSel
        // Responder_Cache.algorithms[MAX_LENGTH-1-36]=1// ExtHashSel LSB // TCG
        // Responder_Cache.algorithms[MAX_LENGTH-1-37]=0// ExtHashSel
        // Responder_Cache.algorithms[MAX_LENGTH-1-38]=0// ExtHashSel
        // Responder_Cache.algorithms[MAX_LENGTH-1-39]=0// ExtHashSel
        // NEGOTIATE_ALGORITHMS 9
        // ReqAlgStruct
        Responder_Cache.algorithms[MAX_LENGTH-1-32]=1// DHE
        Responder_Cache.algorithms[MAX_LENGTH-1-33]=33// DHE // 00100001 
        Responder_Cache.algorithms[MAX_LENGTH-1-34]=2// DHE //AlgSupported ffdhr3072 D=384 (bit 1)
        Responder_Cache.algorithms[MAX_LENGTH-1-35]=0// DHE
        Responder_Cache.algorithms[MAX_LENGTH-1-36]=1// DHE //AlgExternal // TCG
        Responder_Cache.algorithms[MAX_LENGTH-1-37]=0// DHE
        Responder_Cache.algorithms[MAX_LENGTH-1-38]=0// DHE 
        Responder_Cache.algorithms[MAX_LENGTH-1-39]=0// DHE
        Responder_Cache.algorithms[MAX_LENGTH-1-40]=3// AEAD
        Responder_Cache.algorithms[MAX_LENGTH-1-41]=33// AEAD // 00100001 
        Responder_Cache.algorithms[MAX_LENGTH-1-42]=2// AEAD // AlgExternal AES 256 (bit 1)
        Responder_Cache.algorithms[MAX_LENGTH-1-43]=0// AEAD
        Responder_Cache.algorithms[MAX_LENGTH-1-44]=1// AEAD //AlgExternal // TCG
        Responder_Cache.algorithms[MAX_LENGTH-1-45]=0// AEAD
        Responder_Cache.algorithms[MAX_LENGTH-1-46]=0// AEAD
        Responder_Cache.algorithms[MAX_LENGTH-1-47]=0// AEAD
        Responder_Cache.algorithms[MAX_LENGTH-1-48]=4// ReqBaseAsymAg
        Responder_Cache.algorithms[MAX_LENGTH-1-49]=33// ReqBaseAsymAg // 00100001
        Responder_Cache.algorithms[MAX_LENGTH-1-50]=32// ReqBaseAsymAg // AlgSupported TPM_ALG_RSASSA_4096 (bit5)
        Responder_Cache.algorithms[MAX_LENGTH-1-51]=0// ReqBaseAsymAg
        Responder_Cache.algorithms[MAX_LENGTH-1-52]=1// ReqBaseAsymAg //AlgExternal // TCG
        Responder_Cache.algorithms[MAX_LENGTH-1-53]=0// ReqBaseAsymAg
        Responder_Cache.algorithms[MAX_LENGTH-1-54]=0// ReqBaseAsymAg
        Responder_Cache.algorithms[MAX_LENGTH-1-55]=0// ReqBaseAsymAg
        Responder_Cache.algorithms[MAX_LENGTH-1-56]=5// KeySchedule
        Responder_Cache.algorithms[MAX_LENGTH-1-57]=33// KeySchedule // 00100001
        Responder_Cache.algorithms[MAX_LENGTH-1-58]=0// KeySchedule // AlgSupported Keyschedule (bit 0)
        Responder_Cache.algorithms[MAX_LENGTH-1-59]=0// KeySchedule
        Responder_Cache.algorithms[MAX_LENGTH-1-60]=1// KeySchedule //AlgExternal // TCG
        Responder_Cache.algorithms[MAX_LENGTH-1-61]=0// KeySchedule
        Responder_Cache.algorithms[MAX_LENGTH-1-62]=0// KeySchedule
        Responder_Cache.algorithms[MAX_LENGTH-1-63]=0// KeySchedule

        // length_reference
        // length_reference={4, 26, 12, 11, 72, 64, 4, 36, 8, 18, 8, 18, 8, 9, 36, 50}//58]
        // length_reference[40]=[4, 30, 42, 53, 125, 189, 193, 229, 237, 255, 263, 281, 289, 298, 334, 392]
                                                            // certificate 21-10, in total 3 rounds
                                                            // H is influnenced
        //certificate chain
        byte nr;
        for (j : 0 .. 1){
            Requester_Cache.certificate_chain[j].Length[0]=21//2//21//8//21//8//21
            for (i : 0 .. H-1){
                // byte nr;	/* pick random value  */
                // do
                // :: nr++		/* randomly increment */
                // :: nr--		/* or decrement       */
                // :: break	/* or stop            */
                // od;
                nr++;
                Requester_Cache.certificate_chain[j].RootHash[i]=nr
            }
            for (i : 0 .. Requester_Cache.certificate_chain[j].Length[0]-1){
                // byte nr;	/* pick random value  */
                // do
                // :: nr++		/* randomly increment */
                // :: nr--		/* or decrement       */
                // :: break	/* or stop            */
                // od;
                nr++;
                Requester_Cache.certificate_chain[j].Certificates[i]=nr
            } 

            Responder_Cache.certificate_chain[j].Length[0]=21//2//21//8//21//8//21
            for (i : 0 .. H-1){
                // byte nr;	/* pick random value  */
                // do
                // :: nr++		/* randomly increment */
                // :: nr--		/* or decrement       */
                // :: break	/* or stop            */
                // od;
                nr++;
                Responder_Cache.certificate_chain[j].RootHash[i]=nr
            }
            for (i : 0 .. Responder_Cache.certificate_chain[j].Length[0]-1){
                // byte nr;	/* pick random value  */
                // do
                // :: nr++		/* randomly increment */
                // :: nr--		/* or decrement       */
                // :: break	/* or stop            */
                // od;
                nr++;
                Responder_Cache.certificate_chain[j].Certificates[i]=nr
            } 
        }

    }

    atomic{
        run Party2_Responder(spdm1Que, spdm1Spd);
        run Party1_Requester(spdm1Que, spdm1Spd);
    }
}
// GET_VERSION 1
ltl p0 {[]! ((version_match == 0) && (signal==CAPABILITIES))};
ltl p1 {[]! ((version_match == 0) && (response_signal==GET_CAPABILITIES))};
ltl p2 {[]! ((version_match == 0) && (signal==ALGORITHMS))};
ltl p3 {[]! ((version_match == 0) && (response_signal==NEGOTIATE_ALGORITHMS))};
ltl p4 {[]! ((version_match == 0) && (signal==DIGESTS))};
ltl p5 {[]! ((version_match == 0) && (response_signal==GET_DIGESTS))};
ltl p6 {[]! ((version_match == 0) && (signal==CERTIFICATE))};
ltl p7 {[]! ((version_match == 0) && (response_signal==GET_CERTIFICATE))};
ltl p8 {[]! ((version_match == 0) && (signal==CHALLENGE_AUTH))};
ltl p9 {[]! ((version_match == 0) && (response_signal==CHALLENGE))};
ltl p10 {[]! ((version_match == 0) && (signal==MEASUREMENTS))};
ltl p11 {[]! ((version_match == 0) && (response_signal==GET_MEASUREMENTS))};
ltl p12 {[]! ((version_match == 0) && (signal==KEY_EXCHANGE_RSP))};
ltl p13 {[]! ((version_match == 0) && (response_signal==KEY_EXCHANGE))};
ltl p14 {[]! ((version_match == 0) && (signal==FINISH_RSP))};
ltl p15 {[]! ((version_match == 0) && (response_signal==FINISH))};
ltl p16 {[]! ((version_match == 0) && (signal==PSK_EXCHANGE_RSP))};
ltl p17 {[]! ((version_match == 0) && (response_signal==PSK_EXCHANGE))};
ltl p18 {[]! ((version_match == 0) && (signal==PSK_FINISH_RSP))};
ltl p19 {[]! ((version_match == 0) && (response_signal==PSK_FINISH))};
ltl p20 {[]! ((version_match == 0) && (signal==KEY_UPDATE_ACK))};
ltl p21 {[]! ((version_match == 0) && (response_signal==KEY_UPDATE))};
ltl p22 {[]! ((version_match == 0) && (signal==ENCAPSULATED_REQUEST))};
ltl p23 {[]! ((version_match == 0) && (response_signal==GET_ENCAPSULATED_REQUEST))};
ltl p24 {[]! ((version_match == 0) && (signal==ENCAPSULATED_RESPONSE_ACK))};
ltl p25 {[]! ((version_match == 0) && (response_signal==DELIVER_ENCAPSULATED_RESPONSE))};
ltl p26 {[]! ((version_match == 0) && (signal==HEARTBEAT_ACK))};
ltl p27 {[]! ((version_match == 0) && (response_signal==HEARTBEAT))};
ltl p28 {[]! ((version_match == 0) && (signal==END_SESSION_ACK))};
ltl p29 {[]! ((version_match == 0) && (response_signal==END_SESSION))};
ltl p30 {[]! ((version_match == 0) && (signal==VENDOR_DEFINED_RESPONSE))};
ltl p31 {[]! ((version_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))};
// GET_VERSION 2, GET_CAPABILITIES 1, NEGOTIATE_ALGORITHMS 3
ltl p32 {[]! (signal==ERROR && param1 == ResponseNotReady && version_match!=1)}; 
ltl p33 {[]! (signal==ERROR && param1 == ResponseNotReady && capabilities_match!=1)}; 
ltl p34 {[]! (signal==ERROR && param1 == ResponseNotReady && algorithms_match!=1)}; 
// NEGOTIATE_ALGORITHMS 1
ltl p35 {[]! ((capabilities_match == 0) && (response_signal==NEGOTIATE_ALGORITHMS))};
// NEGOTIATE_ALGORITHMS 2
// ltl p36 {[]! ((algorithms_match == 0 && capabilities_match == 1) && (response_signal==GET_CAPABILITIES))};
ltl p36 {[]! ((algorithms_match == 0 && capabilities_match == 1) && (response_signal==GET_VERSION) && new_received_flag==1)};
ltl p37 {[]! ((algorithms_match == 0) && (signal==DIGESTS))};
ltl p38 {[]! ((algorithms_match == 0) && (response_signal==GET_DIGESTS))};
ltl p39 {[]! ((algorithms_match == 0) && (signal==CERTIFICATE))};
ltl p40 {[]! ((algorithms_match == 0) && (response_signal==GET_CERTIFICATE))};
ltl p41 {[]! ((algorithms_match == 0) && (signal==CHALLENGE_AUTH))};
ltl p42 {[]! ((algorithms_match == 0) && (response_signal==CHALLENGE))};
ltl p43 {[]! ((algorithms_match == 0) && (signal==MEASUREMENTS))};
ltl p44 {[]! ((algorithms_match == 0) && (response_signal==GET_MEASUREMENTS))};
ltl p45 {[]! ((algorithms_match == 0) && (signal==KEY_EXCHANGE_RSP))};
ltl p46 {[]! ((algorithms_match == 0) && (response_signal==KEY_EXCHANGE))};
ltl p47 {[]! ((algorithms_match == 0) && (signal==FINISH_RSP))};
ltl p48 {[]! ((algorithms_match == 0) && (response_signal==FINISH))};
ltl p49 {[]! ((algorithms_match == 0) && (signal==PSK_EXCHANGE_RSP))};
ltl p50 {[]! ((algorithms_match == 0) && (response_signal==PSK_EXCHANGE))};
ltl p51 {[]! ((algorithms_match == 0) && (signal==PSK_FINISH_RSP))};
ltl p52 {[]! ((algorithms_match == 0) && (response_signal==PSK_FINISH))};
ltl p53 {[]! ((algorithms_match == 0) && (signal==KEY_UPDATE_ACK))};
ltl p54 {[]! ((algorithms_match == 0) && (response_signal==KEY_UPDATE))};
ltl p55 {[]! ((algorithms_match == 0) && (signal==ENCAPSULATED_REQUEST))};
ltl p56 {[]! ((algorithms_match == 0) && (response_signal==GET_ENCAPSULATED_REQUEST))};
ltl p57 {[]! ((algorithms_match == 0) && (signal==ENCAPSULATED_RESPONSE_ACK))};
ltl p58 {[]! ((algorithms_match == 0) && (response_signal==DELIVER_ENCAPSULATED_RESPONSE))};
ltl p59 {[]! ((algorithms_match == 0) && (signal==HEARTBEAT_ACK))};
ltl p60 {[]! ((algorithms_match == 0) && (response_signal==HEARTBEAT))};
ltl p61 {[]! ((algorithms_match == 0) && (signal==END_SESSION_ACK))};
ltl p62 {[]! ((algorithms_match == 0) && (response_signal==END_SESSION))};
ltl p63 {[]! ((algorithms_match == 0) && (signal==VENDOR_DEFINED_RESPONSE))};
ltl p64 {[]! ((algorithms_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))};
// CHALLENGE 1
ltl p66{(<> (signal==CAPABILITIES W signal==ALGORITHMS)) || (<> (signal==CAPABILITIES W signal==ERROR))};
// GET_MEASUREMENTS 1
ltl p70{[]! (response_signal==GET_MEASUREMENTS && (!(MEAS_CAP==1 || MEAS_CAP==2)))}; 
// GET_MEASUREMENTS 2
// GET_MEASUREMENTS 3
ltl p72{[]! ((challenge_auth_match == 0) && (response_signal==GET_MEASUREMENTS))}; 
// ERROR 1
// VENDOR_DEFINED_REQUEST 1
ltl p74{[]! ((version_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))}; 
ltl p75{[]! ((capabilities_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))}; 
ltl p76{[]! ((algorithms_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))}; 
// FINISH 1
// PSK_EXCHAGE 7
ltl p78{[]! ((version_match == 0) && (response_signal==PSK_EXCHANGE))}; 
// PSK_EXCHAGE 11


// NEGOTIATE ALGORITHMS 8
ltl p79 {[]! ((MeasurementSpecificationSel!=0)&&(MeasurementSpecificationSel!=1)&&\
                (MeasurementSpecificationSel!=2)&&(MeasurementSpecificationSel!=4)&&\
                (MeasurementSpecificationSel!=8)&&(MeasurementSpecificationSel!=16)&&\
                (MeasurementSpecificationSel!=32)&&(MeasurementSpecificationSel!=64)&&\
                (MeasurementSpecificationSel!=128))};

// NEGOTIATE ALGORITHMS 9
// ltl p80 {[]! (ceil(log2(BaseAsymSel)) != floor(log2(BaseAsymSel)) && BaseAsymSel!=0)}
// ltl p81 {[]! (ceil(log2(BaseHashSel)) != floor(log2(BaseHashSel)) && BaseHashSel!=0)}

ltl p80 {[]! (BaseAsymSel!=0 && BaseAsymSel!=1 && BaseAsymSel!=2 \
                && BaseAsymSel!=4 && BaseAsymSel!=8 && BaseAsymSel!=16\
                && BaseAsymSel!=32 && BaseAsymSel!=64 && BaseAsymSel!=128\
                && BaseAsymSel!=256 && BaseAsymSel!=512 && BaseAsymSel!=1024\
                && BaseAsymSel!=2048 && BaseAsymSel!=4096 && BaseAsymSel!=8192\
                && BaseAsymSel!=16384 && BaseAsymSel!=32768 && BaseAsymSel!=65536)}
ltl p81 {[]! (BaseHashSel!=0 && BaseHashSel!=1 && BaseHashSel!=2 \
                && BaseHashSel!=4 && BaseHashSel!=8 && BaseHashSel!=16\
                && BaseHashSel!=32 && BaseHashSel!=64 && BaseHashSel!=128\
                && BaseHashSel!=256 && BaseHashSel!=512 && BaseHashSel!=1024\
                && BaseHashSel!=2048 && BaseHashSel!=4096 && BaseHashSel!=8192\
                && BaseHashSel!=16384 && BaseHashSel!=32768 && BaseHashSel!=65536)}

// GET_DIGESTS 14
ltl p82 {[]! (signal==DIGESTS && ((param2 & 1==1 && Responder_Cache.certificate_chain[0].Length[0]==0)||\
         (param2  &2==1&&Responder_Cache.certificate_chain[1].Length[0]==0)||\
         (param2 & 4==1&&Responder_Cache.certificate_chain[2].Length[0]==0)||\
         (param2 & 8==1&&Responder_Cache.certificate_chain[3].Length[0]==0)||\
         (param2 & 16==1&&Responder_Cache.certificate_chain[4].Length[0]==0)||\
         (param2 & 32==1&&Responder_Cache.certificate_chain[5].Length[0]==0)||\
         (param2 & 64==1&&Responder_Cache.certificate_chain[6].Length[0]==0)||\
         (param2 & 128==1&&Responder_Cache.certificate_chain[7].Length[0]==0))\
        )};
// ltl p83 {[]! (count_1(Param2)!=count_not0(Digest))};

// GET_VERSION
ltl p83 {[]! (version_match==1 && max_version<1)}
