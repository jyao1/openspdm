#include "SPDMWrapper.h"
#include "EverParse.h"
#include "SPDM.h"
void
SPDMEverParseError(char *x, char *y, char *z);
static char *
SPDMStructNameOfErr(uint64_t err)
{
    switch (EverParseFieldIdOfResult(err))
    {
    case 1:
        return "_GET_VERSION_REQUEST_MESSAGE";
    case 2:
        return "_GET_VERSION_REQUEST_MESSAGE";
    case 3:
        return "_GET_VERSION_REQUEST_MESSAGE";
    case 4:
        return "_GET_VERSION_REQUEST_MESSAGE";
    case 5:
        return "_VersionNumberEntry";
    case 6:
        return "_VersionNumberEntry";
    case 7:
        return "_VersionNumberEntry";
    case 8:
        return "_VersionNumberEntry";
    case 9:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 10:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 11:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 12:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 13:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 14:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 15:
        return "_SUCCESSFUL_VERSION_RESPONSE_MESSAGE";
    case 16:
        return "_REQUESTER_FLAG";
    case 17:
        return "_REQUESTER_FLAG";
    case 18:
        return "_REQUESTER_FLAG";
    case 19:
        return "_REQUESTER_FLAG";
    case 20:
        return "_REQUESTER_FLAG";
    case 21:
        return "_REQUESTER_FLAG";
    case 22:
        return "_REQUESTER_FLAG";
    case 23:
        return "_REQUESTER_FLAG";
    case 24:
        return "_REQUESTER_FLAG";
    case 25:
        return "_REQUESTER_FLAG";
    case 26:
        return "_REQUESTER_FLAG";
    case 27:
        return "_REQUESTER_FLAG";
    case 28:
        return "_REQUESTER_FLAG";
    case 29:
        return "_REQUESTER_FLAG";
    case 30:
        return "_REQUESTER_FLAG";
    case 31:
        return "_REQUESTER_FLAG";
    case 32:
        return "_REQUESTER_FLAG";
    case 33:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 34:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 35:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 36:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 37:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 38:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 39:
        return "_GET_CPABILITIES_REQUEST_MESSAGE";
    case 40:
        return "_RESPONDER_FLAG";
    case 41:
        return "_RESPONDER_FLAG";
    case 42:
        return "_RESPONDER_FLAG";
    case 43:
        return "_RESPONDER_FLAG";
    case 44:
        return "_RESPONDER_FLAG";
    case 45:
        return "_RESPONDER_FLAG";
    case 46:
        return "_RESPONDER_FLAG";
    case 47:
        return "_RESPONDER_FLAG";
    case 48:
        return "_RESPONDER_FLAG";
    case 49:
        return "_RESPONDER_FLAG";
    case 50:
        return "_RESPONDER_FLAG";
    case 51:
        return "_RESPONDER_FLAG";
    case 52:
        return "_RESPONDER_FLAG";
    case 53:
        return "_RESPONDER_FLAG";
    case 54:
        return "_RESPONDER_FLAG";
    case 55:
        return "_RESPONDER_FLAG";
    case 56:
        return "_RESPONDER_FLAG";
    case 57:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 58:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 59:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 60:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 61:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 62:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 63:
        return "_SUCCESSFUL_CPABILITIES_RESPONSE_MESSAGE";
    case 64:
        return "_EXTENDED_ALGORITHM_FIELD";
    case 65:
        return "_EXTENDED_ALGORITHM_FIELD";
    case 66:
        return "_EXTENDED_ALGORITHM_FIELD";
    case 67:
        return "_DHE";
    case 68:
        return "_DHE";
    case 69:
        return "_DHE";
    case 70:
        return "_DHE";
    case 71:
        return "_AEAD";
    case 72:
        return "_AEAD";
    case 73:
        return "_AEAD";
    case 74:
        return "_AEAD";
    case 75:
        return "_ReqBaseAsymAlg";
    case 76:
        return "_ReqBaseAsymAlg";
    case 77:
        return "_ReqBaseAsymAlg";
    case 78:
        return "_ReqBaseAsymAlg";
    case 79:
        return "_KeySchedule";
    case 80:
        return "_KeySchedule";
    case 81:
        return "_KeySchedule";
    case 82:
        return "_KeySchedule";
    case 83:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 84:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 85:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 86:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 87:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 88:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 89:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 90:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 91:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 92:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 93:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 94:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 95:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 96:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 97:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 98:
        return "_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE";
    case 99:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 100:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 101:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 102:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 103:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 104:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 105:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 106:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 107:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 108:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 109:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 110:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 111:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 112:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 113:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 114:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 115:
        return "_SUCCESSFUL_ALGORITHMS_RESPONSE_MESSAGE";
    case 116:
        return "_GET_DIGESTS_REQUEST_MESSAGE";
    case 117:
        return "_GET_DIGESTS_REQUEST_MESSAGE";
    case 118:
        return "_GET_DIGESTS_REQUEST_MESSAGE";
    case 119:
        return "_GET_DIGESTS_REQUEST_MESSAGE";
    case 120:
        return "_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE";
    case 121:
        return "_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE";
    case 122:
        return "_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE";
    case 123:
        return "_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE";
    case 124:
        return "_SUCCESSFUL_DIGESTS_RESPONSE_MESSAGE";
    case 125:
        return "_GET_CERTIFICATE_REQUEST_MESSAGE";
    case 126:
        return "_GET_CERTIFICATE_REQUEST_MESSAGE";
    case 127:
        return "_GET_CERTIFICATE_REQUEST_MESSAGE";
    case 128:
        return "_GET_CERTIFICATE_REQUEST_MESSAGE";
    case 129:
        return "_GET_CERTIFICATE_REQUEST_MESSAGE";
    case 130:
        return "_GET_CERTIFICATE_REQUEST_MESSAGE";
    case 131:
        return "_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE";
    case 132:
        return "_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE";
    case 133:
        return "_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE";
    case 134:
        return "_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE";
    case 135:
        return "_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE";
    case 136:
        return "_SUCCESSFUL_CERTIFICATE_RESPONSE_MESSAGE";
    case 137:
        return "_CHALLENGE_REQUEST_MESSAGE";
    case 138:
        return "_CHALLENGE_REQUEST_MESSAGE";
    case 139:
        return "_CHALLENGE_REQUEST_MESSAGE";
    case 140:
        return "_CHALLENGE_REQUEST_MESSAGE";
    case 141:
        return "_CHALLENGE_REQUEST_MESSAGE";
    case 142:
        return "_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE";
    case 143:
        return "_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE";
    case 144:
        return "_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE";
    case 145:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 146:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 147:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 148:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 149:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 150:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 151:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 152:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 153:
        return "_SUCCESSFUL_CHALLENGE_AUTH_RESPONSE_MESSAGE";
    case 154:
        return "_GET_MEASUREMENTS_REQUEST_MESSAGE";
    case 155:
        return "_GET_MEASUREMENTS_REQUEST_MESSAGE";
    case 156:
        return "_GET_MEASUREMENTS_REQUEST_MESSAGE";
    case 157:
        return "_GET_MEASUREMENTS_REQUEST_MESSAGE";
    case 158:
        return "_GET_MEASUREMENTS_REQUEST_MESSAGE";
    case 159:
        return "_GET_MEASUREMENTS_REQUEST_MESSAGE";
    case 160:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 161:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 162:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 163:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 164:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 165:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 166:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 167:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 168:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 169:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 170:
        return "_SUCCESSFUL_MEASUREMENTS_RESPONSE_MESSAGE";
    case 171:
        return "_ERROR_RESPONSE_MESSAGE";
    case 172:
        return "_ERROR_RESPONSE_MESSAGE";
    case 173:
        return "_ERROR_RESPONSE_MESSAGE";
    case 174:
        return "_ERROR_RESPONSE_MESSAGE";
    case 175:
        return "_ERROR_RESPONSE_MESSAGE";
    case 176:
        return "_RESPONSENOTREADY_EXTENDED_ERROR_DATA";
    case 177:
        return "_RESPONSENOTREADY_EXTENDED_ERROR_DATA";
    case 178:
        return "_RESPONSENOTREADY_EXTENDED_ERROR_DATA";
    case 179:
        return "_RESPONSENOTREADY_EXTENDED_ERROR_DATA";
    case 180:
        return "_EXTENDERRORDATA_FOR_VENDOR";
    case 181:
        return "_EXTENDERRORDATA_FOR_VENDOR";
    case 182:
        return "_EXTENDERRORDATA_FOR_VENDOR";
    case 183:
        return "_RESPOND_IF_READY_REQUEST_MESSAGE";
    case 184:
        return "_RESPOND_IF_READY_REQUEST_MESSAGE";
    case 185:
        return "_RESPOND_IF_READY_REQUEST_MESSAGE";
    case 186:
        return "_RESPOND_IF_READY_REQUEST_MESSAGE";
    case 187:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 188:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 189:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 190:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 191:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 192:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 193:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 194:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 195:
        return "_VENDOR_DEFINED_REQUEST_REQUEST_MESSAGE";
    case 196:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 197:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 198:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 199:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 200:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 201:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 202:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 203:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 204:
        return "_VENDOR_DEFINED_RESPONSE_RESPONSE_MESSAGE";
    case 205:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 206:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 207:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 208:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 209:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 210:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 211:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 212:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 213:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 214:
        return "_KEY_EXCHANGE_REQUEST_MESSAGE";
    case 215:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 216:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 217:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 218:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 219:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 220:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 221:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 222:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 223:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 224:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 225:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 226:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 227:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 228:
        return "_SUCCESSFUL_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 229:
        return "_FINISH_REQUEST_MESSAGE";
    case 230:
        return "_FINISH_REQUEST_MESSAGE";
    case 231:
        return "_FINISH_REQUEST_MESSAGE";
    case 232:
        return "_FINISH_REQUEST_MESSAGE";
    case 233:
        return "_FINISH_REQUEST_MESSAGE";
    case 234:
        return "_FINISH_REQUEST_MESSAGE";
    case 235:
        return "_SUCCESSFUL_FINISH_RESPONSE_MESSAGE";
    case 236:
        return "_SUCCESSFUL_FINISH_RESPONSE_MESSAGE";
    case 237:
        return "_SUCCESSFUL_FINISH_RESPONSE_MESSAGE";
    case 238:
        return "_SUCCESSFUL_FINISH_RESPONSE_MESSAGE";
    case 239:
        return "_SUCCESSFUL_FINISH_RESPONSE_MESSAGE";
    case 240:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 241:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 242:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 243:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 244:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 245:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 246:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 247:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 248:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 249:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 250:
        return "_PSK_EXCHANGE_REQUEST_MESSAGE";
    case 251:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 252:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 253:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 254:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 255:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 256:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 257:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 258:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 259:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 260:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 261:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 262:
        return "_PSK_EXCHANGE_RSP_RESPONSE_MESSAGE";
    case 263:
        return "_PSK_FINISH_REQUEST_MESSAGE";
    case 264:
        return "_PSK_FINISH_REQUEST_MESSAGE";
    case 265:
        return "_PSK_FINISH_REQUEST_MESSAGE";
    case 266:
        return "_PSK_FINISH_REQUEST_MESSAGE";
    case 267:
        return "_PSK_FINISH_REQUEST_MESSAGE";
    case 268:
        return "_SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE";
    case 269:
        return "_SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE";
    case 270:
        return "_SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE";
    case 271:
        return "_SUCCESSFUL_PSK_FINISH_RSP_RESPONSE_MESSAGE";
    case 272:
        return "_HEARTBEAT_REQUEST_MESSAGE";
    case 273:
        return "_HEARTBEAT_REQUEST_MESSAGE";
    case 274:
        return "_HEARTBEAT_REQUEST_MESSAGE";
    case 275:
        return "_HEARTBEAT_REQUEST_MESSAGE";
    case 276:
        return "_HEARTBEAT_ACK_RESPONSE_MESSAGE";
    case 277:
        return "_HEARTBEAT_ACK_RESPONSE_MESSAGE";
    case 278:
        return "_HEARTBEAT_ACK_RESPONSE_MESSAGE";
    case 279:
        return "_HEARTBEAT_ACK_RESPONSE_MESSAGE";
    case 280:
        return "_KEY_UPDATE_REQUEST_MESSAGE";
    case 281:
        return "_KEY_UPDATE_REQUEST_MESSAGE";
    case 282:
        return "_KEY_UPDATE_REQUEST_MESSAGE";
    case 283:
        return "_KEY_UPDATE_REQUEST_MESSAGE";
    case 284:
        return "_KEY_UPDATE_ACK_RESPONSE_MESSAGE";
    case 285:
        return "_KEY_UPDATE_ACK_RESPONSE_MESSAGE";
    case 286:
        return "_KEY_UPDATE_ACK_RESPONSE_MESSAGE";
    case 287:
        return "_KEY_UPDATE_ACK_RESPONSE_MESSAGE";
    case 288:
        return "_GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE";
    case 289:
        return "_GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE";
    case 290:
        return "_GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE";
    case 291:
        return "_GET_ENCAPSULATED_REQUEST_REQUEST_MESSAGE";
    case 292:
        return "_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE";
    case 293:
        return "_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE";
    case 294:
        return "_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE";
    case 295:
        return "_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE";
    case 296:
        return "_ENCAPSULATED_REQUEST_RESPONSE_MESSAGE";
    case 297:
        return "_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE";
    case 298:
        return "_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE";
    case 299:
        return "_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE";
    case 300:
        return "_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE";
    case 301:
        return "_DELIVER_ENCAPSULATED_RESPONSE_REQUEST_MESSAGE";
    case 302:
        return "_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE";
    case 303:
        return "_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE";
    case 304:
        return "_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE";
    case 305:
        return "_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE";
    case 306:
        return "_ENCAPSULATED_RESPONSE_ACK_RESPONSE_MESSAGE";
    case 307:
        return "_END_SESSION_REQUEST_MESSAGE";
    case 308:
        return "_END_SESSION_REQUEST_MESSAGE";
    case 309:
        return "_END_SESSION_REQUEST_MESSAGE";
    case 310:
        return "_END_SESSION_REQUEST_MESSAGE";
    case 311:
        return "_END_SESSION_ACK_RESPONSE_MESSAGE";
    case 312:
        return "_END_SESSION_ACK_RESPONSE_MESSAGE";
    case 313:
        return "_END_SESSION_ACK_RESPONSE_MESSAGE";
    case 314:
        return "_END_SESSION_ACK_RESPONSE_MESSAGE";
    default:
        return "";
    }
}

static char *
SPDMFieldNameOfErr(uint64_t err)
{
    switch (EverParseFieldIdOfResult(err))
    {
    case 1:
        return "SPDMVersion";
    case 2:
        return "RequestResponseCode";
    case 3:
        return "Param1";
    case 4:
        return "Param2";
    case 5:
        return "Alpha";
    case 6:
        return "UpdateVersionNumber";
    case 7:
        return "MinorVersion";
    case 8:
        return "MajorVersion";
    case 9:
        return "SPDMVersion";
    case 10:
        return "RequestResponseCode";
    case 11:
        return "Param1";
    case 12:
        return "Param2";
    case 13:
        return "Reserved";
    case 14:
        return "VersionNumberEntryCount";
    case 15:
        return "VersionNumberEntries";
    case 16:
        return "Reserved";
    case 17:
        return "CERT_CAP";
    case 18:
        return "CHAL_CAP";
    case 19:
        return "MEAS_CAP";
    case 20:
        return "MEAS_FRESH_CAP";
    case 21:
        return "ENCRYPT_CAP";
    case 22:
        return "MAC_CAP";
    case 23:
        return "MUT_AUTH_CAP";
    case 24:
        return "KEY_EX_CAP";
    case 25:
        return "PSK_CAP";
    case 26:
        return "ENCAP_CAP";
    case 27:
        return "HBEAT_CAP";
    case 28:
        return "KEY_UPD_CAP";
    case 29:
        return "HANDSHAKE_IN_THE_CLEAR_CAP";
    case 30:
        return "PUB_KEY_ID_CAP";
    case 31:
        return "Reserved1";
    case 32:
        return "Reserved2";
    case 33:
        return "SPDMVersion";
    case 34:
        return "RequestResponseCode";
    case 35:
        return "Param1";
    case 36:
        return "Param2";
    case 37:
        return "Reserved";
    case 38:
        return "CTExponent";
    case 39:
        return "Reserved1";
    case 40:
        return "CACHE_CAP";
    case 41:
        return "CERT_CAP";
    case 42:
        return "CHAL_CAP";
    case 43:
        return "MEAS_CAP";
    case 44:
        return "MEAS_FRESH_CAP";
    case 45:
        return "ENCRYPT_CAP";
    case 46:
        return "MAC_CAP";
    case 47:
        return "MUT_AUTH_CAP";
    case 48:
        return "KEY_EX_CAP";
    case 49:
        return "PSK_CAP";
    case 50:
        return "ENCAP_CAP";
    case 51:
        return "HBEAT_CAP";
    case 52:
        return "KEY_UPD_CAP";
    case 53:
        return "HANDSHAKE_IN_THE_CLEAR_CAP";
    case 54:
        return "PUB_KEY_ID_CAP";
    case 55:
        return "Reserved1";
    case 56:
        return "Reserved2";
    case 57:
        return "SPDMVersion";
    case 58:
        return "RequestResponseCode";
    case 59:
        return "Param1";
    case 60:
        return "Param2";
    case 61:
        return "Reserved";
    case 62:
        return "CTExponent";
    case 63:
        return "Reserved1";
    case 64:
        return "RegistryID";
    case 65:
        return "Reserved";
    case 66:
        return "AlgorithmID";
    case 67:
        return "AlgType";
    case 68:
        return "AlgCount";
    case 69:
        return "AlgSupported";
    case 70:
        return "AlgExternal";
    case 71:
        return "AlgType";
    case 72:
        return "AlgCount";
    case 73:
        return "AlgSupported";
    case 74:
        return "AlgExternal";
    case 75:
        return "AlgType";
    case 76:
        return "AlgCount";
    case 77:
        return "AlgSupported";
    case 78:
        return "AlgExternal";
    case 79:
        return "AlgType";
    case 80:
        return "AlgCount";
    case 81:
        return "AlgSupported";
    case 82:
        return "AlgExternal";
    case 83:
        return "SPDMVersion";
    case 84:
        return "RequestResponseCode";
    case 85:
        return "Param1";
    case 86:
        return "Param2";
    case 87:
        return "Length";
    case 88:
        return "MeasurementSpecification";
    case 89:
        return "Reserved";
    case 90:
        return "BaseAsymAlgo";
    case 91:
        return "BaseHashAlgo";
    case 92:
        return "Reserved1";
    case 93:
        return "ExtAsymCount";
    case 94:
        return "ExtHashCount";
    case 95:
        return "Reserved2";
    case 96:
        return "ExtAsym";
    case 97:
        return "ExtHash";
    case 98:
        return "ReqAlgStruct";
    case 99:
        return "SPDMVersion";
    case 100:
        return "RequestResponseCode";
    case 101:
        return "Param1";
    case 102:
        return "Param2";
    case 103:
        return "Length";
    case 104:
        return "MeasurementSpecificationSel";
    case 105:
        return "Reserved";
    case 106:
        return "MeasurementHashAlgo";
    case 107:
        return "BaseAsymSel";
    case 108:
        return "BaseHashSel";
    case 109:
        return "Reserved1";
    case 110:
        return "ExtAsymSelCount";
    case 111:
        return "ExtHashSelCount";
    case 112:
        return "Reserved2";
    case 113:
        return "ExtAsym";
    case 114:
        return "ExtHash";
    case 115:
        return "ReqAlgStruct";
    case 116:
        return "SPDMVersion";
    case 117:
        return "RequestResponseCode";
    case 118:
        return "Param1";
    case 119:
        return "Param2";
    case 120:
        return "SPDMVersion";
    case 121:
        return "RequestResponseCode";
    case 122:
        return "Param1";
    case 123:
        return "Param2";
    case 124:
        return "Digest";
    case 125:
        return "SPDMVersion";
    case 126:
        return "RequestResponseCode";
    case 127:
        return "Param1";
    case 128:
        return "Param2";
    case 129:
        return "Offset";
    case 130:
        return "Length";
    case 131:
        return "SPDMVersion";
    case 132:
        return "RequestResponseCode";
    case 133:
        return "Param1";
    case 134:
        return "Param2";
    case 135:
        return "PortionLength";
    case 136:
        return "CertChain";
    case 137:
        return "SPDMVersion";
    case 138:
        return "RequestResponseCode";
    case 139:
        return "Param1";
    case 140:
        return "Param2";
    case 141:
        return "Nonce";
    case 142:
        return "SlotID";
    case 143:
        return "Reserved";
    case 144:
        return "BasicMutAuthReq";
    case 145:
        return "SPDMVersion";
    case 146:
        return "RequestResponseCode";
    case 147:
        return "Param2";
    case 148:
        return "CertChainHash";
    case 149:
        return "Nonce";
    case 150:
        return "MeasurementSummaryHash";
    case 151:
        return "OpaqueLength";
    case 152:
        return "OpaqueData";
    case 153:
        return "Signature";
    case 154:
        return "SPDMVersion";
    case 155:
        return "RequestResponseCode";
    case 156:
        return "Param1";
    case 157:
        return "Param2";
    case 158:
        return "Nonce";
    case 159:
        return "SlotIDParam";
    case 160:
        return "SPDMVersion";
    case 161:
        return "RequestResponseCode";
    case 162:
        return "Param1";
    case 163:
        return "Param2";
    case 164:
        return "NumberOfBlocks";
    case 165:
        return "MeasurementRecordLength";
    case 166:
        return "MeasurementRecord";
    case 167:
        return "Nonce";
    case 168:
        return "OpaqueLength";
    case 169:
        return "OpaqueData";
    case 170:
        return "Signature";
    case 171:
        return "SPDMVersion";
    case 172:
        return "RequestResponseCode";
    case 173:
        return "Param1";
    case 174:
        return "Param2";
    case 175:
        return "ExtendedErrorData";
    case 176:
        return "RDTExponent";
    case 177:
        return "RequestCode";
    case 178:
        return "Token";
    case 179:
        return "RDTM";
    case 180:
        return "Len";
    case 181:
        return "VendorID";
    case 182:
        return "OpaqueErrorData";
    case 183:
        return "SPDMVersion";
    case 184:
        return "RequestResponseCode";
    case 185:
        return "Param1";
    case 186:
        return "Param2";
    case 187:
        return "SPDMVersion";
    case 188:
        return "RequestResponseCode";
    case 189:
        return "Param1";
    case 190:
        return "Param2";
    case 191:
        return "StandardID";
    case 192:
        return "Len";
    case 193:
        return "VendorID";
    case 194:
        return "ReqLength";
    case 195:
        return "VendorDefinedReqPayload";
    case 196:
        return "SPDMVersion";
    case 197:
        return "RequestResponseCode";
    case 198:
        return "Param1";
    case 199:
        return "Param2";
    case 200:
        return "StandardID";
    case 201:
        return "Len";
    case 202:
        return "VendorID";
    case 203:
        return "RespLength";
    case 204:
        return "VendorDefinedRespPayload";
    case 205:
        return "SPDMVersion";
    case 206:
        return "RequestResponseCode";
    case 207:
        return "Param1";
    case 208:
        return "Param2";
    case 209:
        return "ReqSessionID";
    case 210:
        return "Reserved";
    case 211:
        return "RandomData";
    case 212:
        return "ExchangeData";
    case 213:
        return "OpaqueDataLength";
    case 214:
        return "OpaqueData";
    case 215:
        return "SPDMVersion";
    case 216:
        return "RequestResponseCode";
    case 217:
        return "Param1";
    case 218:
        return "Param2";
    case 219:
        return "ReqSessionID";
    case 220:
        return "MutAuthRequested";
    case 221:
        return "SlotIDParam";
    case 222:
        return "RandomData";
    case 223:
        return "ExchangeData";
    case 224:
        return "MeasurementSummaryHash";
    case 225:
        return "OpaqueDataLength";
    case 226:
        return "OpaqueData";
    case 227:
        return "Signature";
    case 228:
        return "ResponderVerifyData";
    case 229:
        return "SPDMVersion";
    case 230:
        return "RequestResponseCode";
    case 231:
        return "Param1";
    case 232:
        return "Param2";
    case 233:
        return "Signature";
    case 234:
        return "RequesterVerifyData";
    case 235:
        return "SPDMVersion";
    case 236:
        return "RequestResponseCode";
    case 237:
        return "Param1";
    case 238:
        return "Param2";
    case 239:
        return "RequesterVerifyData";
    case 240:
        return "SPDMVersion";
    case 241:
        return "RequestResponseCode";
    case 242:
        return "Param1";
    case 243:
        return "Param2";
    case 244:
        return "ReqSessionID";
    case 245:
        return "P";
    case 246:
        return "R";
    case 247:
        return "OpaqueDataLength";
    case 248:
        return "PSKHint";
    case 249:
        return "RequesterContext";
    case 250:
        return "OpaqueData";
    case 251:
        return "SPDMVersion";
    case 252:
        return "RequestResponseCode";
    case 253:
        return "Param1";
    case 254:
        return "Param2";
    case 255:
        return "RspSessionID";
    case 256:
        return "Reserved";
    case 257:
        return "Q";
    case 258:
        return "OpaqueDataLength";
    case 259:
        return "MeasurementSummaryHash";
    case 260:
        return "ResponderContext";
    case 261:
        return "OpaqueData";
    case 262:
        return "ResponderVerifyData";
    case 263:
        return "SPDMVersion";
    case 264:
        return "RequestResponseCode";
    case 265:
        return "Param1";
    case 266:
        return "Param2";
    case 267:
        return "RequesterVerifyData";
    case 268:
        return "SPDMVersion";
    case 269:
        return "RequestResponseCode";
    case 270:
        return "Param1";
    case 271:
        return "Param2";
    case 272:
        return "SPDMVersion";
    case 273:
        return "RequestResponseCode";
    case 274:
        return "Param1";
    case 275:
        return "Param2";
    case 276:
        return "SPDMVersion";
    case 277:
        return "RequestResponseCode";
    case 278:
        return "Param1";
    case 279:
        return "Param2";
    case 280:
        return "SPDMVersion";
    case 281:
        return "RequestResponseCode";
    case 282:
        return "Param1";
    case 283:
        return "Param2";
    case 284:
        return "SPDMVersion";
    case 285:
        return "RequestResponseCode";
    case 286:
        return "Param1";
    case 287:
        return "Param2";
    case 288:
        return "SPDMVersion";
    case 289:
        return "RequestResponseCode";
    case 290:
        return "Param1";
    case 291:
        return "Param2";
    case 292:
        return "SPDMVersion";
    case 293:
        return "RequestResponseCode";
    case 294:
        return "Param1";
    case 295:
        return "Param2";
    case 296:
        return "EncapsulatedRequest";
    case 297:
        return "SPDMVersion";
    case 298:
        return "RequestResponseCode";
    case 299:
        return "Param1";
    case 300:
        return "Param2";
    case 301:
        return "EncapsulatedResponse";
    case 302:
        return "SPDMVersion";
    case 303:
        return "RequestResponseCode";
    case 304:
        return "Param1";
    case 305:
        return "Param2";
    case 306:
        return "EncapsulatedRequest";
    case 307:
        return "SPDMVersion";
    case 308:
        return "RequestResponseCode";
    case 309:
        return "Param1";
    case 310:
        return "Param2";
    case 311:
        return "SPDMVersion";
    case 312:
        return "RequestResponseCode";
    case 313:
        return "Param1";
    case 314:
        return "Param2";
    default:
        return "";
    }
}

BOOLEAN
SpdmCheckGetVersionRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateGetVersionRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckVersionNumberEntry(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateVersionNumberEntry(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulVersionResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulVersionResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckRequesterFlag(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateRequesterFlag(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckGetCpabilitiesRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateGetCpabilitiesRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckResponderFlag(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateResponderFlag(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulCpabilitiesResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulCpabilitiesResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckExtendedAlgorithmField(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateExtendedAlgorithmField(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckDhe(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateDhe(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckAead(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateAead(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckReqBaseAsymAlg(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateReqBaseAsymAlg(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckKeySchedule(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateKeySchedule(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckNegotiateAlgorithmsRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateNegotiateAlgorithmsRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulAlgorithmsResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulAlgorithmsResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckGetDigestsRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateGetDigestsRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulDigestsResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulDigestsResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckGetCertificateRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateGetCertificateRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulCertificateResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulCertificateResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckChallengeRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateChallengeRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckChallengeAuthResponseAttribute(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateChallengeAuthResponseAttribute(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulChallengeAuthResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulChallengeAuthResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckGetMeasurementsRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateGetMeasurementsRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulMeasurementsResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulMeasurementsResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckErrorResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateErrorResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckResponsenotreadyExtendedErrorData(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateResponsenotreadyExtendedErrorData(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckExtenderrordataForVendor(
    uint32_t ___Variable,
    uint8_t *base,
    uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateExtenderrordataForVendor(___Variable, s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckRespondIfReadyRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateRespondIfReadyRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckVendorDefinedRequestRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateVendorDefinedRequestRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckVendorDefinedResponseResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateVendorDefinedResponseResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckKeyExchangeRequestMessage(uint32_t ___D, uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateKeyExchangeRequestMessage(___D, s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulKeyExchangeRspResponseMessage(
    uint32_t ___D,
    uint8_t *base,
    uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result =
        SpdmValidateSuccessfulKeyExchangeRspResponseMessage(___D, s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckFinishRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateFinishRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulFinishResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulFinishResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckPskExchangeRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidatePskExchangeRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckPskExchangeRspResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidatePskExchangeRspResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckPskFinishRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidatePskFinishRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckSuccessfulPskFinishRspResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateSuccessfulPskFinishRspResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckHeartbeatRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateHeartbeatRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckHeartbeatAckResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateHeartbeatAckResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckKeyUpdateRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateKeyUpdateRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckKeyUpdateAckResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateKeyUpdateAckResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckGetEncapsulatedRequestRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateGetEncapsulatedRequestRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckEncapsulatedRequestResponseMessage(
    uint32_t ___Variable,
    uint8_t *base,
    uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result =
        SpdmValidateEncapsulatedRequestResponseMessage(___Variable, s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckDeliverEncapsulatedResponseRequestMessage(
    uint32_t ___Variable,
    uint8_t *base,
    uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateDeliverEncapsulatedResponseRequestMessage(
        ___Variable, s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckEncapsulatedResponseAckResponseMessage(
    uint32_t ___Variable,
    uint8_t *base,
    uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result =
        SpdmValidateEncapsulatedResponseAckResponseMessage(___Variable, s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckEndSessionRequestMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateEndSessionRequestMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
SpdmCheckEndSessionAckResponseMessage(uint8_t *base, uint32_t len)
{
    InputBuffer s;
    s.base = base;
    s.len = len;
    uint64_t result = SpdmValidateEndSessionAckResponseMessage(s, 0);
    if (EverParseResultIsError(result))
    {
        SPDMEverParseError(
            SPDMStructNameOfErr(result),
            SPDMFieldNameOfErr(result),
            EverParseErrorReasonOfResult(result));
        return FALSE;
    }
    return TRUE;
}
