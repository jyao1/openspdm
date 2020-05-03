A sample implementation for SPDM specification.

SPDM requester lib and responder lib.

Code can run in UEFI emulation env.

Code can run as OS application (one responder as server and one initiator as client)

=============

feature implemented:
0) both requester and responder
1) crypto: SHA256, HMAC_SHA256, RSASSA, FFDHE, ECDHE, AEAD-AES-GCM
2) GET_VERSION, GET_CAPABILITY, NEGOTIATE_ALGORITHM
3) GET_DIGEST, GET_CERTIFICATE, CHALLENGE
4) GET_MEASUREMENT
5) KEY_EXCHANGE, FINISH
6) PSK_EXCHANGE, PSK_FINISH
7) END_SESSION
8) send/receive encrypted message in a session

feature not implemented:
0) thorough testing (include robustness test and fuzzing test)
1) multiple algorithm (SHA2, RSASSA-PSS, ECDSA, AEAD-ChaCha20Poly1305, etc)
2) multiple cert chain
3) multiple session
4) mutual authentication (ENCAPSULATED message)
5) HEARTBEAT
6) KEY_UPDATE

============

This code is to show the communciation flow between a SPDM requester and a SPDM responder.
The code is not in production quality.
Please do not use it in any production before a full test.

