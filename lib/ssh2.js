var Util   = require("util"),
    Events = require("events"),
    Net    = require("net"),
    Utils  = require("./util"),
    
    Strtok = require("./../support/node-strtok/lib/strtok"),
    BufferReader = require("./../support/BufferReader").BufferReader;

//Execution Bitmap Masks
exports.NET_SSH2_MASK_CONSTRUCTOR = 0x00000001;
exports.NET_SSH2_MASK_LOGIN       = 0x00000002;

/**
 * Channel constants
 *
 * RFC4254 refers not to client and server channels but rather to sender and recipient channels.  we don't refer
 * to them in that way because RFC4254 toggles the meaning. the client sends a SSH_MSG_CHANNEL_OPEN message with
 * a sender channel and the server sends a SSH_MSG_CHANNEL_OPEN_CONFIRMATION in response, with a sender and a
 * recepient channel.  at first glance, you might conclude that SSH_MSG_CHANNEL_OPEN_CONFIRMATION's sender channel
 * would be the same thing as SSH_MSG_CHANNEL_OPEN's sender channel, but it's not, per this snipet:
 *     The 'recipient channel' is the channel number given in the original
 *     open request, and 'sender channel' is the channel number allocated by
 *     the other side.
 *
 * @see ssh2._send_channel_packet()
 * @see ssh2._get_channel_packet()
 */
exports.NET_SSH2_CHANNEL_EXEC = 0; // PuTTy uses 0x100

/**
 * Returns the message numbers
 */
exports.NET_SSH2_LOG_SIMPLE = 1;
/**
 * Returns the message content
 */
exports.NET_SSH2_LOG_COMPLEX = 2;

// message_numbers
exports.NET_SSH2_MSG_DISCONNECT = 1;
exports.NET_SSH2_MSG_IGNORE = 2;
exports.NET_SSH2_MSG_UNIMPLEMENTED = 3;
exports.NET_SSH2_MSG_DEBUG = 4;
exports.NET_SSH2_MSG_SERVICE_REQUEST = 5;
exports.NET_SSH2_MSG_SERVICE_ACCEPT = 6;
exports.NET_SSH2_MSG_KEXINIT = 20;
exports.NET_SSH2_MSG_NEWKEYS = 21;
exports.NET_SSH2_MSG_KEXDH_INIT = 30;
exports.NET_SSH2_MSG_KEXDH_REPLY = 31;
exports.NET_SSH2_MSG_USERAUTH_REQUEST = 50;
exports.NET_SSH2_MSG_USERAUTH_FAILURE = 51;
exports.NET_SSH2_MSG_USERAUTH_SUCCESS = 52;
exports.NET_SSH2_MSG_USERAUTH_BANNER = 53;

exports.NET_SSH2_MSG_GLOBAL_REQUEST = 80;
exports.NET_SSH2_MSG_REQUEST_SUCCESS = 81;
exports.NET_SSH2_MSG_REQUEST_FAILURE = 82;
exports.NET_SSH2_MSG_CHANNEL_OPEN = 90;
exports.NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
exports.NET_SSH2_MSG_CHANNEL_OPEN_FAILURE = 92;
exports.NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST = 93;
exports.NET_SSH2_MSG_CHANNEL_DATA = 94;
exports.NET_SSH2_MSG_CHANNEL_EXTENDED_DATA = 95;
exports.NET_SSH2_MSG_CHANNEL_EOF = 96;
exports.NET_SSH2_MSG_CHANNEL_CLOSE = 97;
exports.NET_SSH2_MSG_CHANNEL_REQUEST = 98;
exports.NET_SSH2_MSG_CHANNEL_SUCCESS = 99;
exports.NET_SSH2_MSG_CHANNEL_FAILURE = 100;

// disconnect_reasons
exports.NET_SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
exports.NET_SSH2_DISCONNECT_PROTOCOL_ERROR = 2;
exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
exports.NET_SSH2_DISCONNECT_RESERVED = 4;
exports.NET_SSH2_DISCONNECT_MAC_ERROR = 5;
exports.NET_SSH2_DISCONNECT_COMPRESSION_ERROR = 6;
exports.NET_SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
exports.NET_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
exports.NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
exports.NET_SSH2_DISCONNECT_CONNECTION_LOST = 10;
exports.NET_SSH2_DISCONNECT_BY_APPLICATION = 11;
exports.NET_SSH2_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
exports.NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
exports.NET_SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
exports.NET_SSH2_DISCONNECT_ILLEGAL_USER_NAME = 15;

// channel_open_failure_reasons
exports.NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;

// terminal_modes
exports.NET_SSH2_TTY_OP_END = 0;

// channel_extended_data_type_codes 
exports.NET_SSH2_EXTENDED_DATA_STDERR = 1;

exports.NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
exports.NET_SSH2_MSG_USERAUTH_PK_OK = 60;

// logging constants:
exports.NET_SSH2_LOG_NONE    = 0;
exports.NET_SSH2_LOG_SIMPLE  = 1;
exports.NET_SSH2_LOG_COMPLEX = 2;
exports.NET_SSH2_LOGGING     = exports.NET_SSH2_LOG_NONE;

/**
 * Default Constructor.
 * Connects to an SSHv2 server
 *
 * @param String host
 * @param optional Number port
 * @param optional Number timeout
 * @return Net_SSH2
 */
function ssh2(host, port, timeout) {
    Events.EventEmitter.call(this);

    this.host = host;
    this.port = port || 22;
    this.timeout = timeout || 10000;
}

Util.inherits(ssh2, Events.EventEmitter);

(function() {
    /**
     * The SSH identifier
     *
     * @var String
     */
    this.identifier = "SSH-2.0-node_ssh_0.1";

    /**
     * The Socket Object
     *
     * @var Object
     */
    this.fsock;

    /**
     * Execution Bitmap
     *
     * The bits that are set reprsent functions that have been called already.  
     * This is used to determine if a requisite function has been successfully executed. 
     * If not, an error should be thrown.
     *
     * @var Number
     */
    this.bitmap = 0;

    /**
     * Error information
     *
     * @see ssh2.getErrors()
     * @see ssh2.getLastError()
     * @var String
     */
    this.errors = [];

    /**
     * Server Identifier
     *
     * @see ssh2.getServerIdentification()
     * @var String
     */
    this.server_identifier = "";

    /**
     * Key Exchange Algorithms
     *
     * @see ssh2.getKexAlgorithims()
     * @var Array
     */
    this.kex_algorithms;

    /**
     * Server Host Key Algorithms
     *
     * @see ssh2.getServerHostKeyAlgorithms()
     * @var Array
     */
    this.server_host_key_algorithms;

    /**
     * Encryption Algorithms: Client to Server
     *
     * @see ssh2.getEncryptionAlgorithmsClient2Server()
     * @var Array
     */
    this.encryption_algorithms_client_to_server;

    /**
     * Encryption Algorithms: Server to Client
     *
     * @see ssh2.getEncryptionAlgorithmsServer2Client()
     * @var Array
     */
    this.encryption_algorithms_server_to_client;

    /**
     * MAC Algorithms: Client to Server
     *
     * @see ssh2.getMACAlgorithmsClient2Server()
     * @var Array
     */
    this.mac_algorithms_client_to_server;

    /**
     * MAC Algorithms: Server to Client
     *
     * @see ssh2.getMACAlgorithmsServer2Client()
     * @var Array
     */
    this.mac_algorithms_server_to_client;

    /**
     * Compression Algorithms: Client to Server
     *
     * @see ssh2.getCompressionAlgorithmsClient2Server()
     * @var Array
     */
    this.compression_algorithms_client_to_server;

    /**
     * Compression Algorithms: Server to Client
     *
     * @see ssh2.getCompressionAlgorithmsServer2Client()
     * @var Array
     */
    this.compression_algorithms_server_to_client;

    /**
     * Languages: Server to Client
     *
     * @see ssh2.getLanguagesServer2Client()
     * @var Array
     */
    this.languages_server_to_client;

    /**
     * Languages: Client to Server
     *
     * @see ssh2.getLanguagesClient2Server()
     * @var Array
     */
    this.languages_client_to_server;

    /**
     * Block Size for Server to Client Encryption
     *
     * "Note that the length of the concatenation of 'packet_length',
     *  'padding_length', 'payload', and 'random padding' MUST be a multiple
     *  of the cipher block size or 8, whichever is larger.  This constraint
     *  MUST be enforced, even when using stream ciphers."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-6
     *
     * @see ssh2.Net_SSH2()
     * @see ssh2._send_binary_packet()
     * @var Number
     */
    this.encrypt_block_size = 8;

    /**
     * Block Size for Client to Server Encryption
     *
     * @see ssh2.Net_SSH2()
     * @see ssh2._get_binary_packet()
     * @var Number
     */
    this.decrypt_block_size = 8;

    /**
     * Server to Client Encryption Object
     *
     * @see ssh2._get_binary_packet()
     * @var Object
     */
    this.decrypt = null;

    /**
     * Client to Server Encryption Object
     *
     * @see ssh2._send_binary_packet()
     * @var Object
     */
    this.encrypt = null;

    /**
     * Client to Server HMAC Object
     *
     * @see ssh2._send_binary_packet()
     * @var Object
     */
    this.hmac_create = null;

    /**
     * Server to Client HMAC Object
     *
     * @see ssh2._get_binary_packet()
     * @var Object
     */
    this.hmac_check = null;

    /**
     * Size of server to client HMAC
     *
     * We need to know how big the HMAC will be for the server to client direction 
     * so that we know how many bytes to read. For the client to server side, the 
     * HMAC object will make the HMAC as long as it needs to be. All we need to do is
     * append it.
     *
     * @see ssh2._get_binary_packet()
     * @var Number
     */
    this.hmac_size = null;

    /**
     * Server Public Host Key
     *
     * @see ssh2.getServerPublicHostKey()
     * @var String
     */
    this.server_public_host_key;

    /**
     * Session identifer
     *
     * "The exchange hash H from the first key exchange is additionally
     *  used as the session identifier, which is a unique identifier for
     *  this connection."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-7.2
     *
     * @see ssh2._key_exchange()
     * @var String
     */
    this.session_id = false;

    /**
     * Message Numbers
     *
     * @var Array
     */
    this.message_numbers = [];

    /**
     * Disconnection Message 'reason codes' defined in RFC4253
     *
     * @var Array
     */
    this.disconnect_reasons = [];

    /**
     * SSH_MSG_CHANNEL_OPEN_FAILURE 'reason codes', defined in RFC4254
     *
     * @var Array
     */
    this.channel_open_failure_reasons = [];

    /**
     * Terminal Modes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-8
     * @var Array
     */
    this.terminal_modes = [];

    /**
     * SSH_MSG_CHANNEL_EXTENDED_DATA's data_type_codes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-5.2
     * @var Array
     */
    this.channel_extended_data_type_codes = [];

    /**
     * Send Sequence Number
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see ssh2._send_binary_packet()
     * @var Number
     */
    this.send_seq_no = 0;

    /**
     * Get Sequence Number
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see ssh2._get_binary_packet()
     * @var Number
     */
    this.get_seq_no = 0;

    /**
     * Server Channels
     * Maps client channels to server channels
     *
     * @see ssh2._get_channel_packet()
     * @see ssh2.exec()
     * @var Array
     */
    this.server_channels = [];

    /**
     * Channel Buffers
     * If a client requests a packet from one channel but receives two packets from 
     * another those packets should be placed in a buffer
     *
     * @see ssh2._get_channel_packet()
     * @see ssh2.exec()
     * @var Array
     */
    this.channel_buffers = [];

    /**
     * Channel Status
     * Contains the type of the last sent message
     *
     * @see ssh2._get_channel_packet()
     * @var Array
     */
    this.channel_status = [];

    /**
     * Packet Size
     * Maximum packet size indexed by channel
     *
     * @see ssh2._send_channel_packet()
     * @var Array
     */
    this.packet_size_client_to_server = [];

    /**
     * Message Number Log
     *
     * @see ssh2.getLog()
     * @var Array
     */
    this.message_number_log = [];

    /**
     * Message Log
     *
     * @see ssh2.getLog()
     * @var Array
     */
    this.message_log = [];

    /**
     * The Window Size
     * Bytes the other party can send before it must wait for the window to be 
     * adjusted (0x7FFFFFFF = 4GB)
     *
     * @var Number
     * @see ssh2._send_channel_packet()
     * @see ssh2.exec()
     */
    this.window_size = 0x7FFFFFFF;

    /**
     * Window size
     * Window size indexed by channel
     *
     * @see ssh2._send_channel_packet()
     * @var Array
     */
    this.window_size_client_to_server = [];

    /**
     * Server signature
     * Verified against this.session_id
     *
     * @see ssh2.getServerPublicHostKey()
     * @var String
     */
    this.signature = "";

    /**
     * Server signature format
     *
     * ssh-rsa or ssh-dss.
     *
     * @see ssh2.getServerPublicHostKey()
     * @var String
     */
    this.signature_format = "";
    
    this.listen_callbacks = [];
    
    this.connect = function(cbconnect) {
        var _self = this;

        this.fsock = Net.createConnection(this.port, this.host);
        this.fsock.setTimeout(this.timeout);
        //this.fsock.setNoDelay();
        this.fsock.addListener("connect", function() {
            var connected     = false,
                authenticated = false,
                extra         = "";
            console.log("listening...");
            
            //_self.buffer = new Utils.Buffy();
            _self.fsock.addListener("data", function listener(data) {
                /* According to the SSH2 specs,

                  "The server MAY send other lines of data before sending the version
                   string.  Each line SHOULD be terminated by a Carriage Return and Line
                   Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
                   in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
                   MUST be able to process such lines." */
                if (!connected) {
                    var temp    = data.toString(),
                        matches = temp.match(/^SSH-(\d\.\d+)/);
                    if (!matches)
                        return extra += temp;

                    if (exports.NET_SSH2_LOGGING) {
                        _self.message_number_log.push("<-", "->");
                        if (exports.NET_SSH2_LOGGING == exports.NET_SSH2_LOG_COMPLEX)
                            _self.message_log.push(temp, _self.identifier + "\r\n");
                    }

                    _self.server_identifier = temp.replace(/[\r\n]+/, "");
                    if (extra)
                        _self.errors.push(extra);

                    if (matches[1] != "1.99" && matches[1] != "2.0")
                        return cbconnect("Cannot connect to SSH " + $matches[1] +" servers");

                    _self.fsock.write(_self.identifier + "\r\n");
                    connected = true;
                    _self.fsock.removeListener("data", listener);
                    
                    _self._get_binary_packet(function(response) {
                        
                    });
                    _self._listen();
                }
                else {
                    
                    if (false){
                    if (!_self.buffer)
                        _self.buffer = data;
                    else
                        _self.buffer.addChunk(data);
                        
                    console.log("buffer expanded", _self.buffer.length);
                    if (!authenticated) {
                        var response = _self._get_binary_packet();
                        if (response === false)
                            return cbconnect("Connection closed by server");
    
                        console.log("RES", typeof response, response);
                        /*return;
                        if (response[0].charCodeAt(0) != exports.NET_SSH2_MSG_KEXINIT)
                            return cbconnect("Expected SSH_MSG_KEXINIT");
    
                        if (!_self._key_exchange(response))
                            return cbconnect("No supported authentication method found");*/
    
                        _self.bitmap = exports.NET_SSH2_MASK_CONSTRUCTOR;
                        authenticated = true;
                        cbconnect(null, _self);
                    }
                    }
                }
                console.log("data: ", data + "--END--");
            });
        });
        this.fsock.addListener("error", function(err) {
            cbconnect("Cannot connect to host: " + err);
            _self.fsock.destroy();
        });
        this.fsock.addListener("timeout", function(err) {
            _self.fsock.end();
        });
    };
    
    /**
     * Disconnect
     */
    this.disconnect = function() {
        this._disconnect(exports.NET_SSH2_DISCONNECT_BY_APPLICATION);
    };
    
    /**
     * Disconnect
     *
     * @param Integer reason
     * @return Boolean
     */
    this._disconnect = function(reason) {
        if (this.bitmap) {
            data = pack("CNNa*Na*", exports.NET_SSH2_MSG_DISCONNECT, reason, 0, "", 0, "");
            this._send_binary_packet(data);
            this.bitmap = 0;
            fclose(this.fsock);
            return false;
        }
    };
    
    /**
     * Key Exchange
     *
     * @param String $kexinit_payload_server
     * @access private
     */
    function _key_exchange(kexinit_payload_server)
    {
        var kex_algorithms = [
            "diffie-hellman-group1-sha1", // REQUIRED
            "diffie-hellman-group14-sha1" // REQUIRED
        ];

        var server_host_key_algorithms = [
            "ssh-rsa", // RECOMMENDED  sign   Raw RSA Key
            "ssh-dss"  // REQUIRED     sign   Raw DSS Key
        ];

        var encryption_algorithms = [
            // from <http://tools.ietf.org/html/rfc4345#section-4>:
            "arcfour256",
            "arcfour128",

            "arcfour",    // OPTIONAL          the ARCFOUR stream cipher with a 128-bit key

            "aes128-cbc", // RECOMMENDED       AES with a 128-bit key
            "aes192-cbc", // OPTIONAL          AES with a 192-bit key
            "aes256-cbc", // OPTIONAL          AES in CBC mode, with a 256-bit key

            // from <http://tools.ietf.org/html/rfc4344#section-4>:
            "aes128-ctr", // RECOMMENDED       AES (Rijndael) in SDCTR mode, with 128-bit key
            "aes192-ctr", // RECOMMENDED       AES with 192-bit key
            "aes256-ctr", // RECOMMENDED       AES with 256-bit key
            "3des-ctr",   // RECOMMENDED       Three-key 3DES in SDCTR mode

            "3des-cbc",   // REQUIRED          three-key 3DES in CBC mode
            "none"        // OPTIONAL          no encryption; NOT RECOMMENDED
        ];

        var mac_algorithms = [
            "hmac-sha1-96", // RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
            "hmac-sha1",    // REQUIRED        HMAC-SHA1 (digest length = key length = 20)
            "hmac-md5-96",  // OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
            "hmac-md5",     // OPTIONAL        HMAC-MD5 (digest length = key length = 16)
            "none"          // OPTIONAL        no MAC; NOT RECOMMENDED
        ];

        var compression_algorithms = [
            "none"   // REQUIRED        no compression
            //"zlib" // OPTIONAL        ZLIB (LZ77) compression
        ];

        var str_kex_algorithms, str_server_host_key_algorithms,
            encryption_algorithms_server_to_client, mac_algorithms_server_to_client, compression_algorithms_server_to_client,
            encryption_algorithms_client_to_server, mac_algorithms_client_to_server, compression_algorithms_client_to_server;

        if (empty(str_kex_algorithms)) {
            str_kex_algorithms = implode(",", kex_algorithms);
            str_server_host_key_algorithms = implode(",", server_host_key_algorithms);
            encryption_algorithms_server_to_client = encryption_algorithms_client_to_server = implode(",", encryption_algorithms);
            mac_algorithms_server_to_client = mac_algorithms_client_to_server = implode(",", mac_algorithms);
            compression_algorithms_server_to_client = compression_algorithms_client_to_server = implode(",", compression_algorithms);
        }

        client_cookie = "";
        for (i = 0; i < 16; i++) {
            client_cookie += chr(crypt_random(0, 255));
        }

        response = kexinit_payload_server;
        this._string_shift(response, 1); // skip past the message number (it should be SSH_MSG_KEXINIT)
        server_cookie = this._string_shift(response, 16);

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.kex_algorithms = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.server_host_key_algorithms = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.encryption_algorithms_client_to_server = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.encryption_algorithms_server_to_client = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.mac_algorithms_client_to_server = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.mac_algorithms_server_to_client = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.compression_algorithms_client_to_server = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.compression_algorithms_server_to_client = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.languages_client_to_server = explode(",", this._string_shift(response, temp["length"]));

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.languages_server_to_client = explode(",", this._string_shift(response, temp["length"]));

        extract(unpack("Cfirst_kex_packet_follows", this._string_shift(response, 1)));
        first_kex_packet_follows = first_kex_packet_follows != 0;

        // the sending of SSH2_MSG_KEXINIT could go in one of two places.  this is the second place.
        kexinit_payload_client = pack("Ca*Na*Na*Na*Na*Na*Na*Na*Na*Na*Na*CN",
            NET_SSH2_MSG_KEXINIT, client_cookie, strlen(str_kex_algorithms), str_kex_algorithms,
            strlen(str_server_host_key_algorithms), str_server_host_key_algorithms, strlen(encryption_algorithms_client_to_server),
            encryption_algorithms_client_to_server, strlen(encryption_algorithms_server_to_client), encryption_algorithms_server_to_client,
            strlen(mac_algorithms_client_to_server), mac_algorithms_client_to_server, strlen(mac_algorithms_server_to_client),
            mac_algorithms_server_to_client, strlen(compression_algorithms_client_to_server), compression_algorithms_client_to_server,
            strlen(compression_algorithms_server_to_client), compression_algorithms_server_to_client, 0, "", 0, "",
            0, 0
        );

        if (!this._send_binary_packet(kexinit_payload_client)) {
            return false;
        }
        // here ends the second place.

        // we need to decide upon the symmetric encryption algorithms before we do the diffie-hellman key exchange
        for (i = 0; i < count(encryption_algorithms) && !in_array(encryption_algorithms[i], this.encryption_algorithms_server_to_client); i++);
        if (i == count(encryption_algorithms)) {
            user_error("No compatible server to client encryption algorithms found", E_USER_NOTICE);
            return this._disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        // we don"t initialize any crypto-objects, yet - we do that, later. for now, we need the lengths to make the
        // diffie-hellman key exchange as fast as possible
        decrypt = encryption_algorithms[i];
        switch (decrypt) {
            case "3des-cbc":
            case "3des-ctr":
                decryptKeyLength = 24; // eg. 192 / 8
                break;
            case "aes256-cbc":
            case "aes256-ctr":
                decryptKeyLength = 32; // eg. 256 / 8
                break;
            case "aes192-cbc":
            case "aes192-ctr":
                decryptKeyLength = 24; // eg. 192 / 8
                break;
            case "aes128-cbc":
            case "aes128-ctr":
                decryptKeyLength = 16; // eg. 128 / 8
                break;
            case "arcfour":
            case "arcfour128":
                decryptKeyLength = 16; // eg. 128 / 8
                break;
            case "arcfour256":
                decryptKeyLength = 32; // eg. 128 / 8
                break;
            case "none":
                decryptKeyLength = 0;
                break;
        }

        for (i = 0; i < count(encryption_algorithms) && !in_array(encryption_algorithms[i], this.encryption_algorithms_client_to_server); i++);
        if (i == count(encryption_algorithms)) {
            user_error("No compatible client to server encryption algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        encrypt = encryption_algorithms[i];
        switch (encrypt) {
            case "3des-cbc":
            case "3des-ctr":
                encryptKeyLength = 24;
                break;
            case "aes256-cbc":
            case "aes256-ctr":
                encryptKeyLength = 32;
                break;
            case "aes192-cbc":
            case "aes192-ctr":
                encryptKeyLength = 24;
                break;
            case "aes128-cbc":
            case "aes128-ctr":
                encryptKeyLength = 16;
                break;
            case "arcfour":
            case "arcfour128":
                encryptKeyLength = 16;
                break;
            case "arcfour256":
                encryptKeyLength = 32;
                break;
            case "none":
                encryptKeyLength = 0;
                break;
        }

        keyLength = decryptKeyLength > encryptKeyLength ? decryptKeyLength : encryptKeyLength;

        // through diffie-hellman key exchange a symmetric key is obtained
        for (i = 0; i < count(kex_algorithms) && !in_array(kex_algorithms[i], this.kex_algorithms); i++);
        if (i == count(kex_algorithms)) {
            user_error("No compatible key exchange algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        switch (kex_algorithms[i]) {
            // see http://tools.ietf.org/html/rfc2409#section-6.2 and 
            // http://tools.ietf.org/html/rfc2412, appendex E
            case "diffie-hellman-group1-sha1":
                p = pack("H256", "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" + 
                                  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" + 
                                  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + 
                                  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");
                keyLength = keyLength < 160 ? keyLength : 160;
                hash = "sha1";
                break;
            // see http://tools.ietf.org/html/rfc3526#section-3
            case "diffie-hellman-group14-sha1":
                p = pack("H512", "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
                                  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" + 
                                  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + 
                                  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" + 
                                  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" + 
                                  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" + 
                                  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" + 
                                  "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
                keyLength = keyLength < 160 ? keyLength : 160;
                hash = "sha1";
        }

        p = new Math_BigInteger(p, 256);
        //q = p.bitwise_rightShift(1);

        /* To increase the speed of the key exchange, both client and server may
           reduce the size of their private exponents.  It should be at least
           twice as long as the key material that is generated from the shared
           secret.  For more details, see the paper by van Oorschot and Wiener
           [VAN-OORSCHOT].

           -- http://tools.ietf.org/html/rfc4419#section-6.2 */
        q = new Math_BigInteger(1);
        q = q.bitwise_leftShift(2 * keyLength);
        q = q.subtract(new Math_BigInteger(1));

        g = new Math_BigInteger(2);
        x = new Math_BigInteger();
        x.setRandomGenerator("crypt_random");
        x = x.random(new Math_BigInteger(1), q);
        e = g.modPow(x, p);

        eBytes = e.toBytes(true);
        data = pack("CNa*", exports.NET_SSH2_MSG_KEXDH_INIT, strlen(eBytes), eBytes);

        if (!this._send_binary_packet(data)) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }

        response = this._get_binary_packet();
        if (response === false) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }
        extract(unpack("Ctype", this._string_shift(response, 1)));

        if (type != NET_SSH2_MSG_KEXDH_REPLY) {
            user_error("Expected SSH_MSG_KEXDH_REPLY", E_USER_NOTICE);
            return false;
        }

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.server_public_host_key = server_public_host_key = this._string_shift(response, temp["length"]);

        temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
        public_key_format = this._string_shift(server_public_host_key, temp["length"]);

        temp = unpack("Nlength", this._string_shift(response, 4));
        fBytes = this._string_shift(response, temp["length"]);
        f = new Math_BigInteger(fBytes, -256);

        temp = unpack("Nlength", this._string_shift(response, 4));
        this.signature = this._string_shift(response, temp["length"]);

        temp = unpack("Nlength", this._string_shift(this.signature, 4));
        this.signature_format = this._string_shift(this.signature, temp["length"]);

        key = f.modPow(x, p);
        keyBytes = key.toBytes(true);

        if (this.session_id === false) {
            source = pack("Na*Na*Na*Na*Na*Na*Na*Na*",
                strlen(this.identifier), this.identifier, strlen(this.server_identifier), this.server_identifier,
                strlen(kexinit_payload_client), kexinit_payload_client, strlen(kexinit_payload_server),
                kexinit_payload_server, strlen(this.server_public_host_key), this.server_public_host_key, strlen(eBytes),
                eBytes, strlen(fBytes), fBytes, strlen(keyBytes), keyBytes
            );

            source = pack("H*", hash(source));

            this.session_id = source;
        }

        for (i = 0; i < count(server_host_key_algorithms) && !in_array(server_host_key_algorithms[i], this.server_host_key_algorithms); i++);
        if (i == count(server_host_key_algorithms)) {
            user_error("No compatible server host key algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        if (public_key_format != server_host_key_algorithms[i] || this.signature_format != server_host_key_algorithms[i]) {
            user_error("Sever Host Key Algorithm Mismatch", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        packet = pack("C",
            exports.NET_SSH2_MSG_NEWKEYS
        );

        if (!this._send_binary_packet(packet)) {
            return false;
        }

        response = this._get_binary_packet();

        if (response === false) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }

        extract(unpack("Ctype", this._string_shift(response, 1)));

        if (type != exports.NET_SSH2_MSG_NEWKEYS) {
            user_error("Expected SSH_MSG_NEWKEYS", E_USER_NOTICE);
            return false;
        }

        switch (encrypt) {
            case "3des-cbc":
                this.encrypt = new Crypt_TripleDES();
                // this.encrypt_block_size = 64 / 8 == the default
                break;
            case "3des-ctr":
                this.encrypt = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
                // this.encrypt_block_size = 64 / 8 == the default
                break;
            case "aes256-cbc":
            case "aes192-cbc":
            case "aes128-cbc":
                this.encrypt = new Crypt_AES();
                this.encrypt_block_size = 16; // eg. 128 / 8
                break;
            case "aes256-ctr":
            case "aes192-ctr":
            case "aes128-ctr":
                this.encrypt = new Crypt_AES(CRYPT_AES_MODE_CTR);
                this.encrypt_block_size = 16; // eg. 128 / 8
                break;
            case "arcfour":
            case "arcfour128":
            case "arcfour256":
                this.encrypt = new Crypt_RC4();
                break;
            case "none":
                //this.encrypt = new Crypt_Null();
                break;
        }

        switch (decrypt) {
            case "3des-cbc":
                this.decrypt = new Crypt_TripleDES();
                break;
            case "3des-ctr":
                this.decrypt = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
                break;
            case "aes256-cbc":
            case "aes192-cbc":
            case "aes128-cbc":
                this.decrypt = new Crypt_AES();
                this.decrypt_block_size = 16;
                break;
            case "aes256-ctr":
            case "aes192-ctr":
            case "aes128-ctr":
                this.decrypt = new Crypt_AES(CRYPT_AES_MODE_CTR);
                this.decrypt_block_size = 16;
                break;
            case "arcfour":
            case "arcfour128":
            case "arcfour256":
                this.decrypt = new Crypt_RC4();
                break;
            case "none":
                //this.decrypt = new Crypt_Null();
                break;
        }

        keyBytes = pack("Na*", strlen(keyBytes), keyBytes);

        if (this.encrypt) {
            this.encrypt.enableContinuousBuffer();
            this.encrypt.disablePadding();

            iv = pack("H*", hash(keyBytes + this.session_id + "A" + this.session_id));
            while (this.encrypt_block_size > strlen(iv)) {
                iv += pack("H*", hash(keyBytes + this.session_id + iv));
            }
            this.encrypt.setIV(substr(iv, 0, this.encrypt_block_size));

            key = pack("H*", hash(keyBytes + this.session_id + "C" + this.session_id));
            while (encryptKeyLength > strlen(key)) {
                key += pack("H*", hash(keyBytes + this.session_id + key));
            }
            this.encrypt.setKey(substr(key, 0, encryptKeyLength));
        }

        if (this.decrypt) {
            this.decrypt.enableContinuousBuffer();
            this.decrypt.disablePadding();

            iv = pack("H*", hash(keyBytes + this.session_id + "B" + this.session_id));
            while (this.decrypt_block_size > strlen(iv)) {
                iv += pack("H*", hash(keyBytes + this.session_id + iv));
            }
            this.decrypt.setIV(substr(iv, 0, this.decrypt_block_size));

            key = pack("H*", hash(keyBytes + this.session_id + "D" + this.session_id));
            while (decryptKeyLength > strlen(key)) {
                key += pack("H*", hash(keyBytes + this.session_id + key));
            }
            this.decrypt.setKey(substr(key, 0, decryptKeyLength));
        }

        /* The "arcfour128" algorithm is the RC4 cipher, as described in
           [SCHNEIER], using a 128-bit key.  The first 1536 bytes of keystream
           generated by the cipher MUST be discarded, and the first byte of the
           first encrypted packet MUST be encrypted using the 1537th byte of
           keystream.

           -- http://tools.ietf.org/html/rfc4345#section-4 */
        if (encrypt == "arcfour128" || encrypt == "arcfour256") {
            this.encrypt.encrypt(str_repeat("\0", 1536));
        }
        if (decrypt == "arcfour128" || decrypt == "arcfour256") {
            this.decrypt.decrypt(str_repeat("\0", 1536));
        }

        for (i = 0; i < count(mac_algorithms) && !in_array(mac_algorithms[i], this.mac_algorithms_client_to_server); i++);
        if (i == count(mac_algorithms)) {
            user_error("No compatible client to server message authentication algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        createKeyLength = 0; // ie. mac_algorithms[i] == "none"
        switch (mac_algorithms[i]) {
            case "hmac-sha1":
                this.hmac_create = new Crypt_Hash("sha1");
                createKeyLength = 20;
                break;
            case "hmac-sha1-96":
                this.hmac_create = new Crypt_Hash("sha1-96");
                createKeyLength = 20;
                break;
            case "hmac-md5":
                this.hmac_create = new Crypt_Hash("md5");
                createKeyLength = 16;
                break;
            case "hmac-md5-96":
                this.hmac_create = new Crypt_Hash("md5-96");
                createKeyLength = 16;
        }

        for (i = 0; i < count(mac_algorithms) && !in_array(mac_algorithms[i], this.mac_algorithms_server_to_client); i++);
        if (i == count(mac_algorithms)) {
            user_error("No compatible server to client message authentication algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        checkKeyLength = 0;
        this.hmac_size = 0;
        switch (mac_algorithms[i]) {
            case "hmac-sha1":
                this.hmac_check = new Crypt_Hash("sha1");
                checkKeyLength = 20;
                this.hmac_size = 20;
                break;
            case "hmac-sha1-96":
                this.hmac_check = new Crypt_Hash("sha1-96");
                checkKeyLength = 20;
                this.hmac_size = 12;
                break;
            case "hmac-md5":
                this.hmac_check = new Crypt_Hash("md5");
                checkKeyLength = 16;
                this.hmac_size = 16;
                break;
            case "hmac-md5-96":
                this.hmac_check = new Crypt_Hash("md5-96");
                checkKeyLength = 16;
                this.hmac_size = 12;
        }

        key = pack("H*", hash(keyBytes + this.session_id + "E" + this.session_id));
        while (createKeyLength > strlen(key)) {
            key += pack("H*", hash(keyBytes + this.session_id + key));
        }
        this.hmac_create.setKey(substr(key, 0, createKeyLength));

        key = pack("H*", hash(keyBytes + this.session_id + "F" + this.session_id));
        while (checkKeyLength > strlen(key)) {
            key += pack("H*", hash(keyBytes + this.session_id + key));
        }
        this.hmac_check.setKey(substr(key, 0, checkKeyLength));

        for (i = 0; i < count(compression_algorithms) && !in_array(compression_algorithms[i], this.compression_algorithms_server_to_client); i++);
        if (i == count(compression_algorithms)) {
            user_error("No compatible server to client compression algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }
        this.decompress = compression_algorithms[i] == "zlib";

        for (i = 0; i < count(compression_algorithms) && !in_array(compression_algorithms[i], this.compression_algorithms_client_to_server); i++);
        if (i == count(compression_algorithms)) {
            user_error("No compatible client to server compression algorithms found", E_USER_NOTICE);
            return this._disconnect(exports.NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }
        this.compress = compression_algorithms[i] == "zlib";

        return true;
    }
    
    /**
     * Login
     *
     * @param String username
     * @param optional String password
     * @return Boolean
     * @internal It might be worthwhile, at some point, to protect against 
     *           {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    this.login = function(username, password) {
        password = password || "";
        if (!(this.bitmap & exports.NET_SSH2_MASK_CONSTRUCTOR)) {
            return false;
        }

        packet = pack("CNa*",
            exports.NET_SSH2_MSG_SERVICE_REQUEST, strlen("ssh-userauth"), "ssh-userauth"
        );

        if (!this._send_binary_packet(packet)) {
            return false;
        }

        response = this._get_binary_packet();
        if (response === false) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }

        extract(unpack("Ctype", this._string_shift(response, 1)));

        if (type != exports.NET_SSH2_MSG_SERVICE_ACCEPT) {
            user_error("Expected SSH_MSG_SERVICE_ACCEPT", E_USER_NOTICE);
            return false;
        }

        // although PHP5"s get_class() preserves the case, PHP4"s does not
        if (is_object(password) && strtolower(get_class(password)) == "crypt_rsa")  {
            return this._privatekey_login(username, password);
        }

        utf8_password = utf8_encode(password);
        packet = pack("CNa*Na*Na*CNa*",
            exports.NET_SSH2_MSG_USERAUTH_REQUEST, strlen(username), username, strlen("ssh-connection"), "ssh-connection",
            strlen("password"), "password", 0, strlen(utf8_password), utf8_password
        );

        if (!this._send_binary_packet(packet)) {
            return false;
        }

        // remove the username and password from the last logged packet
        if (defined("NET_SSH2_LOGGING") && exports.NET_SSH2_LOGGING == exports.NET_SSH2_LOG_COMPLEX) {
            packet = pack("CNa*Na*Na*CNa*",
                exports.NET_SSH2_MSG_USERAUTH_REQUEST, strlen("username"), "username", strlen("ssh-connection"), "ssh-connection",
                strlen("password"), "password", 0, strlen("password"), "password"
            );
            this.message_log[count(this.message_log) - 1] = packet;
        }

        response = this._get_binary_packet();
        if (response === false) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }

        extract(unpack("Ctype", this._string_shift(response, 1)));

        switch (type) {
            case exports.NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ: // in theory, the password can be changed
                if (defined("NET_SSH2_LOGGING")) {
                    this.message_number_log[count(this.message_number_log) - 1] = "NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ";
                }
                extract(unpack("Nlength", this._string_shift(response, 4)));
                this.errors.push("SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: " + utf8_decode(this._string_shift(response, length)));
                return this._disconnect(exports.NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
            case exports.NET_SSH2_MSG_USERAUTH_FAILURE:
                // either the login is bad or the server employees multi-factor authentication
                return false;
            case exports.NET_SSH2_MSG_USERAUTH_SUCCESS:
                this.bitmap |= exports.NET_SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    };

    /**
     * Login with an RSA private key
     *
     * @param String username
     * @param Crypt_RSA password
     * @return Boolean
     * @internal It might be worthwhile, at some point, to protect against 
     *           {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    this._privatekey_login = function(username, privatekey) {
        // see http://tools.ietf.org/html/rfc4253#page-15
        publickey = privatekey.getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_RAW);
        if (publickey === false) {
            return false;
        }

        publickey = {
            "e" : publickey["e"].toBytes(true),
            "n" : publickey["n"].toBytes(true)
        };
        publickey = pack("Na*Na*Na*",
            strlen("ssh-rsa"), "ssh-rsa", strlen(publickey["e"]), publickey["e"], strlen(publickey["n"]), publickey["n"]
        );

        part1 = pack("CNa*Na*Na*",
            exports.NET_SSH2_MSG_USERAUTH_REQUEST, strlen(username), username, strlen("ssh-connection"), "ssh-connection",
            strlen("publickey"), "publickey"
        );
        part2 = pack("Na*Na*", strlen("ssh-rsa"), "ssh-rsa", strlen(publickey), publickey);

        packet = part1 . chr(0) . part2;

        if (!this._send_binary_packet(packet)) {
            return false;
        }

        response = this._get_binary_packet();
        if (response === false) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }

        extract(unpack("Ctype", this._string_shift(response, 1)));

        switch (type) {
            case exports.NET_SSH2_MSG_USERAUTH_FAILURE:
                extract(unpack("Nlength", this._string_shift(response, 4)));
                this.errors.push("SSH_MSG_USERAUTH_FAILURE: " + this._string_shift(response, length));
                return this._disconnect(exports.NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
            case exports.NET_SSH2_MSG_USERAUTH_PK_OK:
                // we"ll just take it on faith that the public key blob and the public key algorithm name are as
                // they should be
                if (defined("NET_SSH2_LOGGING")) {
                    this.message_number_log[count(this.message_number_log) - 1] = "NET_SSH2_MSG_USERAUTH_PK_OK";
                }
        }

        packet = part1 . chr(1) . part2;
        privatekey.setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        signature = privatekey.sign(pack("Na*a*", strlen(this.session_id), this.session_id, packet));
        signature = pack("Na*Na*", strlen("ssh-rsa"), "ssh-rsa", strlen(signature), signature);
        packet += pack("Na*", strlen(signature), signature);

        if (!this._send_binary_packet(packet)) {
            return false;
        }

        response = this._get_binary_packet();
        if (response === false) {
            user_error("Connection closed by server", E_USER_NOTICE);
            return false;
        }

        extract(unpack("Ctype", this._string_shift(response, 1)));

        switch (type) {
            case exports.NET_SSH2_MSG_USERAUTH_FAILURE:
                // either the login is bad or the server employees multi-factor authentication
                return false;
            case exports.NET_SSH2_MSG_USERAUTH_SUCCESS:
                this.bitmap |= exports.NET_SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    };

    /**
     * Execute Command
     *
     * @param String command
     * @return String
     */
    this.exec = function(command) {
        if (!(this.bitmap & exports.NET_SSH2_MASK_LOGIN)) {
            return false;
        }

        // RFC4254 defines the (client) window size as "bytes the other party can send before it must wait for the window to
        // be adjusted".  0x7FFFFFFF is, at 4GB, the max size.  technically, it should probably be decremented, but, 
        // honestly, if you"re transfering more than 4GB, you probably shouldn"t be using phpseclib, anyway.
        // see http://tools.ietf.org/html/rfc4254#section-5.2 for more info
        this.window_size_client_to_server[exports.NET_SSH2_CHANNEL_EXEC] = 0x7FFFFFFF;
        // 0x8000 is the maximum max packet size, per http://tools.ietf.org/html/rfc4253#section-6.1, although since PuTTy
        // uses 0x4000, that"s what will be used here, as well.
        packet_size = 0x4000;

        packet = pack("CNa*N3",
            NET_SSH2_MSG_CHANNEL_OPEN, strlen("session"), "session", exports.NET_SSH2_CHANNEL_EXEC, 
            this.window_size_client_to_server[exports.NET_SSH2_CHANNEL_EXEC], packet_size);

        if (!this._send_binary_packet(packet)) {
            return false;
        }

        this.channel_status[exports.NET_SSH2_CHANNEL_EXEC] = exports.NET_SSH2_MSG_CHANNEL_OPEN;

        response = this._get_channel_packet(exports.NET_SSH2_CHANNEL_EXEC);
        if (response === false) {
            return false;
        }

        // sending a pty-req SSH_MSG_CHANNEL_REQUEST message is unnecessary and, in fact, in most cases, slows things
        // down.  the one place where it might be desirable is if you"re doing something like Net_SSH2::exec("ping localhost &").
        // with a pty-req SSH_MSG_cHANNEL_REQUEST, exec() will return immediately and the ping process will then
        // then immediately terminate.  without such a request exec() will loop indefinitely.  the ping process won"t end but
        // neither will your script.

        // although, in theory, the size of SSH_MSG_CHANNEL_REQUEST could exceed the maximum packet size established by
        // SSH_MSG_CHANNEL_OPEN_CONFIRMATION, RFC4254#section-5.1 states that the "maximum packet size" refers to the 
        // "maximum size of an individual data packet". ie. SSH_MSG_CHANNEL_DATA.  RFC4254#section-5.2 corroborates.
        packet = pack("CNNa*CNa*",
            exports.NET_SSH2_MSG_CHANNEL_REQUEST, this.server_channels[exports.NET_SSH2_CHANNEL_EXEC], 
            strlen("exec"), "exec", 1, strlen(command), command);
        if (!this._send_binary_packet(packet)) {
            return false;
        }

        this.channel_status[exports.NET_SSH2_CHANNEL_EXEC] = exports.NET_SSH2_MSG_CHANNEL_REQUEST;

        response = this._get_channel_packet(exports.NET_SSH2_CHANNEL_EXEC);
        if (response === false) {
            return false;
        }

        this.channel_status[exports.NET_SSH2_CHANNEL_EXEC] = exports.NET_SSH2_MSG_CHANNEL_DATA;

        output = "";
        while (true) {
            temp = this._get_channel_packet(exports.NET_SSH2_CHANNEL_EXEC);
            switch (true) {
                case temp === true:
                    return output;
                case temp === false:
                    return false;
                default:
                    output += temp;
            }
        }
    };
    
    this._listen = function() {
        this.packets = [];
        
        var remaining_length, buffer, message,
            _self = this;
            
        function reset() {
            remaining_length = -1;
            message = {};
            return Strtok.UINT32_BE;
        }
        reset();
        
        Strtok.parse(this.fsock, function(v, callback) {
            //console.log("callback: ", v);
            if (typeof v == "undefined")
                return Strtok.UINT32_BE;

            if (!message.packet_length) {
                message.packet_length = v;
                //return Strtok.UINT8;
                return new Strtok.BufferType(_self.decrypt_block_size);
            }
            else if (!message.padding_length) {
                message.raw = v;
                if (_self.decrypt)
                    raw = _self.decrypt.decrypt(message.raw);
                message.padding_length = Strtok.UINT8.get(message.raw, 0);
                message.type = (new Strtok.StringType(1, "binary")).get(message.raw, Strtok.UINT8.len).charCodeAt(0);

                remaining_length = message.packet_length - _self.decrypt_block_size - 1;// + 4 - _self.decrypt_block_size;
                //console.log("how many bytes remaining? ", message.packet_length, remaining_length, _self.decrypt_block_size);
                buffer = new Buffer(0);
                return new Strtok.BufferType(remaining_length);
            }
            else if (remaining_length > 0) {
                remaining_length -= v.length;
                buffer = Buffer.concat(buffer, v);
                //console.log("MORE BYTES? ", remaining_length);
                return new Strtok.BufferType(remaining_length);
            }
            else if (!message.payload) {
                //console.log("DO WE GET HERE??", buffer.length);
                if (buffer.length > 0)
                    message.raw = Buffer.concat(message.raw, _self.decrypt ? _self.decrypt.decrypt(buffer) : buffer);

                var pay_len = message.packet_length - message.padding_length - 1;
                //console.log("message length: ", message.raw.length, pay_len);
                message.payload = message.raw.slice(0, pay_len);
                message.padding = message.raw.slice(pay_len, pay_len + message.padding_length);

                /*if (_self.hmac_check) {
                    message.hmac = fread($this->fsock, $this->hmac_size);
                    if ($hmac != $this->hmac_check->hash(pack('NNCa*', $this->get_seq_no, $packet_length, $padding_length, $payload . $padding))) {
                        user_error('Invalid HMAC', E_USER_NOTICE);
                        return false;
                    }
                }
                else {
                    
                }*/
                _self.get_seq_no++;
                
                if (exports.NET_SSH2_LOGGING) {
                    temp = _self.message_numbers[message.payload[0]] 
                        ? _self.message_numbers[message.payload[0]] 
                        : "UNKNOWN";
                    if (exports.NET_SSH2_LOGGING == exports.NET_SSH2_LOG_COMPLEX)
                        _self.message_log.push(message.payload.slice(1));
                }

                message = _self._filter(message);
                if (message !== null) {
                    _self.packets[_self.get_seq_no] = message;
                    var cb = _self.listen_callbacks.shift();
                    if (cb)
                        cb(message);
                }
                    
                // start over from the start (wait for the next packet)
                return reset();
            }
        });
    };

    /**
     * Gets Binary Packets
     * See "6. Binary Packet Protocol" of rfc4253 for more info.
     *
     * @see Net_SSH2::_send_binary_packet()
     * @return String
     */
    this._get_binary_packet = function(callback) {
        this.listen_callbacks.push(callback);
    };

    /**
     * Filter Binary Packets
     * Because some binary packets need to be ignored...
     *
     * @see Net_SSH2::_get_binary_packet()
     * @return String
     */
    this._filter = function(message) {
        console.log("payload: ", message);
        switch (message.type) {
            case exports.NET_SSH2_MSG_DISCONNECT:
                var reason_code = Strtok.UINT8.get(message.payload, 1);
                var length      = Strtok.UINT8.get(message.payload, 1 + Strtok.UINT8.len);
                this.errors.push("SSH_MSG_DISCONNECT: " + this.disconnect_reasons[reason_code] + "\r\n" 
                    + message.payload.slice(1 + (Strtok.UINT8.len * 2), length).toString("utf8"));
                this.bitmask = 0;
                // return immediately, message will not be pushed on the stack
                return false;
            case exports.NET_SSH2_MSG_IGNORE:
                // return immediately, message will not be pushed on the stack
                return null;
            case exports.NET_SSH2_MSG_DEBUG:
                var length = Strtok.UINT8.get(message.payload, 2);
                this.errors.push("SSH_MSG_DEBUG: " + message.payload.slice(2 + Strtok.UINT8.len, length));
                // return immediately, message will not be pushed on the stack
                return null;
            case exports.NET_SSH2_MSG_UNIMPLEMENTED:
                // return immediately, message will not be pushed on the stack
                return false;
            case exports.NET_SSH2_MSG_KEXINIT:
                console.log("KEXINIT: ", this.session_id);
                if (this.session_id !== false) {
                    if (!this._key_exchange(message.payload)) {
                        this.bitmask = 0;
                        return false;
                    }
                    // return immediately, message will not be pushed on the stack
                    return null;
                }
                break;
        }

        // see http://tools.ietf.org/html/rfc4252#section-5.4; only called when the 
        // encryption has been activated and when we haven"t already logged in
        if ((this.bitmap & exports.NET_SSH2_MASK_CONSTRUCTOR) && !(this.bitmap & exports.NET_SSH2_MASK_LOGIN) 
          && message.type == exports.NET_SSH2_MSG_USERAUTH_BANNER) {
            var length = Strtok.INT32_BE.get(message.payload, 1);
            this.errors.push("SSH_MSG_USERAUTH_BANNER: " + payload.slice(1 + Strtok.INT32_BE, length).toString("utf8"));
            // return immediately, message will not be pushed on the stack
            return null;
        }

        // only called when we've already logged in
        if ((this.bitmap & exports.NET_SSH2_MASK_CONSTRUCTOR) && (this.bitmap & exports.NET_SSH2_MASK_LOGIN)) {
            switch (message.type) {
                case exports.NET_SSH2_MSG_GLOBAL_REQUEST: // see http://tools.ietf.org/html/rfc4254#section-4
                    var length = Strtok.UINT8.get(message.payload, 1);
                    this.errors.push("SSH_MSG_GLOBAL_REQUEST: " + message.payload.slice(1 + Strtok.UINT8.len, length).toString("utf8"));
                    if (!this._send_binary_packet(pack("C", exports.NET_SSH2_MSG_REQUEST_FAILURE)))
                        return this._disconnect(exports.NET_SSH2_DISCONNECT_BY_APPLICATION);

                    // return immediately, message will not be pushed on the stack
                    return null;
                    break;
                case exports.NET_SSH2_MSG_CHANNEL_OPEN: // see http://tools.ietf.org/html/rfc4254#section-5.1
                    var length = Strtok.UINT8.get(message.payload, 1);
                    this.errors.push("SSH_MSG_CHANNEL_OPEN: " + message.payload.slice(1, length).toString("utf8"));

                    var server_channel = Strtok.UINT8.get(message.payload, 1 + 4); // skip over client channel

                    packet = pack("CN3a*Na*",
                        exports.NET_SSH2_MSG_REQUEST_FAILURE, server_channel, NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED, 0, "", 0, "");

                    if (!this._send_binary_packet(packet)) {
                        return this._disconnect(exports.NET_SSH2_DISCONNECT_BY_APPLICATION);
                    }

                    // return immediately, message will not be pushed on the stack
                    return null;
                case exports.NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
                    // return immediately, message will not be pushed on the stack
                    return null;
            }
        }

        return message;
    };

    /**
     * Gets channel data
     * Returns the data as a string if it"s available and false if not.
     *
     * @param client_channel
     * @return Mixed
     */
    this._get_channel_packet = function(client_channel) {
        if (!empty(this.channel_buffers[client_channel])) {
            return array_shift(this.channel_buffers[client_channel]);
        }

        while (true) {
            response = this._get_binary_packet();
            if (response === false) {
                user_error("Connection closed by server", E_USER_NOTICE);
                return false;
            }

            extract(unpack("Ctype/Nchannel", this._string_shift(response, 5)));

            switch (this.channel_status[channel]) {
                case NET_SSH2_MSG_CHANNEL_OPEN:
                    switch (type) {
                        case NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
                            extract(unpack("Nserver_channel", this._string_shift(response, 4)));
                            this.server_channels[client_channel] = server_channel;
                            this._string_shift(response, 4); // skip over (server) window size
                            temp = unpack("Npacket_size_client_to_server", this._string_shift(response, 4));
                            this.packet_size_client_to_server[client_channel] = temp["packet_size_client_to_server"];
                            return true;
                        //case NET_SSH2_MSG_CHANNEL_OPEN_FAILURE:
                        default:
                            user_error("Unable to open channel", E_USER_NOTICE);
                            return this._disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
                    }
                    break;
                case NET_SSH2_MSG_CHANNEL_REQUEST:
                    switch (type) {
                        case NET_SSH2_MSG_CHANNEL_SUCCESS:
                            return true;
                        //case NET_SSH2_MSG_CHANNEL_FAILURE:
                        default:
                            user_error("Unable to request pseudo-terminal", E_USER_NOTICE);
                            return this._disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
                    }

            }

            switch (type) {
                case NET_SSH2_MSG_CHANNEL_DATA:
                    if (client_channel == NET_SSH2_CHANNEL_EXEC) {
                        // SCP requires null packets, such as this, be sent.  further, in the case of the ssh.com SSH server
                        // this actually seems to make things twice as fast.  more to the point, the message right after 
                        // SSH_MSG_CHANNEL_DATA (usually SSH_MSG_IGNORE) won"t block for as long as it would have otherwise.
                        // in OpenSSH it slows things down but only by a couple thousandths of a second.
                        this._send_channel_packet(client_channel, chr(0));
                    }
                    extract(unpack("Nlength", this._string_shift(response, 4)));
                    data = this._string_shift(response, length);
                    if (client_channel == channel) {
                        return data;
                    }
                    if (!isset(this.channel_buffers[client_channel])) {
                        this.channel_buffers[client_channel] = []
                    }
                    this.channel_buffers[client_channel].push(data);
                    break;
                case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:
                    if (client_channel == NET_SSH2_CHANNEL_EXEC) {
                        this._send_channel_packet(client_channel, chr(0));
                    }
                    // currently, there"s only one possible value for data_type_code: NET_SSH2_EXTENDED_DATA_STDERR
                    extract(unpack("Ndata_type_code/Nlength", this._string_shift(response, 8)));
                    data = this._string_shift(response, length);
                    if (client_channel == channel) {
                        return data;
                    }
                    if (!isset(this.channel_buffers[client_channel])) {
                        this.channel_buffers[client_channel] = []
                    }
                    this.channel_buffers[client_channel].push(data);
                    break;
                case NET_SSH2_MSG_CHANNEL_REQUEST:
                    extract(unpack("Nlength", this._string_shift(response, 4)));
                    value = this._string_shift(response, length);
                    switch (value) {
                        case "exit-signal":
                            this._string_shift(response, 1);
                            extract(unpack("Nlength", this._string_shift(response, 4)));
                            this.errors.push("SSH_MSG_CHANNEL_REQUEST (exit-signal): " + this._string_shift(response, length));
                            this._string_shift(response, 1);
                            extract(unpack("Nlength", this._string_shift(response, 4)));
                            if (length) {
                                this.errors.push(this.errors.pop() + "\r\n" + this._string_shift(response, length));
                            }
                        //case "exit-status":
                        default:
                            // "Some systems may not implement signals, in which case they SHOULD ignore this message."
                            //  -- http://tools.ietf.org/html/rfc4254#section-6.9
                            break;
                    }
                    break;
                case NET_SSH2_MSG_CHANNEL_CLOSE:
                    this._send_binary_packet(pack("CN", NET_SSH2_MSG_CHANNEL_CLOSE, this.server_channels[channel]));
                    return true;
                case NET_SSH2_MSG_CHANNEL_EOF:
                    break;
                default:
                    user_error("Error reading channel data", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
            }
        }
    };

    /**
     * Sends Binary Packets
     * See "6. Binary Packet Protocol" of rfc4253 for more info.
     *
     * @param String data
     * @see Net_SSH2::_get_binary_packet()
     * @return Boolean
     */
    this._send_binary_packet = function(data) {
        if (feof(this.fsock)) {
            user_error("Connection closed prematurely", E_USER_NOTICE);
            return false;
        }

        //if (this.compress) {
        //    // the -4 removes the checksum:
        //    // http://php.net/function.gzcompress#57710
        //    data = substr(gzcompress(data), 0, -4);
        //}

        // 4 (packet length) + 1 (padding length) + 4 (minimal padding amount) == 9
        packet_length = strlen(data) + 9;
        // round up to the nearest this.encrypt_block_size
        packet_length+= ((this.encrypt_block_size - 1) * packet_length) % this.encrypt_block_size;
        // subtracting strlen(data) is obvious - subtracting 5 is necessary because of packet_length and padding_length
        padding_length = packet_length - strlen(data) - 5;

        padding = "";
        for (i = 0; i < padding_length; i++) {
            padding += chr(crypt_random(0, 255));
        }

        // we subtract 4 from packet_length because the packet_length field isn"t supposed to include itself
        packet = pack("NCa*", packet_length - 4, padding_length, data . padding);

        hmac = this.hmac_create !== false ? this.hmac_create.hash(pack("Na*", this.send_seq_no, packet)) : "";
        this.send_seq_no++;

        if (this.encrypt !== false) {
            packet = this.encrypt.encrypt(packet);
        }

        packet += hmac;

        start = strtok(microtime(), " ") + strtok(""); // http://php.net/microtime#61838
        result = strlen(packet) == fputs(this.fsock, packet);
        stop = strtok(microtime(), " ") + strtok("");

        if (defined("NET_SSH2_LOGGING")) {
            temp = isset(this.message_numbers[ord(data[0])]) ? this.message_numbers[ord(data[0])] : "UNKNOWN";
            this.message_number_log.push(". " + temp +
                                          " (" + round(stop - start, 4) + "s)");
            if (NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX) {
                this.message_log.push(substr(data, 1));
            }
        }

        return result;
    };

    /**
     * Sends channel data
     * Spans multiple SSH_MSG_CHANNEL_DATAs if appropriate
     *
     * @param Integer client_channel
     * @param String data
     * @return Boolean
     */
    this._send_channel_packet = function(client_channel, data) {
        while (strlen(data) > this.packet_size_client_to_server[client_channel]) {
            // resize the window, if appropriate
            this.window_size_client_to_server[client_channel]-= this.packet_size_client_to_server[client_channel];
            if (this.window_size_client_to_server[client_channel] < 0) {
                packet = pack("CNN", NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST, this.server_channels[client_channel], this.window_size);
                if (!this._send_binary_packet(packet)) {
                    return false;
                }
                this.window_size_client_to_server[client_channel]+= this.window_size;
            }

            packet = pack("CN2a*",
                NET_SSH2_MSG_CHANNEL_DATA,
                this.server_channels[client_channel],
                this.packet_size_client_to_server[client_channel],
                this._string_shift(data, this.packet_size_client_to_server[client_channel])
            );

            if (!this._send_binary_packet(packet)) {
                return false;
            }
        }

        // resize the window, if appropriate
        this.window_size_client_to_server[client_channel]-= strlen(data);
        if (this.window_size_client_to_server[client_channel] < 0) {
            packet = pack("CNN", NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST, this.server_channels[client_channel], this.window_size);
            if (!this._send_binary_packet(packet)) {
                return false;
            }
            this.window_size_client_to_server[client_channel]+= this.window_size;
        }

        return this._send_binary_packet(pack("CN2a*",
            NET_SSH2_MSG_CHANNEL_DATA,
            this.server_channels[client_channel],
            strlen(data),
            data));
    };

    /**
     * String Shift
     * Inspired by array_shift
     *
     * @param String string
     * @param optional Integer index
     * @return String
     */
    this._string_shift = function(string, index) {
        if (typeof index == "undefined")
            index = 1;
        substr = substr(string, 0, index);
        string = substr(string, index);
        return substr;
    };

    /**
     * Returns a log of the packets that have been sent and received.
     * Returns a string if NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX, an array if 
     * NET_SSH2_LOGGING == NET_SSH2_LOG_SIMPLE and false if !defined("NET_SSH2_LOGGING")
     *
     * @return String or Array
     */
    this.getLog = function() {
        if (!defined("NET_SSH2_LOGGING")) {
            return false;
        }

        switch (NET_SSH2_LOGGING) {
            case NET_SSH2_LOG_SIMPLE:
                return this.message_number_log;
                break;
            case NET_SSH2_LOG_COMPLEX:
                return this._format_log(this.message_log, this.message_number_log);
                break;
            default:
                return false;
        }
    };

    /**
     * Formats a log for printing
     *
     * @param Array message_log
     * @param Array message_number_log
     * @return String
     */
    this._format_log = function(message_log, message_number_log) {
        var boundary = ":", long_width = 65, short_width = 16;

        output = "";
        for (i = 0; i < count(message_log); i++) {
            output += message_number_log[i] + "\r\n";
            current_log = message_log[i];
            j = 0;
            do {
                if (!empty(current_log)) {
                    output += str_pad(dechex(j), 7, "0", STR_PAD_LEFT) + "0  ";
                }
                fragment = this._string_shift(current_log, short_width);
                hex = substr(
                           preg_replace(
                               "#(.)#es",
                               "\"" + boundary + "\"" . str_pad(dechex(ord(substr("\\1", -1))), 2, "0", STR_PAD_LEFT),
                               fragment),
                           strlen(boundary)
                       );
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                // also replace < with a . since < messes up the output on web browsers
                raw = preg_replace("#[^\x20-\x7E]|<#", ".", fragment);
                output += str_pad(hex, long_width - short_width, " ") + raw + "\r\n";
                j++;
            } while (!empty(current_log));
            output += "\r\n";
        }

        return output;
    };

    /**
     * Returns all errors
     *
     * @return String
     */
    this.getErrors = function() {
        return this.errors;
    };

    /**
     * Returns the last error
     *
     * @return String
     */
    this.getLastError = function() {
        return this.errors[count(this.errors) - 1];
    };

    /**
     * Return the server identification.
     *
     * @return String
     */
    this.getServerIdentification = function() {
        return this.server_identifier;
    };

    /**
     * Return a list of the key exchange algorithms the server supports.
     *
     * @return Array
     */
    this.getKexAlgorithms = function() {
        return this.kex_algorithms;
    };

    /**
     * Return a list of the host key (public key) algorithms the server supports.
     *
     * @return Array
     */
    this.getServerHostKeyAlgorithms = function() {
        return this.server_host_key_algorithms;
    };

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    this.getEncryptionAlgorithmsClient2Server = function() {
        return this.encryption_algorithms_client_to_server;
    };

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    this.getEncryptionAlgorithmsServer2Client = function() {
        return this.encryption_algorithms_server_to_client;
    };

    /**
     * Return a list of the MAC algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    this.getMACAlgorithmsClient2Server = function() {
        return this.mac_algorithms_client_to_server;
    };

    /**
     * Return a list of the MAC algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    this.getMACAlgorithmsServer2Client = function() {
        return this.mac_algorithms_server_to_client;
    };

    /**
     * Return a list of the compression algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    this.getCompressionAlgorithmsClient2Server = function() {
        return this.compression_algorithms_client_to_server;
    };

    /**
     * Return a list of the compression algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    this.getCompressionAlgorithmsServer2Client = function() {
        return this.compression_algorithms_server_to_client;
    };

    /**
     * Return a list of the languages the server supports, when sending stuff to the client.
     *
     * @return Array
     */
    this.getLanguagesServer2Client = function() {
        return this.languages_server_to_client;
    };

    /**
     * Return a list of the languages the server supports, when receiving stuff from the client.
     *
     * @return Array
     */
    this.getLanguagesClient2Server = function() {
        return this.languages_client_to_server;
    };

    /**
     * Returns the server public host key.
     *
     * Caching this the first time you connect to a server and checking the result on subsequent connections
     * is recommended.  Returns false if the server signature is not signed correctly with the public host key.
     *
     * @return Mixed
     */
    this.getServerPublicHostKey = function(){
        signature = this.signature;
        server_public_host_key = this.server_public_host_key;

        extract(unpack("Nlength", this._string_shift(server_public_host_key, 4)));
        this._string_shift(server_public_host_key, length);

        switch (this.signature_format) {
            case "ssh-dss":
                temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
                p = new Math_BigInteger(this._string_shift(server_public_host_key, temp["length"]), -256);

                temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
                q = new Math_BigInteger(this._string_shift(server_public_host_key, temp["length"]), -256);

                temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
                g = new Math_BigInteger(this._string_shift(server_public_host_key, temp["length"]), -256);

                temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
                y = new Math_BigInteger(this._string_shift(server_public_host_key, temp["length"]), -256);

                /* The value for "dss_signature_blob" is encoded as a string containing
                   r, followed by s (which are 160-bit integers, without lengths or
                   padding, unsigned, and in network byte order). */
                temp = unpack("Nlength", this._string_shift(signature, 4));
                if (temp["length"] != 40) {
                    user_error("Invalid signature", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                r = new Math_BigInteger(this._string_shift(signature, 20), 256);
                s = new Math_BigInteger(this._string_shift(signature, 20), 256);

                if (r.compare(q) >= 0 || s.compare(q) >= 0) {
                    user_error("Invalid signature", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                w = s.modInverse(q);

                u1 = w.multiply(new Math_BigInteger(sha1(this.session_id), 16));
                u1 = u1.divide(q)[1];

                u2 = w.multiply(r);
                u2 = u2.divide(q)[1];

                g = g.modPow(u1, p);
                y = y.modPow(u2, p);

                v = g.multiply(y);
                v = v.divide(p)[1];
                v = v.divide(q)[1];

                if (!v.equals(r)) {
                    user_error("Bad server signature", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }

                break;
            case "ssh-rsa":
                temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
                e = new Math_BigInteger(this._string_shift(server_public_host_key, temp["length"]), -256);

                temp = unpack("Nlength", this._string_shift(server_public_host_key, 4));
                n = new Math_BigInteger(this._string_shift(server_public_host_key, temp["length"]), -256);
                nLength = temp["length"];

                /*
                temp = unpack("Nlength", this._string_shift(signature, 4));
                signature = this._string_shift(signature, temp["length"]);

                if (!class_exists("Crypt_RSA")) {
                    require_once("Crypt/RSA.php");
                }

                rsa = new Crypt_RSA();
                rsa.setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
                rsa.loadKey(array("e" => e, "n" => n), CRYPT_RSA_PUBLIC_FORMAT_RAW);
                if (!rsa.verify(this.session_id, signature)) {
                    user_error("Bad server signature", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                */

                temp = unpack("Nlength", this._string_shift(signature, 4));
                s = new Math_BigInteger(this._string_shift(signature, temp["length"]), 256);

                // validate an RSA signature per "8.2 RSASSA-PKCS1-v1_5", "5.2.2 RSAVP1", and "9.1 EMSA-PSS" in the
                // following URL:
                // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

                // also, see SSHRSA.c (rsa2_verifysig) in PuTTy"s source.

                if (s.compare(new Math_BigInteger()) < 0 || s.compare(n.subtract(new Math_BigInteger(1))) > 0) {
                    user_error("Invalid signature", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                s = s.modPow(e, n);
                s = s.toBytes();

                h = pack("N4H*", 0x00302130, 0x0906052B, 0x0E03021A, 0x05000414, sha1(this.session_id));
                h = chr(0x01) . str_repeat(chr(0xFF), nLength - 3 - strlen(h)) . h;

                if (s != h) {
                    user_error("Bad server signature", E_USER_NOTICE);
                    return this._disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
        }

        return this.server_public_host_key;
    };
}).call(ssh2.prototype);

exports.createConnection = function(port, host, callback) {
    var socket = new ssh2(port, host);
    socket.connect(callback);
    return socket;
};
