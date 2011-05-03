var SSH2 = require("./../lib/ssh2");
// turn ON logging:
SSH2.NET_SSH2_LOGGING = SSH2.NET_SSH2_LOG_COMPLEX;

SSH2.createConnection("localhost", 22, function(err, conn) {
    console.log("DONE!", err);
});