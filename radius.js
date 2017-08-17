'use strict';
var radius = require('radius');
var dgram = require("dgram");
var AuthenticationContext  = require('adal-node').AuthenticationContext;
var fs = require('fs');
var https = require('https');

 
function RadiusServer(settings) {
    this.config = settings || {};
    this.port = this.config.port || 1645;
    this.secret = this.config.secret || "";
    this.server = null;
 
    this.ACCESS_REQUEST = 'Access-Request';
    this.ACCESS_DENIED = 'Access-Reject';
    this.ACCESS_ACCEPT = 'Access-Accept';
};
RadiusServer.prototype.start = function () {
    var self = this;
     
    // create the UDP server
    self.server = dgram.createSocket("udp4");
     
    self.server.on('message', function (msg, rinfo) {
        if (msg && rinfo) {
 
            // decode the radius packet
            var packet;
            try {
                packet = radius.decode({ packet: msg, secret: self.secret });
            }
            catch (err) {
                console.log('Unable to decode packet.');
                return;
            }
   
            // if we have an access request, then
            if (packet && packet.code == self.ACCESS_REQUEST) {
                 
                // get user/password from attributes
                var username = packet.attributes['User-Name'];
                var password = packet.attributes['User-Password'];
 
                // verify credentials, make calls to 3rd party services, then set RADIUS response
                // var responseCode = self.ACCESS_DENIED;
                // if (username == "test" && password == "test") {
                    // responseCode = self.ACCESS_ACCEPT;
                // }
				
				var authorityHostUrl = 'https://login.windows.net';
				var tenant = 'sillawatmycostech.onmicrosoft.com';
				var authorityUrl = authorityHostUrl + '/' + tenant;
				var clientId = '83f3ce0c-f50c-4838-8975-97b5e411d7fe';
				var resource = '00000002-0000-0000-c000-000000000000';
				

				var context = new AuthenticationContext(authorityUrl);

				context.acquireTokenWithUsernamePassword(resource, username, password, clientId, function(err, tokenResponse) {
				  if (err) {
					console.log('well that didn\'t work: ');
					ReplyServerResponse(self.ACCESS_DENIED, username, packet, self, rinfo);
				  } else {
					console.log(tokenResponse);
					ReplyServerResponse(self.ACCESS_ACCEPT, username, packet, self, rinfo);
				  }
				});
                 
                
            }
        }
    });
     
    self.server.on('listening', function () {
        var address = self.server.address();
        console.log('Radius server listening on port ' + address.port);
    });
     
    self.server.bind(self.port);
};

function ReplyServerResponse(responseCode, username, packet, listener, rinfo)
{
	console.log('Access-Request for "' + username + '" (' + responseCode + ').');
	 
	// build the radius response
	var response = radius.encode_response({
		packet: packet,
		code: responseCode,
		secret: listener.secret
	});

	// send the radius response
	listener.server.send(response, 0, response.length, rinfo.port, rinfo.address, function (err, bytes) {
		if (err) {
			console.log('Error sending response to ', rinfo);
			console.log(err);
		}
	});
};
 
var rServer = new RadiusServer({ port: 1645, secret: "MySecret" });
rServer.start();