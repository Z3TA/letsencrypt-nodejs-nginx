/*
	The MIT License (MIT)
	
	Copyright (c) 2016 Johan Zetterberg
	
	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:
	
	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.
	
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
	
*/

"use strict";

var PORT = 8094; // Run the HTTP server on this port, witch need to be configured in a nginx config file:
/*
	
	# Lets encrypt challange
	location /.well-known/acme-challenge/ {
	proxy_pass http://127.0.0.1:8094;
	proxy_set_header Host $http_host;
	proxy_set_header        X-Real-IP       $remote_addr;
	}
	
*/

var CERT_BASE_PATH = "/tank/ssl/cert/"; // path to certification files (used by nginx)
var KEYS_BASE_PATH = "/tank/ssl/keys/"; // path to crypto keys! (used by nginx)

/*
	
	sudo mkdir /tank/ssl/cert/ /tank/ssl/keys/ -p
	sudo useradd -r -s /bin/false letsencrypt
	sudo chown letsencrypt:letsencrypt /tank/ssl/cert/ /tank/ssl/keys/
	sudo chmod 755 /tank/ssl/cert/
	sudo chmod 750 /tank/ssl/keys/
	
	Do I need to add nginx to letsencrypt group?
	
	Usage: sudo -u letsencrypt node letsencrypt.js yourdomain.com
	
	If no domain is supplied to the argument, all existing domains will be checked for expire date and automaticly renewed.
	
	crontab "installation"
	----------------------
	crontab -u letsencrypt -e
	
	45 7,19 * * *       node /tank/nodejs/letsencrypt.js
	
	Change the first value (minute 45), and hours 7,19 to a "random" value to somewhat ease the load on the ACME servers
	
*/

var MAX_EXPIRE_HOURS = 120; // Renew the certificate if it expires in less then 

var ADMIN_EMAIL = "zeta@zetafiles.org"; // Change this to your own e-mail address!

var ACME_URL = "https://acme-v01.api.letsencrypt.org/directory"; // Change this to production after testing! 
/*
	testing url= https://acme-staging.api.letsencrypt.org/directory
	
	Do your tests before switching to
	
	prod url= https://acme-v01.api.letsencrypt.org/directory
	
	Remove letsencrypt-account.json (and recreate letsencrypt-acccount.key), as well as all created certificates, when switching to prod
	
	sudo rm /tank/ssl/keys/letsencrypt-account.json
	sudo rm /tank/ssl/keys/letsencrypt-account.key
	
*/


// Option flags
var revoke = false; // This is not implemented, but contributions are welcome! (call revoke-cert)
var logall = true;  // If set to false, only writes to console log if it's "imporant""
var checkDomain;    // The domain to check

for(var i=2; i<process.argv.length; i++) {
	if(process.argv[i].substr(0, 1) != "-") checkDomain = process.argv[i].trim()
	else if(process.argv[i] == "-silent") logall = false
	else if(process.argv[i] == "-revoke") revoke = true // Not yet implemented
}


// Functions to manage ACME challenges
var challengeCache = {};
var challengeStore = {
	set: function setChallenge(hostname, key, value, cb) {
		log("challengeStore.set: hostname=" + hostname + " key=" + key + " value=" + value);
		challengeCache[key] = value;
		
		cb(null);
		
	}
	, get: function getChallengeAnswer(hostname, key, cb) {
		log("challengeStore.get: hostname=" + hostname + " key=" + key);
		
		cb(null, challengeCache[key]);
	}
	, remove: function removeChallenge(hostname, key, cb) {
		log("challengeStore.remove: hostname=" + hostname + " key=" + key);
		
		delete challengeCache[key];
		
		cb(null);
	}
};

// Functions to manage certificates
var certCache = {};
var certStore = {
	set: function storeCertificate(hostname, certs, cb) {
		log("certStore.set: hostname=" + hostname + " certs=" + certs);
		
		if(certs == undefined) {
			console.warn("certStore: certs is undefined!")
			cb(null);
		}
		else {
			
			certCache[hostname] = certs;
			
			var counter = 0;
			var countUntil = 2; // Wait until all two files has been created before calling callback function
			
			/*
				fs.writeFile("ca.pem", certs["ca"], function(err) {
				if (err) throw err;
				log("ca.pem created");
				if(++counter==countUntil) cb(null);
				});
				fs.writeFile("cert.pem", certs["cert"], function(err) {
				if (err) throw err;
				log("cert.pem created");
				if(++counter==countUntil) cb(null);
				});
			*/
			
			fs.writeFile(KEYS_BASE_PATH + hostname + ".key", certs["key"], function(err) {
				if (err) throw err;
				log(hostname + ".key created");
				if(++counter==countUntil) cb(null);
			});
			// Nginx needs both the cert and "ca" concatenated
			fs.writeFile(CERT_BASE_PATH + hostname + ".crt", certs["cert"] + "\n" + certs["ca"], function(err) {
				if (err) throw err;
				log(hostname + ".crt created");
				if(++counter==countUntil) cb(null);
			});
			
		}
	}
	, get: function retrieveCert(hostname, cb) {
		log("certStore.get: hostname=" + hostname);
		cb(null, certCache[hostname]);
	}
	, remove: function deleteCert(hostname, cb) {
		log("certStore.remove: hostname=" + hostname);
		delete certCache[hostname];
		cb(null);
	}
};


var fs = require("fs"); // Load nodeJS file library into the fs variable


// Check if account.key file exist
var accountKeyPath = KEYS_BASE_PATH + "letsencrypt-account.key"
try {
	var ACCOUNT_KEY = fs.readFileSync(accountKeyPath);
}
catch(err) {
	if(err.code=="ENOENT") {
		log(accountKeyPath + " does not exist. Create it using:\nsudo sh -c 'openssl genrsa 4096 > " + accountKeyPath + "' && sudo chown letsencrypt:letsencrypt " + accountKeyPath + " && sudo chmod 700 " + accountKeyPath + "\n", true);
		process.exit();
	}
	else throw err;
}






// Create a HTTP server to use for ACME challenges
var http = require('http');
var httpServer = http.createServer(acmeResponder);
function acmeResponder(req, res) {
	
	var addr = req.url;
	var ip = req.headers["x-real-ip"] ? req.headers["x-real-ip"] : req.connection.remoteAddress;
	
	log("Request to " + addr + " from " + ip + "");
	
	if (0 !== req.url.indexOf(LeCore.acmeChallengePrefix)) {
		res.end('Hello World!');
		return;
	}
	
	var key = req.url.slice(LeCore.acmeChallengePrefix.length);
	
	var hostname = req.headers["x-host"] || req.hostname;
	
	challengeStore.get(hostname, key, function (err, val) {
		res.end(val || 'Error');
	});
}
var http_server_running = false;



var LeCore = require('letiny-core'); // This is an important dependency (npm install letiny-core)

var accountJson = KEYS_BASE_PATH + "letsencrypt-account.json";

// Get the ACME URL's used to make commands like new-cert, new-reg and revoke-cert
var ACME_URLS;

log("Getting urls");
LeCore.getAcmeUrls(ACME_URL, function (err, urls) {
	
	if(err) throw err;
	
	log("Got urls: " + urls);
	ACME_URLS = urls;
	
	// Check if letsencrypt-account.json exist, if not, we have probably not registered. Remove this file (and account.key) when switching from staging to live/prod
	try {
		fs.readFileSync(accountJson)
	}
	catch(err) {
		if(err.code=="ENOENT") {
			// This means we have probably not registered. Register an account, then run the main function.
			return registerNewAccount(main);
		}
		else throw err;
	}
	
	// If the read was successful
	return main();
	
});



function main() {
	
	if(checkDomain) {
		
		checkNginxCnf(checkDomain, function(err) {
			
			if(err) throw err;
			
			checkCertRenewal(checkDomain, function(err, renewNeeded) {
				if(err) throw err;
				
				log("renewNeeded=" + renewNeeded);
				
				if(renewNeeded) {
					getCert(checkDomain, function(err, certs) {
						if(err) throw err;
						log(checkDomain + " renewed");
						exit();
					});
				}
				else return exit();
				
			});
			
		});
	}
	else {
		
		// Check existing domains if they need renewal
		fs.readdir(CERT_BASE_PATH, function listCerts(err, files) {
			
			if(files == undefined) {
				log("Did not find any (certiface) files in " + CERT_BASE_PATH, true);
				process.exit();
			}
			
			var leftToCheck = files.length;
			var errors = [];
			
			if(leftToCheck == 0) log("No certificates found!", true)
			else {
				files.forEach(function checkFile(fileName) {
					
					// Remove the .crt part from file name
					var checkDomain = fileName.substring(0, fileName.length-4);
					
					log("Checking " + checkDomain);
					
					// Make sure the nginx config is ok
					checkNginxCnf(checkDomain, function(err) {
						
						if(err) {
							log("Problem checking nginx configuration for " + checkDomain + "", true);
							log(err.message, true);
							errors.push(err);
							doneCheck(checkDomain);
						}
						else {
							
							checkCertRenewal(checkDomain, function(err, renewNeeded) {
								
								if(err) {
									log("Problem checking if " + checkDomain + " need renewal", true);
									log(err.message, true);
									
									errors.push(err);
									doneCheck(checkDomain);
								}
								else {
									
									if(renewNeeded) {
										log("Needs renewal: " + checkDomain);
										getCert(checkDomain, function(err, certs) {
											
											if(err) {
												log("Problem requesting certificate for " + checkDomain, true);
												log(err.message, true);
												
												errors.push(err);
											}
											else {
												log(checkDomain + " renewed", true);
											}
											
											doneCheck(checkDomain);
											
										});
									}
									else doneCheck(checkDomain);
								}
							});
						}
						
					});
				});
			}
			
			function doneCheck(checkDomain) {
				leftToCheck--;
				log("Handled " + checkDomain + ". " + leftToCheck + " domains left to check.")
				
				if(leftToCheck === 0) {
					
					if(errors.length > 0) {
						var messages = "";
						for (var i=0; i<errors.length; i++) {
							messages += errors[i].message + "\n";
						}
						throw new Error("One or more errors occured. Check the log file!\n" + messages);
					}
					
					exit();
					
				}
			}
			
			
		});
	}
	
}


function exit() {
	// Close the server
	if(http_server_running) {
		httpServer.close();
		log("Closed HTTP server")
	}
}



function checkNginxCnf(checkDomain, callback) {
	// Make sure it exist in nginx enabled sites and is configurated to redirect ACME challanges
	
	var fs = require("fs");
	
	var nginxCfgPath = "/etc/nginx/sites-enabled/" + checkDomain;
	
	fs.readFile(nginxCfgPath, "utf8", function readNginxCnf(err, nginxCnf) {
		if (err) {
			
			if(err.code=="ENOENT") {
				
				// Allow naked domain ...
				var parts = checkDomain.match(/(.*)\.(.*)\.(.*)/);
				
				if(parts) {
					if(parts.length == 4) {
						var subdomain = parts[1];
						var domain = parts[2];
						var tld = parts[3];
						
						nginxCfgPath = "/etc/nginx/sites-enabled/" + domain + "." + tld;
						
						log("Unable to find nginx config file for " + checkDomain + " checking " + domain + "." + tld + " instead ...");
						
						fs.readFile(nginxCfgPath, "utf8", function readNginxCnfNaked(err, nginxCnf) {
							if (err) {
								if(err.code=="ENOENT") noNginxConfigFound();
								else throw err;
							}
							else checkNginxCnfContent(nginxCnf);
							
						});
						
					}
					else {
						throw new Error("Expected parts.length=" + parts.length + " to be 4 ! parts=" + JSON.stringify(parts));
					}
				}
				else noNginxConfigFound();
				
			}
			else throw err;
			
		}
		else checkNginxCnfContent(nginxCnf);
		
		function checkNginxCnfContent(nginxCnf) {
			
			// Why doesn't multi-line regex work??
			//var acmeChallenge = new RegExp("location \/\.well-known\/acme-challenge\/ {\s+proxy_pass http:\/\/127\.0\.0\.1:" + PORT + ";", "img");
			//var hasAcmeChallenge = nginxCnf.match(acmeChallenge);
			
			var hasAcmeChallenge = nginxCnf.indexOf("location /.well-known/acme-challenge/") != -1 && 
			nginxCnf.indexOf("proxy_pass http://127.0.0.1:" + PORT + ";") != -1;
			
			var hasServerName = nginxCnf.match(new RegExp("server_name .*" + checkDomain));
			
			//log("hasAcmeChallenge=" + hasAcmeChallenge);
			
			if(hasAcmeChallenge && hasServerName) {
				log("nginx config for " + checkDomain + " OK!");
				
				if(callback) return callback(null);
			}
			else {
				
				var err = new Error(checkDomain + " is not configured with /.well-known/acme-challenge");
				
				if(callback) return callback(err)
				else throw err;
				
			}
		}
		
		function noNginxConfigFound() {
			var err = new Error("No nginx configuration file for " + checkDomain + " exist! (" + nginxCfgPath + ")");
			
			if(callback) return callback(err)
			else throw err;
		}
	});
}


function checkCertRenewal(checkDomain, callback) {
	// Check if the certificate exist, and if it needs to be renewed
	
	if(callback == undefined) throw new Error("No callback defined in function argument");
	
	var certPath = CERT_BASE_PATH + checkDomain + ".crt";
	
	//log("Reading certPath=" + certPath + " ...");
	
	
	fs.readFile(certPath, "utf8", function readCert(err, cert) {
		
		if (err) {
			if(err.code=="ENOENT") {
				
				log(certPath + " does not exist! So it needs *renewal*", true);
				
				return callback(null, true);
				
			}
			else {
				log("Error reading certPath=" + certPath + " Error: " + err.message);
				return callback(err);
			}
		}
		
		// Check if it needs to be renewed
		var ssl = require('ssl-utils');
		ssl.checkCertificateExpiration(cert, function gotDate(err, expiry) {
			//expiry is a Date instance
			//log("expiry=" + expiry);
			
			if(err) {
				log("Error checking expire date for domain=" + checkDomain + " Errror: " + err.message);
				callback(err);
			}
			else {
				var remainingTime = expiry.getTime() - Date.now();
				//log("remainingTime=" + remainingTime);
				
				var remainingHours = Math.round(remainingTime / (1000 * 60 * 60));
				//log(checkDomain + " remainingHours=" + remainingHours);
				
				log(remainingHours + " hours left until " + checkDomain + " expires");
				
				if(remainingHours < MAX_EXPIRE_HOURS) {
					return callback(null, true);
				}
				else {
					return callback(null, false);
				}
			}
			
		});
		
	});
}


function registerNewAccount(callback) {
	
	// Registers a new lets encrypt account, that will be used for creating certificates
	
	var LeCore = require('letiny-core');
	
	LeCore.registerNewAccount(
	{ newRegUrl: ACME_URLS.newReg
		, email: ADMIN_EMAIL
		, accountPrivateKeyPem: ACCOUNT_KEY
		, agreeToTerms: function agreeToTerms(tosUrl, done) {
			
			log("agreeToTerms: tosUrl=" + tosUrl);
			
			// agree to the exact version of these terms
			done(null, tosUrl);
		}
	}
	, function registered(err, regr) {
		
		if(err) throw err;
		
		//log("regr=" + JSON.stringify(regr));
		
		// This data might become useful later ... So lets save it
		fs.writeFile(accountJson, JSON.stringify(regr, null, 2), function accountJsonCreated(err) {
			
			if (err) throw err;
			log(accountJson + " created");
			
			if(callback) callback(null);
			
		});
		
	});
}


function getCert(domain, callback) {
	
	var LeCore = require('letiny-core');
	
	var domains = [domain]; // Needs to be an array
	
	log("Getting certificate for domain=" + domain);
	
	// Always create a new key (change the locks) when creating a new certificate
	LeCore.leCrypto.generateRsaKeypair(2048, 65537, function (err, pems) {
		if(err) throw err;
		//log(pems);
		var domainPrivateKeyPem = pems.privateKeyPem;
		
		if(!http_server_running) { // Only start the server if it hasn't already started
			http_server_running = true;
			httpServer.listen(PORT, function () {
				log('Started HTTP server on ' + this.address());
				
				getCertificate();
			});
		}
		else {
			log("HTTP server already running");
			getCertificate();
		}
		
		function getCertificate() {
			LeCore.getCertificate(
			{ newAuthzUrl: ACME_URLS.newAuthz
				, newCertUrl: ACME_URLS.newCert
				
				, domainPrivateKeyPem: domainPrivateKeyPem
				, accountPrivateKeyPem: ACCOUNT_KEY
				, domains: domains
				
				, setChallenge: challengeStore.set
				, removeChallenge: challengeStore.remove
			}
			, function (err, certs) {
				
				if(err) {
					log("Error getting certificate for domain=" + domain + " Error: " + err.message);
					if(callback) callback(err)
					else throw err;
				}
				else {
					//log("certs=" + JSON.stringify(certs));
					
					log("Received certificate for ... ");
					
					// Note: you should save certs to disk (or db)
					certStore.set(domains[0], certs, function (err) {
						
						if(err) {
							if(callback) callback(err)
							else throw err;
						}
						else {
							log("Files saved");
							if(callback) callback(null, certs);
						}
					});
				}
			}
			);
			
		}
		
	});
	
}

function log(msg, important) {
	if(logall || important) console.log(msg);
}

