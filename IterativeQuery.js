

var onTimeout = function (interest) {
    console.log("Interest time out.");
    console.log('Interest name: ' + interest.name.to_uri());
    handle.close();
};


// Convert DNS name string to NDN Name object.
var ndnify = function (str) {
    var arr = str.split('.');
    var n = new Name();
    for (var i = arr.length - 1; i >= 0; i--) {
	if (arr[i].length == 0)
	    continue;
	
	n.append(arr[i]);
    }
    return n;
};

// Convert NDN Name object to DNS name string.
var dnsify = function (name) {
    var str = '';
    for (var i = name.size() - 1; i >= 0; i--) {
	str += Name.toEscapedString(name.components[i]) + '.';
    }
    return str;
};

// 'Relativize' dname against zone.
var relativize = function (dname, zone) {
    if (zone == null || zone.length == 0 || zone == '.')
	return dname;

    var zpos = dname.length - zone.length;
    if (dname.substr(zpos) == zone)
	return dname.substr(0, zpos);
    else
	return dname;
};

// 'hint' and 'zone' are NDN Name objects while 'lable' and 'rrtype' are strings.
var generateQuestion = function (hint, zone, lable, rrtype) {
    var q = new Name();
    q.append(zone).append('DNS');

    if (lable != null)
	q.append(ndnify(lable));
    
    if (rrtype != null)
	q.append(rrtype);

    if (hint != null && hint.size() > 0 && !hint.isPrefixOf(q)) {
	q = new Name().append(hint).append('%F0.').append(q);;
    }

    return q;
};

var IterativeQuery = function IterativeQuery() {
    
    this.ans = null;
    
    this.query = function (o_name, o_rrtype,callback) {
//        console.log("callback  "+callback);
    var handle = new NDN();

    handle.onopen = function () {
	var question = (o_name).split('/').slice(1);
	question.push(o_rrtype);
	var iter = 0;
	var rrtype = 'NS';
	var zone = new Name();
	var hint = new Name();
	var lastq = false;
    var queryStack = new Array();

    var NdnsPolicy = new IdentityPolicy(
                                            // anchors
                                            [
                                             { key_name: new Name("/ndn/keys/ucla.edu/alex/%C1.M.K%00F%8D%E9%C3%EE4%7F%C1Mjqro%C6L%8DGV%91%90%03%24%ECt%95n%F3%9E%A6i%F1%C9"),
                                             namespace: new Name("/"),
                                             key: Key.createFromPEM({ pub: "-----BEGIN PUBLIC KEY-----\n" +
                                                                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSPdPM7+DjDcUGHtwEDmkq4kO5\n" +
                                                                    "tEUI05w5gR4JC1UiZxS0ckMWSLRPWXozHrpJsjNzDeI6OiQrXzup1tF2IN+Xtdr+\n" +
                                                                    "Pr3CwyBRloTJJbm5kf+pGuJh4fE9Qk0i/fS9Xs6gFup3oPnr+wFFjJObnRTrUsaM\n" +
                                                                    "8TQokOLYZFsatsZOvwIDAQAB\n" +
                                                                    "-----END PUBLIC KEY-----" }) }
                                             ],
                                            // rules
                                            [
                                             { key_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)/[^/]+/NDNCERT$"),
                                             key_pat_ext: "$1$2",
                                             data_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)$"),
                                             data_pat_ext: "$1$2" },
                                             
                                             { key_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)/[^/]+/NDNCERT$"),
                                             key_pat_ext: "$1$2",
                                             data_pat: new RegExp("^((?:/[^/]+)*)/([^/\.]+)\.([^/\.]+)/DNS((?:/[^/]+)*)$"),
                                             data_pat_ext: "$1/$3/$2$4" },
                                             
                                             { key_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)/[^/]+/NDNCERT$"),
                                             key_pat_ext: "$1$2",
                                             data_pat: /(.*)/,
                                             data_pat_ext: "$1" }
                                             ]
                                            );
        
    
	var onData = function (inst, co) {
	    console.log('Data name: ' + co.name.to_uri());
        queryStack.push(co);
        NdnsPolicy.verify(co, function (result) {
//            console.log(result);
		    if (result == VerifyResult.FAILURE) {
			console.log('Verification failed.');
			return;
		    } else if (result == VerifyResult.TIMEOUT) {
			console.log('Verification failed due to timeout.');
			return;
		    }
//        console.log(co.content);
            var parser = new DnsParser(co.content);
        
		    try {
			var packet = parser.parse();
			
			if (lastq) {
			    console.log('Result found. Parsed DNS packet is:');
                console.log(packet);
                this.answer = co.name.to_uri();
                console.log(this.answer);
//                _chain.getVerification(this.answer);
                console.log(queryStack);
                callback(queryStack);
			    handle.close();
			    return;
			}

			if (rrtype == 'NS' && packet.answer.length > 0 && packet.answer[0].type == RRType.NS) {
			    var target = packet.answer[0].rdata.nsdname;
			    if (zone.isPrefixOf(ndnify(target))) {
				target = relativize(target, dnsify(zone));
				rrtype = 'FH';
				var qfh = generateQuestion(hint, zone, target, rrtype);
//                console.log(qfh.to_uri());
				handle.expressInterest(qfh, null, onData, onTimeout);
			    } else {
				throw new Error('NS record is in a different domain of the querying zone.');
			    }
			} else if (rrtype == 'NS' && packet.answer.length > 0 && packet.answer[0].type == RRType.NEXISTS) {
			    console.log('NS does not exist.');
			    rrtype = question[question.length - 1];
			    var last = generateQuestion(hint, zone);
			    for (var i = iter; i < question.length; i++) {
				last.append(question[i]);
			    }
			    lastq = true;
                console.log(last);
			    handle.expressInterest(last, null, onData, onTimeout);
			} else if (rrtype == 'FH' && packet.answer.length > 0 && packet.answer[0].type == RRType.FH) {
			    hint = packet.answer[0].rdata.hint;
			    rrtype = 'NS';
			    zone.append(question[iter++]);
			    var qns = generateQuestion(hint, zone, question[iter], rrtype);
                console.log(qns);
			    handle.expressInterest(qns, null, onData, onTimeout);
			}
		    } catch (e) {
			// Content is not a DNS packet.
			console.log(e.message);
			console.log('not a DNS packet.');
			handle.close();
		    }
//        console.log("dfa");
		});
	};
        
	var q = generateQuestion(hint, zone, question[iter], rrtype);
    
//    console.log("gen   "+q.to_uri());

	handle.expressInterest(q, null, onData, onTimeout);
    };

    handle.connect();
    }
};

