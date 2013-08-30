
var Chain = function (paper,_id1) {
    this.id1 = _id1;
    this.paper = paper;
    var self = this;
    
    this.outputKeyChain = function(_keyname,_domainstack) {
//        var paper = Raphael(150, 150, 800, 1800);
        this.paper.clear();
        var cnt = 0;
        var _length = 0;
        var height = 100;
        for (var i = 0; i < _keyname.length - 1; i++) {
            cnt += 1;
            if ( _domainstack[i][0] != _domainstack[i+1][0]) {
                _length = _length + 30;
                _length = _length + height * cnt;
                cnt = 0;
            }
        }
        cnt = 0;
        var lasty = _length + 30 ;
        var nowy = 0;
        var start = [];
        var end = [];
        var group = [];
        var num = 0;
        for (var i = 0; i < _keyname.length; i++) {
            cnt += 1;
            group[i] = num;
            if (i == _keyname.length -1 || _domainstack[i][0] != _domainstack[i+1][0]) {
                var width = 500;
                var height  = 85;
                var x = 40;
                var y = lasty - 30 ;
                var rect = this.paper.rect(x, y , width, height*cnt, 10);
                var t = this.paper.text(280, y+10, _domainstack[i][0]);
                t.attr("font-size",15);
                lasty = y - height * cnt;
                start[num] = y;
                end[num] = lasty;
                num ++;
                nowy = lasty;
                cnt = 0;
            }
        }
        
       for (var i = 0; i < num - 1; i++) {
//            var c = this.paper.image("../Arrow.gif",400,end[i]+5, 40, start[i+1] - end[i] - 10);
           var line_str = "M 400 " + (start[i])  +"L 400 "+ (start[i] - 30);
           var c = this.paper.path(line_str);
           c.attr("stroke-width",5);
           c.attr("arrow-end","classic-wide-long");
       }
        
        cnt = 0;
        var keystart = [];
        for (var i = 0; i  < _keyname.length; i++) {
            var y = start[group[i]] + 100 - cnt*70;
            keystart[i] = y;
            var rect = this.paper.rect(50, y, 480,50,10);
            var t = this.paper.text(280, y + 20, _domainstack[i][1]);
            t.attr("font-size",12);
            var t = this.paper.text(280, y + 40, _keyname[i]);
            t.attr("font-size",11);
            if (i > 0 &&  group[i] == group[i-1]) {
                cnt = 0;
            }
            else cnt++;
        }
 
        for (var i = 0 ; i < _keyname.length -1 ; i++) {
            var line_str = "M 100 " + (keystart[i] )  +"L 100 "+ (keystart[i+1] + 50 );
            var c = this.paper.path(line_str);
            c.attr("stroke-width",2);
            c.attr("arrow-end","classic-wide-long");
//            var c = paper.image("Arrow.gif",100,keystart[i] + 50, 100, keystart[i+1] -
//                                keystart[i] - 50 , 30);
        }
    }
    
    this.outputQuerySeq = function(_keyname,_domainstack) {
        this.paper.clear();
        var cnt = 0;
        var lasty = 0;
        var nowy = 0;
        var start = [];
        var end = [];
        var group = [];
        var num = 0;
        for (var i = 0; i < _keyname.length; i++) {
            cnt += 1;
            group[i] = num;
            if (i == _keyname.length -1 || _domainstack[i][0] != _domainstack[i+1][0]) {
                var width = 500;
                var height  = 85;
                var x = 40;
                var y = lasty + 30 ;
                var rect = this.paper.rect(x, y , width, height*cnt, 10);
                var t = this.paper.text(280, y+20, _domainstack[i][0]);
                t.attr("font-size",15);
                lasty = y + height * cnt;
                start[num] = y;
                end[num] = lasty;
                num ++;
                nowy = lasty;
                cnt = 0;
            }
        }
        
        for (var i = 1; i < num; i++) {
//            var c = this.paper.image("Arrow.gif",400,end[i]+5, 40, start[i+1] - end[i] - 10);
            var line_str = "M 400 " + (start[i] - 30)  +"L 400 "+ (start[i] );
            var c = this.paper.path(line_str);
            c.attr("stroke-width",5);
            c.attr("arrow-end","classic-wide-long");
        }
        
        cnt = 0;
        var keystart = [];
        for (var i = 0; i  < _keyname.length; i++) {
            var y = start[group[i]] + 30 + cnt*70;
            keystart[i] = y;
            var rect = this.paper.rect(50, y, 480,50,10);
            var t = this.paper.text(280, y + 20, _domainstack[i][1]);
            t.attr("font-size",12);
            var t = this.paper.text(280, y + 40, _keyname[i]);
            t.attr("font-size",12);
            if (i > 0 &&  group[i] == group[i-1]) {
                cnt = 0;
            }
            else cnt++;
        }
        for (var i = 0 ; i < _keyname.length -1 ; i++) {
            var line_str = "M 100 " + (keystart[i] + 50)  +"L 100 "+ (keystart[i+1]);
            var c = this.paper.path(line_str);
            c.attr("stroke-width",2);
            c.attr("arrow-end","classic-wide-long");
        }
    }
    
    this.outputQueryChain = function(_list) {
        var tmp  = [];
        var queryStack = [];
        var packetStack = [];
        for (var i = 0 ; i < _list.length; i++) {
            var str = _list[i].name.to_uri();
            var strArray = str.split("/");
            var domain_name = null;
            var type = null;
            for (var j = 0 ; j < strArray.length; j++) {
                if (strArray[j] == "DNS") {
                    domain_name = _list[i].name.getPrefix(j-1).to_uri();
                }
                if (strArray[j] == "FH" || strArray[j] == "NS") {
                    type = strArray[j];
                    break;
                }
            }
            queryStack.push([domain_name,type]);
            packetStack.push(_list[i].name.to_uri());
        }
        self.outputQuerySeq(packetStack,queryStack);
    }
 
    
    this.getChain = function(_list) {
        /*query chain*/        
        var iv = new IdentityPolicy(
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
        /*query to get the certificate chain*/
        iv.obtainChain(_list[_list.length - 1].name.to_uri(),self.showChain);
    };
    
    this.parseNDNCertName = function(/*name*/_name) {
        var str = _name.to_uri();
        var strArray = str.split("/");
        for (var i = 0 ; i < strArray.length; i++) {
            if (strArray[i] == "NDNCERT") {
                var tmp = strArray[i-1].split("-");
                if (tmp[0] == "zsk") {
                    if (i - 3 < 0)
                        return [new Name("/").to_uri(),"ZSK"];
//                    console.log(_name.getPrefix(i-3));
                    return [_name.getPrefix(i-3).to_uri(),"ZSK"];
                }
                if (tmp[0] == "ksk") {
                    for (var j = 0; j < i ; j++) {
                        if (strArray[j] == "DNS")
                            return [_name.getPrefix(j-1).to_uri(),"KSK"];
                    }
                }
            }
            
            if (strArray[i] == "FH" || strArray[i] == "NS") {
                for (var j = 0; j < i ; j++) {
                    if (strArray[j] == "DNS")
                        return [_name.getPrefix(j-1).to_uri(),strArray[i]];
                }
           }
        }
        return null;
    }

    this.showChain = function(result) {
        var domainStack = [];
        var keyName = [];
        for (var i = 0 ; i < result.length; i++) {
            keyName[i] = result[i].name.to_uri();
            if (self.parseNDNCertName(result[i].name) != null) {
             domainStack.push(self.parseNDNCertName(result[i].name));
            }
        }
        self.outputKeyChain(keyName,domainStack);
        
    };
};