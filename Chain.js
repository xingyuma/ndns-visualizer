
var Chain = function (paper,_id1, _id2) {
    this.id1 = _id1;
    this.id2 = _id2;
    this.paper = paper;
    var self = this;
    
    this.outputKeyChain = function(_keyname,_domainstack, _id) {
//        var paper = Raphael(150, 150, 800, 1800);
        this.paper.clear();
/*        for (var i = 0; i < _keyname.length; i++) {
            var width = 400;
            var height  = 50;
            var x = 40 ;
            var y = 40 + i * 100;
            var rect = paper.rect(x, y , width, height, 10);
            console.log(i);
            var t = paper.text(x+200, y+20, _keyname[i]);
            t.attr("font-size", 10);
        }
  */
        var cnt = 0;
//        var lastx = 0;
        var lasty = 0;
        var nowy = 0;
        var start = [];
        var end = [];
        var group = [];
        var num = 0;
        for (var i = 0; i < _keyname.length; i++) {
            console.log(i+"  "+_domainstack[i][0]);
            cnt += 1;

/*            var rect = paper.rect(50, nowy + 80, 400, 50, 10);
            var t = paper.text(150, nowy+90, _domainstack[i][1]);
            var t = paper.text(250, nowy+110, _keyname[i]);
            nowy += 80;
 */
            group[i] = num;
            if (i == _keyname.length -1 || _domainstack[i][0] != _domainstack[i+1][0]) {
                var width = 500;
                var height  = 100;
                var x = 40;
                var y = lasty + 40 ;
                var rect = this.paper.rect(x, y , width, height*cnt, 10);
                var t = this.paper.text(x+200, y+20, _domainstack[i][0]);
                lasty = y + height * cnt;
                start[num] = y;
                end[num] = lasty;
                num ++;
                nowy = lasty;
//                console.log(i);
                cnt = 0;
            }
        }
        
        for (var i = 0; i < num - 1; i++) {
            var c = this.paper.image("Arrow.gif",400,end[i]+5, 40, start[i+1] - end[i] - 10);
        }
        
        cnt = 0;
        var keystart = [];
        for (var i = 0; i  < _keyname.length; i++) {
            var y = start[group[i]] + 50 + cnt*80;
            keystart[i] = y;
            var rect = this.paper.rect(50, y, 400,50,10);
            var t = this.paper.text(150, y + 20, _domainstack[i][1]);
            var t = this.paper.text(250, y + 40, _keyname[i]);
        

            
            if (i > 0 &&  group[i] == group[i-1]) {
                cnt = 0;
            }
            else cnt++;
        }
        
        for (var i = 0 ; i < _keyname.length -1 ; i++) {
            var line_str = "M 100 " + (keystart[i] + 50)  +"L 100 "+ (keystart[i+1] -5 );
            var c = this.paper.path(line_str);
            c.attr("stroke-width",2);
            c.attr("arrow-end","classic-wide-long");
//            var c = paper.image("Arrow.gif",100,keystart[i] + 50, 100, keystart[i+1] -
//                                keystart[i] - 50 , 30);
        }
//                paper.clear();
    }
    
    this.getChain = function(_list) {
        /*query chain*/
        var tmp  = [];
        for (var i = 0 ; i < _list.length; i++) {
           tmp[i] = _list[i].name.to_uri();
        }
//        self.outputKeyChain(tmp,self.id2);
        
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
                    console.log(_name.getPrefix(i-3));
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
/*                var tmp_name = new Name();
                for (var j = 1 ; j < i ; j++) {
                    if (strArray[j] != "DNS") {
                        tmp_name.append(strArray[j]);
                    }
                }
                return [tmp_name.to_uri(),strArray[i]];
 */           }
        }
        return null;
    }
    
    this.showQueryChain = function(result) {
/*        for (var i =  0 ; i < result.length; i++) {
            console.log(result[i]);
        }
 */
//        self.output(result);
    }
    
    this.showChain = function(result) {
        var domainStack = [];
        var keyName = [];
        for (var i = 0 ; i < result.length; i++) {
            keyName[i] = result[i].name.to_uri();
            if (self.parseNDNCertName(result[i].name) != null) {
                console.log(self.parseNDNCertName(result[i].name) );
                domainStack.push(self.parseNDNCertName(result[i].name));
//                console.log(ret);
            }
        }
        self.outputKeyChain(keyName,domainStack,self.id1);
        
    };
};