/**
 * Created by dev team on 07/10/13.
 */

var cop = function()
{
    var metadata;
    var ain;
    var aout;
}

var cmeta = function()
{
    var name;
    var code;
    var format;
    var session;
    var server;
}


var cin = function()
{
    var name;
    var type;
    var value;
}

var cout = function()
{
    var name;
    var type;
    var array;
}

var machine = (function() {
    var fileversion = 'js/conv004.xml';
    var operations;
    var status = 'closed';

    return { // public interface
        load: function () {
            //init operations
            operations = {};

            if (window.XMLHttpRequest)
            {// code for IE7+, Firefox, Chrome, Opera, Safari
                xhr = new XMLHttpRequest({ mozSystem: true });
            }
            else
            {// code for IE6, IE5
                xhr = new ActiveXObject("Microsoft.XMLHTTP");
            }
            xhr.open("GET",fileversion,true);
            xhr.send();

            xhr.onload = function (e) {
                if (xhr.readyState === 4) {
                    if (xhr.status === 200) {
                        //
                        var response = xhr.responseXML;

                        //load operations
                        var ops = response.getElementsByTagName('op');
                        //read ins and outs
                        for(var i=0;i<ops.length;i++){//loop operations
                            var op = ops[i];
                            //loading meta info
                            var meta = new cmeta();
                            meta.name = op.getAttribute('name');
                            meta.code = op.getAttribute('code');
                            meta.format = op.getAttribute('format');
                            meta.session = op.getAttribute('array');
                            meta.server = op.getAttribute('server');

                            var ins = op.getElementsByTagName('in');
                            var list_ins = [];
                            for(var j=0;j<ins.length;j++){
                                var auxin = new cin();
                                auxin.name = ins[j].getAttribute('name');
                                auxin.type = ins[j].getAttribute('type');
                                auxin.value = ins[j].getAttribute('value');
                                list_ins.push(auxin);
                            }

                            var outs = op.getElementsByTagName('out');
                            var list_outs = [];
                            for(var k=0;k<outs.length;k++){
                                var auxout = new cout();
                                auxout.name=outs[k].getAttribute('name');
                                auxout.type=outs[k].getAttribute('type');
                                auxout.array=outs[k].getAttribute('array');
                                list_outs.push(auxout);
                            }
                        }
                        //fill in op var
                        var aop = new cop();
                        aop.metadata = meta;
                        aop.ain = list_ins;
                        aop.aout = list_outs;

                        //store operation
                        operations[aop.metadata.name] = aop;

                        //finally
                        status='opened';

                        //test decode
                        machine.runOp();
                    } else {
                        console.error('error connecting to the xml: ' + xhr.status);
                    }
                }
            };
            xhr.onerror = function (e) {
                console.error('reconnect2 get xml op file');
            };
        },
        runOp: function (opename, inarray, callback) {
            if(status==='opened'){
                var op =  operations['decode'];
                console.info('server ' + op.metadata.server);
            }
        }
    };
})();
