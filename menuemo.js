var nIntervIdUp;
var nIntervIdDown;
var edown=1;
var emoSize=220;


function emomove(){
    if(edown==1){
        //edown=0;
        fastUp();
        //emoUp()
    }else{
        //edown=1;
        fastDown();
        emoDown();
    }
}

function emoUp(){
    edown=0;
    if(nIntervIdDown!=undefined){
        clearInterval(nIntervIdDown);
    }
    nIntervIdUp = setInterval(pushUp, 5);
}

function emoDown(){
    edown=1;
    if(nIntervIdUp!=undefined){
        clearInterval(nIntervIdUp);
    }
    nIntervIdDown = setInterval(pushDown, 5);
}

function fastDown(){
    document.getElementById('emomenu').style.height='0px';
    document.getElementById('emoimg').style.height='0px';
    //document.getElementById('emoimg').scrollTop=0;
    edown=1;
}

function fastUp(){
    document.getElementById('emomenu').style.height= emoSize +'px';
    document.getElementById('emoimg').style.height='178px';
    //document.getElementById('emoimg').scrollTop=0;
    resizeScreenEmo();
    edown=0;
}

function pushUp(){
    var emenu = document.getElementById('emomenu');
    var len = emenu.style.height;
    if(len.substr(0,len.length-2)<emoSize){
        emenu.style.height = (parseInt(len.substr(0,len.length-2))+20) + "px";
    }else{
        clearInterval(nIntervIdUp);
        resizeScreenEmo();
        document.getElementById('emoimg').style.height='178px';
    }
}

function pushDown(){
    var emenu = document.getElementById('emomenu');
    var len = emenu.style.height;
    if(len.substr(0,len.length-2)>0){
        emenu.style.height = (parseInt(len.substr(0,len.length-2))-20) + "px";
    }else{
        clearInterval(nIntervIdDown);
        resizeScreen();
        document.getElementById('emoimg').style.height='0px';
        document.getElementById('emoimg').scrollTop=0;
    }
}




function getCaretPosition(editableDiv) {
    var caretPos = 0, containerEl = null, sel, range;
    if (window.getSelection) {
        sel = window.getSelection();
        if (sel.rangeCount) {
            range = sel.getRangeAt(0);
            if (range.commonAncestorContainer.parentNode == editableDiv) {
                caretPos = range.endOffset;
            }
        }
    } else if (document.selection && document.selection.createRange) {
        range = document.selection.createRange();
        if (range.parentElement() == editableDiv) {
            var tempEl = document.createElement("span");
            editableDiv.insertBefore(tempEl, editableDiv.firstChild);
            var tempRange = range.duplicate();
            tempRange.moveToElementText(tempEl);
            tempRange.setEndPoint("EndToEnd", range);
            caretPos = tempRange.text.length;
        }
    }
    return caretPos;
}


/*function insertAtCaret(areaId,text) {



    var txtarea = document.getElementById(areaId);
    //txtarea.focus();
    var scrollPos = txtarea.scrollTop;
    var strPos = 0;
    var br = ((txtarea.selectionStart || txtarea.selectionStart == '0') ?
        "ff" : (document.selection ? "ie" : false ) );
    if (br == "ie") {
        txtarea.focus();
        var range = document.selection.createRange();
        range.moveStart ('character', -txtarea.value.length);
        strPos = range.text.length;
    }
    else if (br == "ff") strPos = txtarea.selectionStart;
    strPos = getCaretPosition(txtarea);

    var aux = '';
    var auxT = txtarea.innerHTML;
    var flag=true;
    var end=0;
    for(var i= 0,j=0;i<auxT.length,j<strPos;i++){
        var char = auxT.substring(i,i+1);
        if(char!='<' && flag){
            aux+=char;
            j++;
        }else if (char=='>'){
            flag=true;
        }else{
            flag=false;
        }
        end = i;
    }
    //alert(auxT);
    //alert('front: ' + front);
    var front = aux;
    var back = (auxT).substring(i,auxT.length);
    //alert('back: ' + back);
    txtarea.innerHTML=front+text+back;
    strPos = strPos + text.length;
    if (br == "ie") {
        txtarea.focus();
        var range = document.selection.createRange();
        range.moveStart ('character', -txtarea.value.length);
        range.moveStart ('character', strPos);
        range.moveEnd ('character', 0);
        range.select();
    }
    else if (br == "ff") {
        txtarea.selectionStart = strPos;
        txtarea.selectionEnd = strPos;
        txtarea.focus();
    }
    txtarea.scrollTop = scrollPos;
}
*/

function resizeScreenEmo(){
    var elem = document.getElementById('contenido');
    elem.style.height = (window.innerHeight - 70 - emoSize) + "px";
    elem.scrollTop = elem.scrollHeight;
}

function getMedia(){
    navigator.getMedia = ( navigator.getUserMedia ||
        navigator.webkitGetUserMedia ||
        navigator.mozGetUserMedia ||
        navigator.msGetUserMedia);

    navigator.getMedia (

        // constraints
        {
            //video: true,
            audio: true
        },

        // successCallback
        function(localMediaStream) {
            alert('SUCCESS');
            var video = document.querySelector('audio');
            video.src = window.URL.createObjectURL(localMediaStream);
            video.onloadedmetadata = function(e) {
                // Do something with the video here.
            };
        },

        // errorCallback
        function(err) {
            console.log("The following error occured: " + err);
            alert(err.name + "," + err.message );
        }

    );
}
