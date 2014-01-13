// Workaround Firefox bug, uglified from sha256_asm above with little manual changes
function sha256_asm ( stdlib, foreign, buffer ) {
    return (new Function('e,t,n','"use asm";var r=0,i=0,s=0,o=0,u=0,a=0,f=0,l=0,c=0,h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0;var L=new e.Uint8Array(n);function A(e,t,n,c,h,p,d,v,m,g,y,b,w,E,S,x){e=e|0;t=t|0;n=n|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;m=m|0;g=g|0;y=y|0;b=b|0;w=w|0;E=E|0;S=S|0;x=x|0;var T=0,N=0,C=0,k=0,L=0,A=0,O=0,M=0,_=0;T=r;N=i;C=s;k=o;L=u;A=a;O=f;M=l;_=e+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1116352408|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=t+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1899447441|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=n+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3049323471|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=c+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3921009573|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=h+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+961987163|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=p+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1508970993|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=d+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2453635748|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=v+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2870763221|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=m+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3624381080|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=g+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+310598401|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=y+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+607225278|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=b+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1426881987|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=w+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1925078388|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=E+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2162078206|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=S+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2614888103|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=x+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3248222580|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;e=_=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(S>>>17^S>>>19^S>>>10^S<<15^S<<13)+e+g|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3835390401|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;t=_=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(x>>>17^x>>>19^x>>>10^x<<15^x<<13)+t+y|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+4022224774|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;n=_=(c>>>7^c>>>18^c>>>3^c<<25^c<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+n+b|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+264347078|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;c=_=(h>>>7^h>>>18^h>>>3^h<<25^h<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+c+w|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+604807628|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;h=_=(p>>>7^p>>>18^p>>>3^p<<25^p<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+h+E|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+770255983|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;p=_=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+p+S|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1249150122|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;d=_=(v>>>7^v>>>18^v>>>3^v<<25^v<<14)+(h>>>17^h>>>19^h>>>10^h<<15^h<<13)+d+x|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1555081692|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;v=_=(m>>>7^m>>>18^m>>>3^m<<25^m<<14)+(p>>>17^p>>>19^p>>>10^p<<15^p<<13)+v+e|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1996064986|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;m=_=(g>>>7^g>>>18^g>>>3^g<<25^g<<14)+(d>>>17^d>>>19^d>>>10^d<<15^d<<13)+m+t|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2554220882|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;g=_=(y>>>7^y>>>18^y>>>3^y<<25^y<<14)+(v>>>17^v>>>19^v>>>10^v<<15^v<<13)+g+n|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2821834349|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;y=_=(b>>>7^b>>>18^b>>>3^b<<25^b<<14)+(m>>>17^m>>>19^m>>>10^m<<15^m<<13)+y+c|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2952996808|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;b=_=(w>>>7^w>>>18^w>>>3^w<<25^w<<14)+(g>>>17^g>>>19^g>>>10^g<<15^g<<13)+b+h|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3210313671|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;w=_=(E>>>7^E>>>18^E>>>3^E<<25^E<<14)+(y>>>17^y>>>19^y>>>10^y<<15^y<<13)+w+p|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3336571891|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;E=_=(S>>>7^S>>>18^S>>>3^S<<25^S<<14)+(b>>>17^b>>>19^b>>>10^b<<15^b<<13)+E+d|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3584528711|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;S=_=(x>>>7^x>>>18^x>>>3^x<<25^x<<14)+(w>>>17^w>>>19^w>>>10^w<<15^w<<13)+S+v|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+113926993|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;x=_=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(E>>>17^E>>>19^E>>>10^E<<15^E<<13)+x+m|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+338241895|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;e=_=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(S>>>17^S>>>19^S>>>10^S<<15^S<<13)+e+g|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+666307205|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;t=_=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(x>>>17^x>>>19^x>>>10^x<<15^x<<13)+t+y|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+773529912|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;n=_=(c>>>7^c>>>18^c>>>3^c<<25^c<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+n+b|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1294757372|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;c=_=(h>>>7^h>>>18^h>>>3^h<<25^h<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+c+w|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1396182291|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;h=_=(p>>>7^p>>>18^p>>>3^p<<25^p<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+h+E|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1695183700|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;p=_=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+p+S|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1986661051|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;d=_=(v>>>7^v>>>18^v>>>3^v<<25^v<<14)+(h>>>17^h>>>19^h>>>10^h<<15^h<<13)+d+x|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2177026350|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;v=_=(m>>>7^m>>>18^m>>>3^m<<25^m<<14)+(p>>>17^p>>>19^p>>>10^p<<15^p<<13)+v+e|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2456956037|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;m=_=(g>>>7^g>>>18^g>>>3^g<<25^g<<14)+(d>>>17^d>>>19^d>>>10^d<<15^d<<13)+m+t|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2730485921|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;g=_=(y>>>7^y>>>18^y>>>3^y<<25^y<<14)+(v>>>17^v>>>19^v>>>10^v<<15^v<<13)+g+n|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2820302411|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;y=_=(b>>>7^b>>>18^b>>>3^b<<25^b<<14)+(m>>>17^m>>>19^m>>>10^m<<15^m<<13)+y+c|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3259730800|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;b=_=(w>>>7^w>>>18^w>>>3^w<<25^w<<14)+(g>>>17^g>>>19^g>>>10^g<<15^g<<13)+b+h|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3345764771|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;w=_=(E>>>7^E>>>18^E>>>3^E<<25^E<<14)+(y>>>17^y>>>19^y>>>10^y<<15^y<<13)+w+p|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3516065817|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;E=_=(S>>>7^S>>>18^S>>>3^S<<25^S<<14)+(b>>>17^b>>>19^b>>>10^b<<15^b<<13)+E+d|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3600352804|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;S=_=(x>>>7^x>>>18^x>>>3^x<<25^x<<14)+(w>>>17^w>>>19^w>>>10^w<<15^w<<13)+S+v|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+4094571909|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;x=_=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(E>>>17^E>>>19^E>>>10^E<<15^E<<13)+x+m|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+275423344|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;e=_=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(S>>>17^S>>>19^S>>>10^S<<15^S<<13)+e+g|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+430227734|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;t=_=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(x>>>17^x>>>19^x>>>10^x<<15^x<<13)+t+y|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+506948616|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;n=_=(c>>>7^c>>>18^c>>>3^c<<25^c<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+n+b|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+659060556|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;c=_=(h>>>7^h>>>18^h>>>3^h<<25^h<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+c+w|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+883997877|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;h=_=(p>>>7^p>>>18^p>>>3^p<<25^p<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+h+E|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+958139571|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;p=_=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+p+S|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1322822218|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;d=_=(v>>>7^v>>>18^v>>>3^v<<25^v<<14)+(h>>>17^h>>>19^h>>>10^h<<15^h<<13)+d+x|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1537002063|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;v=_=(m>>>7^m>>>18^m>>>3^m<<25^m<<14)+(p>>>17^p>>>19^p>>>10^p<<15^p<<13)+v+e|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1747873779|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;m=_=(g>>>7^g>>>18^g>>>3^g<<25^g<<14)+(d>>>17^d>>>19^d>>>10^d<<15^d<<13)+m+t|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1955562222|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;g=_=(y>>>7^y>>>18^y>>>3^y<<25^y<<14)+(v>>>17^v>>>19^v>>>10^v<<15^v<<13)+g+n|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2024104815|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;y=_=(b>>>7^b>>>18^b>>>3^b<<25^b<<14)+(m>>>17^m>>>19^m>>>10^m<<15^m<<13)+y+c|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2227730452|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;b=_=(w>>>7^w>>>18^w>>>3^w<<25^w<<14)+(g>>>17^g>>>19^g>>>10^g<<15^g<<13)+b+h|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2361852424|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;w=_=(E>>>7^E>>>18^E>>>3^E<<25^E<<14)+(y>>>17^y>>>19^y>>>10^y<<15^y<<13)+w+p|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2428436474|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;E=_=(S>>>7^S>>>18^S>>>3^S<<25^S<<14)+(b>>>17^b>>>19^b>>>10^b<<15^b<<13)+E+d|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2756734187|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;S=_=(x>>>7^x>>>18^x>>>3^x<<25^x<<14)+(w>>>17^w>>>19^w>>>10^w<<15^w<<13)+S+v|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3204031479|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;x=_=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(E>>>17^E>>>19^E>>>10^E<<15^E<<13)+x+m|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3329325298|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;r=r+T|0;i=i+N|0;s=s+C|0;o=o+k|0;u=u+L|0;a=a+A|0;f=f+O|0;l=l+M|0}function O(e){e=e|0;A(L[e|0]<<24|L[e|1]<<16|L[e|2]<<8|L[e|3],L[e|4]<<24|L[e|5]<<16|L[e|6]<<8|L[e|7],L[e|8]<<24|L[e|9]<<16|L[e|10]<<8|L[e|11],L[e|12]<<24|L[e|13]<<16|L[e|14]<<8|L[e|15],L[e|16]<<24|L[e|17]<<16|L[e|18]<<8|L[e|19],L[e|20]<<24|L[e|21]<<16|L[e|22]<<8|L[e|23],L[e|24]<<24|L[e|25]<<16|L[e|26]<<8|L[e|27],L[e|28]<<24|L[e|29]<<16|L[e|30]<<8|L[e|31],L[e|32]<<24|L[e|33]<<16|L[e|34]<<8|L[e|35],L[e|36]<<24|L[e|37]<<16|L[e|38]<<8|L[e|39],L[e|40]<<24|L[e|41]<<16|L[e|42]<<8|L[e|43],L[e|44]<<24|L[e|45]<<16|L[e|46]<<8|L[e|47],L[e|48]<<24|L[e|49]<<16|L[e|50]<<8|L[e|51],L[e|52]<<24|L[e|53]<<16|L[e|54]<<8|L[e|55],L[e|56]<<24|L[e|57]<<16|L[e|58]<<8|L[e|59],L[e|60]<<24|L[e|61]<<16|L[e|62]<<8|L[e|63])}function M(e){e=e|0;L[e|0]=r>>>24;L[e|1]=r>>>16&255;L[e|2]=r>>>8&255;L[e|3]=r&255;L[e|4]=i>>>24;L[e|5]=i>>>16&255;L[e|6]=i>>>8&255;L[e|7]=i&255;L[e|8]=s>>>24;L[e|9]=s>>>16&255;L[e|10]=s>>>8&255;L[e|11]=s&255;L[e|12]=o>>>24;L[e|13]=o>>>16&255;L[e|14]=o>>>8&255;L[e|15]=o&255;L[e|16]=u>>>24;L[e|17]=u>>>16&255;L[e|18]=u>>>8&255;L[e|19]=u&255;L[e|20]=a>>>24;L[e|21]=a>>>16&255;L[e|22]=a>>>8&255;L[e|23]=a&255;L[e|24]=f>>>24;L[e|25]=f>>>16&255;L[e|26]=f>>>8&255;L[e|27]=f&255;L[e|28]=l>>>24;L[e|29]=l>>>16&255;L[e|30]=l>>>8&255;L[e|31]=l&255}function _(){r=1779033703;i=3144134277;s=1013904242;o=2773480762;u=1359893119;a=2600822924;f=528734635;l=1541459225;c=0}function D(e,t,n,h,p,d,v,m,g){e=e|0;t=t|0;n=n|0;h=h|0;p=p|0;d=d|0;v=v|0;m=m|0;g=g|0;r=e;i=t;s=n;o=h;u=p;a=d;f=v;l=m;c=g}function P(e,t){e=e|0;t=t|0;var n=0;if(e&63)return-1;while((t|0)>=64){O(e);e=e+64|0;t=t-64|0;n=n+64|0}c=c+n|0;return n|0}function H(e,t,n){e=e|0;t=t|0;n=n|0;var r=0,i=0;if(e&63)return-1;if(~n)if(n&31)return-1;if((t|0)>=64){r=P(e,t)|0;if((r|0)==-1)return-1;e=e+r|0;t=t-r|0}r=r+t|0;c=c+t|0;L[e|t]=128;if((t|0)>=56){for(i=t+1|0;(i|0)<64;i=i+1|0)L[e|i]=0;O(e);t=0;L[e|0]=0}for(i=t+1|0;(i|0)<59;i=i+1|0)L[e|i]=0;L[e|59]=c>>>29;L[e|60]=c>>>21&255;L[e|61]=c>>>13&255;L[e|62]=c>>>5&255;L[e|63]=c<<3&255;O(e);if(~n)M(n);return r|0}function B(){r=h;i=p;s=d;o=v;u=m;a=g;f=y;l=b;c=64}function j(){r=w;i=E;s=S;o=x;u=T;a=N;f=C;l=k;c=64}function F(e,t,n,L,O,M,D,P,H,B,j,F,I,q,R,U){e=e|0;t=t|0;n=n|0;L=L|0;O=O|0;M=M|0;D=D|0;P=P|0;H=H|0;B=B|0;j=j|0;F=F|0;I=I|0;q=q|0;R=R|0;U=U|0;_();A(e^1549556828,t^1549556828,n^1549556828,L^1549556828,O^1549556828,M^1549556828,D^1549556828,P^1549556828,H^1549556828,B^1549556828,j^1549556828,F^1549556828,I^1549556828,q^1549556828,R^1549556828,U^1549556828);w=r;E=i;S=s;x=o;T=u;N=a;C=f;k=l;_();A(e^909522486,t^909522486,n^909522486,L^909522486,O^909522486,M^909522486,D^909522486,P^909522486,H^909522486,B^909522486,j^909522486,F^909522486,I^909522486,q^909522486,R^909522486,U^909522486);h=r;p=i;d=s;v=o;m=u;g=a;y=f;b=l;c=64}function I(e,t,n){e=e|0;t=t|0;n=n|0;var c=0,h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0;if(e&63)return-1;if(~n)if(n&31)return-1;b=H(e,t,-1)|0;c=r,h=i,p=s,d=o,v=u,m=a,g=f,y=l;j();A(c,h,p,d,v,m,g,y,2147483648,0,0,0,0,0,0,768);if(~n)M(n);return b|0}function q(e,t,n,c,h){e=e|0;t=t|0;n=n|0;c=c|0;h=h|0;var p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0,O=0;if(e&63)return-1;if(~h)if(h&31)return-1;L[e+t|0]=n>>>24;L[e+t+1|0]=n>>>16&255;L[e+t+2|0]=n>>>8&255;L[e+t+3|0]=n&255;I(e,t+4|0,-1)|0;p=E=r,d=S=i,v=x=s,m=T=o,g=N=u,y=C=a,b=k=f,w=O=l;c=c-1|0;while((c|0)>0){B();A(E,S,x,T,N,C,k,O,2147483648,0,0,0,0,0,0,768);E=r,S=i,x=s,T=o,N=u,C=a,k=f,O=l;j();A(E,S,x,T,N,C,k,O,2147483648,0,0,0,0,0,0,768);E=r,S=i,x=s,T=o,N=u,C=a,k=f,O=l;p=p^r;d=d^i;v=v^s;m=m^o;g=g^u;y=y^a;b=b^f;w=w^l;c=c-1|0}r=p;i=d;s=v;o=m;u=g;a=y;f=b;l=w;if(~h)M(h);return 0}return{reset:_,init:D,process:P,finish:H,hmac_reset:B,hmac_init:F,hmac_finish:I,pbkdf2_generate_block:q}'))( stdlib, foreign, buffer );
}
