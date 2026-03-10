const net = require("net");

const ports = [21,22,25,53,80,110,143,443,3306,8080];

async function scanPorts(host){

let openPorts = [];

for(let port of ports){

await new Promise((resolve)=>{

const socket = new net.Socket();

socket.setTimeout(1000);

socket.connect(port,host,()=>{
openPorts.push(port);
socket.destroy();
resolve();
});

socket.on("error",()=>{
resolve();
});

socket.on("timeout",()=>{
socket.destroy();
resolve();
});

});

}

return openPorts;

}

module.exports = scanPorts;