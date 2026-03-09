const axios = require("axios");

const directories = [
"/admin",
"/backup",
"/uploads",
"/.git",
"/config",
"/dashboard"
];

async function scanDirectories(url){

let found = [];

for(let dir of directories){

try{

let res = await axios.get(url + dir);

if(res.status === 200){
found.push(url + dir);
}

}catch(err){}

}

return found;

}

module.exports = scanDirectories;