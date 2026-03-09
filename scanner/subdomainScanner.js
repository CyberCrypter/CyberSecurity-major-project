const axios = require("axios");

const subdomains = [
"api",
"dev",
"test",
"admin",
"mail",
"staging"
];

async function scanSubdomains(domain){

let found = [];

for(let sub of subdomains){

let url = "https://" + sub + "." + domain;

try{

let res = await axios.get(url);

if(res.status < 400){
found.push(url);
}

}catch(err){}

}

return found;

}

module.exports = scanSubdomains;