const axios = require("axios");

async function findSecrets(jsURL){

let secrets = [];

try{

let res = await axios.get(jsURL, {
timeout: 8000,
validateStatus: () => true,
});

if (res.status >= 400) {
return secrets;
}

let content = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

const patterns = [
/AIza[0-9A-Za-z-_]{35}/g,
/sk_live_[0-9a-zA-Z]{24}/g,
/AKIA[0-9A-Z]{16}/g
];

for(let pattern of patterns){

let matches = content.match(pattern);

if(matches){
secrets.push(...matches);
}

}

}catch(err){}

return secrets;

}

module.exports = findSecrets;