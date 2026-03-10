const axios = require("axios");

const passwords = [
"admin",
"password",
"123456",
"admin123",
"test123"
];

async function bruteForceLogin(url){

for(let pass of passwords){

try{

let res = await axios.post(url,{
username:"admin",
password:pass
});

if(res.data.includes("dashboard") || res.status === 200){
return "Weak password found: " + pass;
}

}catch(err){}

}

return "No weak password detected";

}

module.exports = bruteForceLogin;