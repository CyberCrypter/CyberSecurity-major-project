const axios = require("axios");

async function scanXSS(url){

const payload = "<script>alert(1)</script>";

try{

let res = await axios.get(url + "?q=" + payload);

if(res.data.includes(payload))
return "Possible XSS";

else
return "No XSS detected";

}catch(err){

return "Error scanning";

}

}

module.exports = scanXSS;