const axios = require("axios");

async function scanSQL(url){

const payload = "' OR 1=1--";

try{

let res = await axios.get(url + "?id=" + payload);

if(res.data.includes("sql") || res.data.includes("database")){
return "Possible SQL Injection";
}

return "No SQL Injection detected";

}catch(err){

return "Error scanning";

}

}

module.exports = scanSQL;