const jwt = require("jsonwebtoken");

function scanJWT(token){

try{

const decoded = jwt.decode(token,{complete:true});

if(decoded.header.alg === "none"){
return "JWT vulnerable: alg none";
}

return "JWT algorithm: " + decoded.header.alg;

}catch(err){

return "Invalid JWT";

}

}

module.exports = scanJWT;