const axios = require("axios");

async function detectTech(url){

let tech = [];

try{

const res = await axios.get(url, {
timeout: 8000,
validateStatus: () => true,
});

if (res.status >= 400) {
return tech;
}

const headers = res.headers;
const html = typeof res.data === "string" ? res.data.toLowerCase() : JSON.stringify(res.data).toLowerCase();

if(headers["x-powered-by"])
tech.push(headers["x-powered-by"]);

if(html.includes("wp-content"))
tech.push("WordPress");

if(html.includes("react"))
tech.push("React");

if(html.includes("angular"))
tech.push("Angular");

}catch(err){}

return tech;

}

module.exports = detectTech;