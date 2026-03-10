const axios = require("axios");
const cheerio = require("cheerio");

async function findJSEndpoints(url){

let endpoints = [];

try{

const res = await axios.get(url, {
timeout: 8000,
validateStatus: () => true,
});

if (res.status >= 400 || typeof res.data !== "string") {
return endpoints;
}
const $ = cheerio.load(res.data);

let scripts = [];

$("script").each((i,el)=>{
let src = $(el).attr("src");
if(src) scripts.push(src);
});

for(let script of scripts){

let jsURL;

try {
jsURL = new URL(script, url).toString();
} catch {
continue;
}

try{

let js = await axios.get(jsURL, {
timeout: 8000,
validateStatus: () => true,
});

if (js.status >= 400) {
continue;
}

const jsBody = typeof js.data === "string" ? js.data : JSON.stringify(js.data);
let matches = jsBody.match(/\/api\/[a-zA-Z0-9\/_-]*/g);

if(matches){
endpoints.push(...matches);
}

}catch(err){}

}

}catch(err){}

return [...new Set(endpoints)];

}

module.exports = findJSEndpoints;