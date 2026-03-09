const axios = require("axios");
const cheerio = require("cheerio");

async function crawl(url){

const visited = new Set();
const pages = [];

try{

const res = await axios.get(url);

const $ = cheerio.load(res.data);

$("a").each((i,link)=>{

let href = $(link).attr("href");

if(href && href.startsWith("/")){
pages.push(url + href);
}

});

return pages;

}catch(err){

return [];

}

}

module.exports = crawl;