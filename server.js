const express = require("express");
const crawl = require("./scanner/crawler");
const scanHeaders = require("./scanner/headerScanner");
const findAdmin = require("./scanner/adminFinder");
const scanXSS = require("./scanner/xssScanner");
const scanDirectories = require("./scanner/directoryScanner");
const scanSQL = require("./scanner/sqlScanner");
const scanSubdomains = require("./scanner/subdomainScanner");



const app = express();
app.use(express.json());
app.use(express.static("public"));

app.post("/scan", async (req,res)=>{

    const url = req.body.url;
    const headers = await scanHeaders(url);
    const admin = await findAdmin(url);
    const xss = await scanXSS(url);
    const directories = await scanDirectories(url);
    const sql = await scanSQL(url);

    const domain = url.replace("https://","").replace("http://","");
    const subdomains = await scanSubdomains(domain);

    const pages = await crawl(url);


    res.json({
    headers,
    adminPanels:admin,
    directories,
    sql,
    xss,
    subdomains,
    pages
    });

})

app.listen(3000,()=>{
    console.log("Scanner running on port 3000");
})