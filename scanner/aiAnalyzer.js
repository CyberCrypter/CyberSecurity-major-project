function analyze(results){

let report = [];

if(results.headers?.vulnerabilities?.length > 0){
report.push("Website missing important security headers.");
}

if(results.directories?.length > 0){
report.push("Sensitive directories exposed.");
}

if(results.openPorts?.includes(22)){
report.push("SSH port open - potential brute force risk.");
}

if(results.parameters?.length > 3){
report.push("Multiple parameters detected - possible injection points.");
}

return report;

}

module.exports = analyze;