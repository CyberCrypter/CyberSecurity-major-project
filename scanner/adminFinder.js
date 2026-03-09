const axios = require("axios");

const paths = [
"/admin",
"/admin/login",
"/dashboard",
"/wp-admin",
"/phpmyadmin"
]

async function findAdmin(url){

    let found = [];

    for(let path of paths){

        try{

            let res = await axios.get(url + path);

            if(res.status === 200)
            found.push(url + path);

        }catch(err){}

    }

    return found;

}

module.exports = findAdmin;