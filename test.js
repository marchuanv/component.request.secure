const requestSecure = require("./component.request.secure.js");
(async()=>{

    await requestSecure.send({
        host: "localhost", 
        port: 5000, 
        path: "/test", 
        method:"POST", 
        username: "admin1", 
        passphrase: "secure1",
        fromhost: "localhost",
        fromport: 6000,
        data: "Hello World From Client" 
    });

})().catch((err)=>{
    console.log(err);
});
