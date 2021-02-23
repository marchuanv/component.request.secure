const utils = require("utils");
const requestDeferred = require("component.request.deferred");
const logging = require("logging");
logging.config.add("Sending Secure Request");

const userSessions = [];
module.exports = { 
    send: async ({ host, port, path, method, username, passphrase, data, fromhost, fromport }) => {
        const requestUrl = `${host}:${port}${path}`;
        let session = userSessions.find(s => s.username === username);
        if (!session) {
            if (!username || !passphrase){
                const message = `username and passphrase was not provided for ${requestUrl}`;
                logging.write("Sending Secure Request",message);
                throw new Error(message);
            }
            const { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase(passphrase);
            const { publicKey, privateKey } = utils.generatePublicPrivateKeys(hashedPassphrase);
            const encryptionKey = {
                local: utils.stringToBase64(publicKey),
                remote: null
            };
            session = { Id: null, username, hashedPassphrase, hashedPassphraseSalt, encryptionKey, publicKey, privateKey, fromhost, fromport, token: null };
            userSessions.push(session);
        }
        if (!session.token){
            const results = await requestDeferred.send({  host, port, path, method, headers: {
                "Content-Type":"text/plain",
                encryptionkey: session.encryptionKey.local,
                fromhost,
                fromport,
                username,
                passphrase
            }, data: "" });
            if (results.statusCode !== 200){
                const message = `failed to get a session from ${host}:${port}`;
                logging.write("Sending Secure Request",message);
                throw new Error(message);
            }
            session.Id = results.headers.sessionid;
            session.encryptionKey.remote = utils.base64ToString(results.headers.encryptionkey);
            session.token = results.headers.token;
            return await module.exports.send({ host, port, path, method, username, passphrase, data, fromhost, fromport });
        }
        data = utils.encryptToBase64Str(data, session.encryptionKey.remote);
        const results = await requestDeferred.send({  host, port, path, method, headers: {
            "Content-Type":"text/plain",
            encryptionkey: session.encryptionKey.local,
            sessionid: session.Id,
            token: session.token
        }, data });
        if (results.statusCode === 200){
            results.data = utils.decryptFromBase64Str(results.data,session.privateKey);
        }
        return results;
    }
};