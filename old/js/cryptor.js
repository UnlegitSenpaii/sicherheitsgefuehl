/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                            To-Do
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    - feature chasing < stability

    (bugs)
    - sending message on enter doesn't work sometimes?
    - "channel info" button is not very good
    - ui ui ui

    (implementation queue)
    - !IMPORTANT! improve loading times by loading messages one by one
        -> would make channel switching infinitely faster
        -> no need to refresh entire page to check for messages
        -> cache
    - Right Click Message Menu
        -> React to messages
        -> Reply to messages
        -> Copy message / content?
    - remove inline js & forbid inline js using csp
    - sandbox domain / sandbox iframe
    - Remove from content upload queue > remove images from queue
    - Focus on image content
    - Message formatting (code, bold, italic, ...)
    - Steam & Reddit embedding
    - Edit Channels ?? (pictures?)
    - Switch over to events
    - start switching over to classes?
    - replace "embedding blocked" with something else, maybe just change color of message or something
    - custom channel picture
    - avatar support
    - user-friendliness (user does not have to "focus" to understand something)
    - desktop notification on new message (? -> new message event we get from the server)
    - message banner for new message
    - method of censoring/spoiler warning content with either blur or black overlay
    - dynamic website title
    - make logs more appealing to the user (example: "msg too long!" in top right? )
    - drag and drop images?
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for
    - self-destructing messages
    - different encryption strengths using dropdown
        - (failed to decrypt, this message was sent with different encryption settings (change to high/low - only this message))


    (still thinking about it)
    - support for different file types or file hosters
    - support for automation
    - make the send message button a checkbox in settings (disable by default on PCs and enable on Mobile)
    - changelog
    - advertise somewhere?
    - "custom encryption functions" - user can code / use their own implementation of message encryption (technically already possible)

 */

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                            Globals
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
let encryptionStuff = {};
let channelStuff = {};
let embeddingStuff = {};
let currentAttachments = {};
let fetchingMessages = false;
const logging = new logging_engine()

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                     Encoders and Sanitizers
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

function encodeMe(val) {
    let enc = new TextEncoder();
    return enc.encode(val);
}

function StringToCipher(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function CipherToString(buf) {
    //fix for https://stackoverflow.com/a/24595052
    return new Uint8Array(buf).reduce((data, byte) => data + String.fromCharCode(byte), '');
    //return String.fromCharCode.apply(null, new Uint8Array(buf));
}

//converts stuff like <script> to &#60;script&#62;
function sanitize(str) {
    return String(str).replace(/[^\w. ]/gi, function (c) {
        return '&#' + c.charCodeAt(0) + (isNaN(c.charCodeAt(1)) ? "" : c.charCodeAt(1)) + ';';
    });
}

function CheckText() {
    let inputelement = document.getElementById("chatmessage");
    const userInput = inputelement.value;
    if (userInput > 2000) inputelement.value = userInput.slice(0, 2000);

    const actualInput = userInput.replaceAll(new RegExp('\r?\n', 'g'), "");

    //theoretical limit is 2147483647, so this size is appropriate I think? - lol it crashes after like 10mio chars
    //! now used for image overhead !

    document.getElementById("chatmessage-comment").innerText = (actualInput.length > 0) ? actualInput.length + " / 2000" : "";
}

function CheckForAlerts() {
    const controller = new AbortController();
    let close = document.getElementsByClassName("warning-closebutton");

    for (let i = 0; i < close.length; i++) {
        const item = close[i];
        item.addEventListener("click", closeAlert, {signal: controller.signal});

        function closeAlert() {
            let div = item.parentElement;
            div.style.opacity = "0";
            setTimeout(function () {
                div.style.display = "none"
                controller.abort();
            }, 600)
        }
    }
}

function handleUserName() {
    let username = document.getElementById("chat-username");
    if (username.value.length > 25) username.value.slice(0, 25);

    let finalUsername = username.value;
    if (username.value.length <= 0) finalUsername = "Anonymous";

    localStorage.setItem("chat-username", finalUsername);
}

//converts my scuffed sql server time to eu time
function convertUTCDateToLocalDate(date) {
    let newDate = new Date(date.getTime() + date.getTimezoneOffset() * 60 * 1000); //on whatever fucking timezone my fucking sql server is set

    const offset = date.getTimezoneOffset() / 60;
    const hours = date.getHours();

    newDate.setHours(hours + 2 - offset);// don't ask please
    return newDate;
}

function GetYoutubeVideoID(url) {
    const regExp = /^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|&v=)([^#&?]*).*/;
    const match = url.match(regExp);
    return (match && match[2].length === 11) ? match[2] : null;
}

//RETURNS NOT SANITIZED STRING!
async function GetChannelNameFromToken(token) {
    const channelAddress = await GetChatRoomAddressFromKey(token);
    let currentChannel = channelStuff[channelAddress];
    return LZString.decompressFromEncodedURIComponent(currentChannel['alias']);
}

async function postData(url = '', data = '') {
    const response = await fetch(url, {
        method: 'POST', mode: 'cors', // no-cors, *cors, same-origin
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }, redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        body: data // body data type must match "Content-Type" header
    });

    if (response.status !== 200) {//enter user in infinite loading time
        return [false, response.status];
    }

    return [true, response];
}

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          Key Generation
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

//wait for https://csrc.nist.gov/projects/post-quantum-cryptography to conclude
//Lets hope kyber goes through, looks pretty cool

function getKeyMaterial(blankoKey) {
    return window.crypto.subtle.importKey("raw", encodeMe(blankoKey), {name: "PBKDF2"}, false, ["deriveBits", "deriveKey"]);
}

function getKey(keyMaterial, salt) {
    return window.crypto.subtle.deriveKey({
        "name": "PBKDF2", "salt": salt, "iterations": 5125120, "hash": "SHA-512"
    }, keyMaterial, {"name": "AES-GCM", "length": 256}, true, ["encrypt", "decrypt"]);
}


/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        Hashing Functions
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

functions used below are found in sha3.js
 - sha3_512
 - keccak256

*/
async function GetSHA512(message) {
    return sha3_512(message);
}

async function GetSHA224(message) {
    return sha3_224(message);
}

async function GetChatRoomAddress() {
    const key = encryptionStuff["key"];
    return shake256(btoa(await GetSHA512(btoa(key))), 512);
}

async function GetChatRoomAddressFromKey(key) {
    return shake256(btoa(await GetSHA512(btoa(key))), 512);
}

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          Crypt Functions
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

async function encrypt(text, cryptData) {
    const salt = encodeMe(cryptData["salt"]);
    const iv = encodeMe(cryptData["iv"]);
    const userKey = cryptData["key"];
    const bonkers = await getKeyMaterial(userKey);

    let key = await getKey(bonkers, salt);
    let encoded = encodeMe(text);
    const ciphertext = await window.crypto.subtle.encrypt({
        name: "AES-GCM", iv: iv
    }, key, encoded);

    return btoa(CipherToString(ciphertext));
}

async function decrypt(text, cryptData) {
    const salt = encodeMe(cryptData["salt"]);
    const iv = encodeMe(cryptData["iv"]);
    const userKey = cryptData["key"];
    const bonkers = await getKeyMaterial(userKey);

    let key = await getKey(bonkers, salt);
    let ciphertext = StringToCipher(atob(text));

    try {
        let decrypted = await window.crypto.subtle.decrypt({
            name: "AES-GCM", iv: iv
        }, key, ciphertext);

        let dec = new TextDecoder();
        return dec.decode(decrypted);
    } catch (e) {
        await PostMessageToUser("* error decrypting *");
        logging.Log("There was an error decrypting a message!", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        return false;
    }
}


/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          Logging
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

function ClearLogs() {
    const logs = document.getElementById('crypt-logs');

    if (!logs)//missing, page loading or something
        return;

    logs.innerHTML = "";
}

async function PostMessageToUser(message) {
    const logs = document.getElementById('crypt-logs');

    if (!logs)//missing, page loading or something
        return;

    logs.innerHTML += "<div class=\"input-group\"> <div class=\"form-control settings_log\"><span>" + sanitize(message) + "</span></div></div>";
    console.log(message);
}

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                       Chat Embedding Stuff
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

async function SaveEmbeddingData() {
    const cryptKey = sessionStorage.getItem("roomKey");
    const stuff = await GetEncryptionKey(cryptKey);
    const stringyData = JSON.stringify(embeddingStuff);
    const encryptedData = await encrypt(stringyData, stuff)
    const embeddingData = LZString.compress(encryptedData);
    localStorage.setItem("savedEmbeddingData", embeddingData);
}

async function AddToWhitelist() {
    const htmlElement = document.getElementById("add_to_whitelist");

    if (!htmlElement) return;

    const whitelistedURL = htmlElement.value;

    embeddingStuff[(await GetSHA224(whitelistedURL)).toString()] = (whitelistedURL);


    await SaveEmbeddingData();
    ReloadEmbeddingWhitelist();
    htmlElement.value = "";
}

function GetWhitelistHTML(key, hash) {
    return "<div class=\"input-group\"><span class=\"form-control settings_note_in_text\">" + key + "</span><div class=\"input-group-prepend\"><span class=\"input-group-text settings_note_in_button\" onclick='DeleteFromEmbeddingData(\"" + hash + "\")'><i class=\"fas fa-trash\"></i></span></div></div>";
}

function ReloadEmbeddingWhitelist() {
    const embeddingWhitelist = document.getElementById("embedding-whitelist");

    embeddingWhitelist.innerHTML = "";
    // unescape(encodeURIComponent( )); apparently this is wanted somewhere
    Object.keys(embeddingStuff).forEach(key => {
        embeddingWhitelist.innerHTML += GetWhitelistHTML(sanitize(embeddingStuff[key]), encodeURI(key));
    })
}

async function DeleteFromEmbeddingData(embedding) {
    if (!embeddingStuff.hasOwnProperty(embedding.toString())) return;
    logging.Log("deleted " + embeddingStuff[embedding.toString()] + " from embed data.", LOG_TYPE_MSG["message"].LEVEL_NOTIFICATION);
    delete embeddingStuff[embedding.toString()];
    await SaveEmbeddingData();
    ReloadEmbeddingWhitelist();
}

async function LoadDefaultEmbeddingData() {
    const defaultValues = ["https://i.imgur.com/", "https://cdn.discordapp.com/attachments/", "https://youtu.be/", "https://www.youtube.com/"];
    for (const val of defaultValues) {
        embeddingStuff[(await GetSHA224(val)).toString()] = val;
    }
}

async function FetchEmbeddedData() {
    const cryptKey = sessionStorage.getItem("roomKey");
    const embeddingData = localStorage.getItem("savedEmbeddingData");

    if (!cryptKey) return false;

    if (!embeddingData) {
        await LoadDefaultEmbeddingData();
        ReloadEmbeddingWhitelist();
        return true;
    }

    const stuff = await GetEncryptionKey(cryptKey);
    const ciphertext = LZString.decompress(embeddingData);
    const decryptedData = await decrypt(ciphertext, stuff);

    if (!decryptedData || decryptedData === "false") return false;

    embeddingStuff = JSON.parse(decryptedData);
    ReloadEmbeddingWhitelist();
    return true;
}

function GetErrorPage(errorcode) {
    switch (errorcode) {
        case 401:
            return "<div class=\"content\">  Authentication failed. Please try logging in again. &nbsp; <a onclick=\"location.reload()\" target=\"_blank\" style='color:mediumpurple'>  <i class=\"fa fa-rotate-right\" aria-hidden=\"true\"> </i> </a></div>";
        default:
            return "<div class=\"content\">  Server refused to work on your request. &nbsp; <a onclick=\"location.reload()\" target=\"_blank\" style='color:mediumpurple'>  <i class=\"fa fa-rotate-right\" aria-hidden=\"true\"> </i> </a> </div>";
    }
}


function getLocationInformation(href) {
    //whatever phpstrom says about this regex is wrong, ignore, or it'll implode
    const match = href.match(/^(?:(https?\:)\/\/)?(([^:\/?#]*)(?:\:([0-9]+))?)([\/]{0,1}[^?#]*)(\?[^#]*|)(#.*|)$/);
    return match && {
        href: href, protocol: match[1], host: match[2], hostname: match[3], port: match[4], pathname: match[5], search: match[6], hash: match[7]
    }
}

async function URLIsInWhitelist(url) {
    let hasValue = false;

    const urlInformation = getLocationInformation(url);

    Object.keys(embeddingStuff).forEach(value => {
        const entry = embeddingStuff[value];
        if (hasValue) return;
        const embedInformation = getLocationInformation(entry);
        hasValue = (urlInformation.host === embedInformation.host);
    });

    return hasValue;
}

function IsImagePath(path) {
    const allowedImageFormats = ['.jpg', '.png', '.gif']
    let retVal = false;
    Object.keys(allowedImageFormats).forEach(key => {
        if (retVal) return;
        const format = allowedImageFormats[key].trim();
        const val = path.substring((path.length - format.length), path.length).toLowerCase().trim();
        if (val === format) retVal = true;
    });
    return retVal;
}

async function formatChatMessage(messageData, timeStamp) {
    try {
        let message = messageData["message"];
        let appendImagesString = "";

        const isInsecure = message.match(/\bhttp?:\/\/\S+/gi);
        const urlMatches = message.match(/\bhttps?:\/\/\S+/gi) || isInsecure;

        //this has so many security vulnerabilities :/
        if (urlMatches) {
            for (let key of urlMatches) {
                //try upgrading to https
                if (isInsecure) {
                    key = (key.replace("http", "https"));
                }

                const urlInformation = getLocationInformation(key);

                const inWhitelist = await URLIsInWhitelist(key);
                if (!inWhitelist) {
                    appendImagesString += "<p style='font-size: 11px; margin-bottom: 1px; font-weight: 700; color: red'>embedding blocked!</p>";
                    continue;
                }

                const urlHost = urlInformation.host.toString();
                const isYouTubeLink = urlHost === "www.youtube.com" || urlHost === "youtube.com" || urlHost === "youtu.be";//(key.includes("youtube.com")) || (key.includes("youtu.be"));
                const isImageLink = IsImagePath(urlInformation.pathname);

                if (isImageLink) {
                    appendImagesString += (isInsecure ? "<p style='font-size: 11px; margin-bottom: 1px; font-weight: 700'>upgraded to https!</p>" : "") + "<img src='" + sanitize(key) + "' alt=''> ";
                    message = message.replace(key, "");
                    //appendImagesString += "<p style='font-size: 11px; margin-bottom: 1px; font-weight: 700; color: #00ff00'>embedded!</p>";
                } else if (isYouTubeLink) {
                    const videoID = GetYoutubeVideoID(key);
                    if (videoID) {
                        const embedURL = 'https://www.youtube.com/embed/' + videoID;
                        appendImagesString += "<iframe allow=\"accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture\" " + "sandbox=\"allow-scripts allow-same-origin\" allowfullscreen frameborder=\"0\"" + "title='YouTube video player' type=\"text/html\" width='640' height='362' src='" + embedURL + "'></iframe>";
                        message = message.replace(key, "");
                        //appendImagesString += "<p style='font-size: 11px; margin-bottom: 1px; font-weight: 700; color: #00ff00'>embedded!</p>";
                    }
                }
            }
        }

        if (messageData["attachments"]) {
            const attachments = JSON.parse(messageData["attachments"]);
            if (attachments) {
                for (const key of Object.keys(attachments)) {
                    let obj = attachments[key];
                    let result = await decrypt(obj, encryptionStuff);

                    if (!result) {
                        appendImagesString += "<p style='font-size: 11px; margin-bottom: 1px; font-weight: 700; color: red'>failed to load image!</p>";
                    } else {
                        appendImagesString += "<img src='" + result + "' alt='failed to load image!'>";
                    }
                }
            }
        }

        const username = messageData["username"];
        const messageSecret = messageData["secret"];
        let sanitizedMessage = "";

        const chatElement = document.createElement('p');
        chatElement.style = "margin: 0"
        chatElement.innerText = message;

        sanitizedMessage += chatElement.outerHTML;

        return "<div class=\"d-flex justify-content-start mb-4\">" + "<div class=\"msg_cotainer\"><span class=\"msg_username\">" + sanitize(username) + " <span class=\"msg_time\" onclick='PostMessageToUser(\"user id: " + messageSecret + "\")'>" + timeStamp + " UID: " + sanitize(messageSecret.slice(0, 16)) + "</span></span>" + (sanitizedMessage) + "" + appendImagesString + "</div></div>";
    } catch (e) {
        logging.Log("failed to format message, check console for more information", LOG_TYPE_MSG["message"].LEVEL_WARNING);
        console.log(e);
        return "<div class=\"d-flex justify-content-start mb-4\">" + "<div class=\"msg_cotainer\"><span class=\"msg_username\"> unknown <span class=\"msg_time\" onclick='PostMessageToUser(\"user id: error message\")'>" + timeStamp + " UID: none</span></span> failed to format message :( </div></div>";
    }
}

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                            File Engine
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

//I don't think that's how you use classes
class file_engine {
    constructor() {
        this.HTMLElementID = "chatfile";
        //emptiness
    }

    get EventHandler() {
        //very hackyy
        const attachment = document.getElementById("chatmessage_attachments");
        if (attachment) {
            attachment.addEventListener("click", () => {
                if (!htmlElement) return;

                const event = new MouseEvent('click', {
                    view: window
                });
                htmlElement.dispatchEvent(event);
            });
        }

        let htmlElement = document.getElementById(this.HTMLElementID);
        if (htmlElement) {
            htmlElement.addEventListener("change", async ({item}) => {
                await this.NewEventHandler();
            });
        }
    }

    async finishUpImage(img) {
        if (!img || img === "") return;
        let result = "";

        try {
            let encVal = await encrypt(img, encryptionStuff);
            currentAttachments[await GetSHA224(img)] = encVal;

            result = await decrypt(encVal, encryptionStuff);
        } catch (err) {
            logging.Log("error occurred while processing image: " + err, LOG_TYPE_MSG["message"].LEVEL_ERROR);
        }

        const preview = document.getElementById("preview_placeholder");

        const parent = document.createElement('div');
        parent.className = "preview";

        const image = document.createElement('img');
        image.src = result === "false" ? "" : result;
        image.alt = "preview failed.";
        parent.appendChild(image);

        preview.appendChild(parent);
        preview.removeChild(preview.getElementsByClassName("loading")[0]);
    }

    async EncodeImageToBase64(image) {
        //accept only images for now...
        if (!(/\.(jpe?g|png|gif)$/i.test(image.name))) {
            const preview = document.getElementById("preview_placeholder");
            preview.removeChild(preview.getElementsByClassName("loading")[0]);
            return;
        }

        let reader = new FileReader();

        reader.addEventListener("load", async () => {
            // convert image file to base64 string
            await this.finishUpImage(reader.result).catch((err) => {
                console.log(err);
            });
        }, false);
        reader.readAsDataURL(image);
    }

    async NewEventHandler() {
        const items = document.getElementById(this.HTMLElementID).files;
        //do loading screen..
        const preview = document.getElementById("preview_placeholder");
        preview.innerHTML = ""; //kill all children
        Object.keys(currentAttachments).forEach(key => {
            delete currentAttachments[key]
        });

        for (let i = 0; i < items.length; i++) {
            const loadingDiv = document.createElement('div');
            loadingDiv.className = "loading";
            loadingDiv.innerHTML = "<p>loading</p><span></span>";
            preview.appendChild(loadingDiv);

            await this.EncodeImageToBase64(items[i]);
        }
    }
}

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          HTML Functions
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

async function ResetEncryptToken() {
    localStorage.clear();
    sessionStorage.clear();
    encryptionStuff = {};
    channelStuff = {};
    location.reload();
}

async function PostChatMessage() {
    "use strict";
    //very important

    CheckText();
    handleUserName();
    const chatMessageElement = document.getElementById("chatmessage");
    let userInput = chatMessageElement.value;
    let username = localStorage.getItem("chat-username");
    //I know, this can be easily tampered with since I have no way of double-checking this on the server-side :(
    //please dont
    const actualInput = userInput.replaceAll(new RegExp('\r?\n', 'g'), "");
    if (actualInput.length <= 1 || actualInput.length > 2000) {
        logging.Log("message is invalid or too long", LOG_TYPE_MSG["message"].LEVEL_WARNING);
        return;
    }

    //clear last chat-message
    chatMessageElement.value = "";
    const preview = document.getElementById("preview_placeholder");
    preview.innerHTML = ""; //kill all children

    let chatSecretData = document.getElementById("chat-secret").value;

    if (chatSecretData.length <= 0) {
        let array = new Uint8Array(24);
        chatSecretData = window.crypto.getRandomValues(array).toLocaleString();//fuck IE
        document.getElementById("chat-secret").value = chatSecretData;
    }

    const cryptKey = sessionStorage.getItem("roomKey");
    const stuff = await GetEncryptionKey(cryptKey);
    const encryptedData = await encrypt(chatSecretData, stuff)
    const chatSecEncrypted = LZString.compress(encryptedData);

    localStorage.setItem("savedChatSecret", chatSecEncrypted);

    try {
        const messageData = {
            "username": username, "secret": await GetSHA224(chatSecretData), "message": userInput, "attachments": JSON.stringify(currentAttachments)
        }
        const finalMessage = JSON.stringify(messageData);
        let encVal = await encrypt(finalMessage, encryptionStuff);
        const encoded = LZString.compressToEncodedURIComponent(encVal);
        if (encoded.length >= 4300000) {
            throw new Error("message too big!");
        }

        const chatRoomAddress = await GetChatRoomAddress();
        await postData('sicherheitsgefuehl.php', 'send=1&chatroom=' + chatRoomAddress + "&data=" + encoded)
            .then(response => !response[0] ? GetErrorPage(response[1]) : response[1].text())
            .then(async data => {
                if (data !== "completed") {
                    logging.Log("something isn't quite right. please check console for more info", LOG_TYPE_MSG["message"].LEVEL_WARNING);
                    console.log(data);
                }
            }).then(CheckForAlerts);
    } catch (e) {
        console.log(e);
        logging.Log("Error occurred while trying to send message: " + e, LOG_TYPE_MSG["message"].LEVEL_ERROR);
        Object.keys(currentAttachments).forEach(key => {
            delete currentAttachments[key]
        });
    }

    Object.keys(currentAttachments).forEach(key => {
        delete currentAttachments[key]
    });
    CheckText();
}

async function GetEncryptionKey(userin) {
    //check if we have the encryption data stored
    if (!userin) {
        logging.Log("No encryption key..", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        return;
    }
    let temp = {};
    temp["key"] = userin;
    temp["salt"] = await GetSHA512(userin);
    temp["iv"] = await GetSHA512(btoa(userin));

    return temp;
}

async function ReloadChannels(active = "") {
    const channel_ul = document.getElementById("new_channel_token_div");
    if (!channel_ul) return;
    channel_ul.innerHTML = "<ul class='channels'>";//clear das shit
    Object.keys(channelStuff).forEach(key => {
        let currentChannel = channelStuff[key];
        let channelName = sanitize(LZString.decompressFromEncodedURIComponent(currentChannel['alias'])).slice(0, 21);

        if (channelName.length >= 21) channelName += "..";
        //sanitize should be fine, since were encoding it as an uricomponent when saving
        if (active === key) {
            channel_ul.innerHTML += "<li class='active'>" + "<div class=\"d-flex bd-highlight\" onclick=\"JoinChannel('" + sanitize(currentChannel['token']) + "')\">" + "<div class=\"img_cont\">" + "<img alt='green' class=\"rounded-circle channel_img\" src=\"./storage/channel_img.png\">" + "<span class=\"online_icon\"></span>" + "</div>" + "<div class=\"user_info\">" + "<span> " + channelName + " </span>" + "</div>" + "</div>" + "</li>";
        } else {
            channel_ul.innerHTML += "<li>" + "<div class=\"d-flex bd-highlight\" onclick=\"JoinChannel('" + sanitize(currentChannel['token']) + "')\">" + "<div class=\"img_cont\">" + "<img alt='chatroom' class=\"rounded-circle channel_img\" src=\"./storage/channel_img.png\">" + "<span class=\"online_icon\"></span>" + "</div>" + "<div class=\"user_info\">" + "<span> " + channelName + " </span>" + "</div>" + "</div>" + "</li>";
        }
    });
    channel_ul.innerHTML += "</ul>";

    const cryptKey = sessionStorage.getItem("roomKey");
    const stuff = await GetEncryptionKey(cryptKey);
    const stringyData = JSON.stringify(channelStuff);
    const encryptedData = await encrypt(stringyData, stuff)
    const channelData = LZString.compress(encryptedData);

    localStorage.setItem("savedChannelData", channelData);
}

async function DecryptChannels() {
    const cryptKey = sessionStorage.getItem("roomKey");
    const userRoomData = localStorage.getItem("savedChannelData");
    const chatSecretData = localStorage.getItem("savedChatSecret");

    await FetchEmbeddedData();

    if (cryptKey && userRoomData) {
        const stuff = await GetEncryptionKey(cryptKey);
        if (chatSecretData) {
            const secretData = LZString.decompress(chatSecretData);
            const decryptedData = await decrypt(secretData, stuff);
            if (decryptedData && decryptedData !== "false") document.getElementById("chat-secret").value = decryptedData;
        }

        const channelData = LZString.decompress(userRoomData);
        const decryptedData = await decrypt(channelData, stuff);
        if (decryptedData && decryptedData !== "false") {
            channelStuff = JSON.parse(decryptedData);
            return true;
        }
    }
    return false;
}

async function DecryptAccessTokens() {
    const encryptkey = document.getElementById("encryptkey");
    const askForDecrypt = document.getElementById("ask_for_decrypt");
    const newChannelToken = document.getElementById("new_channel_token_div");
    const channelsettings = document.getElementById("channelsettingsgroup");
    if (!encryptkey || !askForDecrypt || !newChannelToken || !channelsettings) return;
    if (encryptkey.value.length === 0) return;

    const backup = askForDecrypt.innerHTML;
    askForDecrypt.innerHTML = "<div class=\"loading\"><p>loading</p><span></span></div>";

    sessionStorage.setItem("roomKey", encryptkey.value);

    const userRoomData = localStorage.getItem("savedChannelData");
    if (userRoomData && !(await DecryptChannels())) {
        logging.Log("Provided decrypt key is incorrect.", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        askForDecrypt.innerHTML = backup;
        return;
    }

    askForDecrypt.hidden = true;
    newChannelToken.hidden = false;
    channelsettings.hidden = false;

    if (!userRoomData) {  //user has yet to join any rooms
        newChannelToken.innerHTML = '<div class="setting_group"><div class="input-group"><span class="form-control settings_title"> such empty.. </span></div>' + '<div class="input-group"><div class="form-control settings_note"><span> You can start by adding a channel! </span></div></div></div>';
        return;
    }

    await ReloadChannels();
}

async function JoinChannel(temp) {
    funnyLoadingScreen();
    encryptionStuff = await GetEncryptionKey(LZString.decompressFromEncodedURIComponent(temp));
    await ReloadChannels(await GetChatRoomAddressFromKey(encryptionStuff['key']));
    await FetchChatMessages("1");
    funnyLoadingScreen(false);//this is getting called in FetchChatMessages too, call this just to be sure
}

async function CopyCurrentToken() {
    await CopyToClipboard(encryptionStuff['key']);
}

async function RemoveCurrentChannel() {
    const currentChannelID = await GetChatRoomAddressFromKey(encryptionStuff['key']);
    if (!channelStuff.hasOwnProperty(currentChannelID.toString())) return;
    delete channelStuff[currentChannelID.toString()];
    await ReloadChannels("");
}

async function JoinNewChannel() {
    const newChannelAlias = document.getElementById("new_channel_alias");
    const newChannelToken = document.getElementById("new_channel_token");
    if (!newChannelToken || !newChannelAlias) return;
    if (newChannelToken.value.length === 0) {
        //make make the channel token random?
        return;
    }

    if (newChannelToken.value.length <= 12) {
        logging.Log("Provided channel key is too short.", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        return;
    }

    let channelAlias = newChannelAlias.value;
    const channelToken = newChannelToken.value;
    const channelId = await GetChatRoomAddressFromKey(channelToken);

    if (channelAlias.length === 0) channelAlias = channelId;

    channelStuff[channelId.toString()] = {
        "token": LZString.compressToEncodedURIComponent(channelToken), "alias": LZString.compressToEncodedURIComponent(channelAlias)
    };

    await ReloadChannels(channelId.toString());
    await JoinChannel(channelStuff[channelId.toString()]['token']);

    newChannelAlias.value = "";
    newChannelToken.value = "";
}

async function SendPostData(url = '', data = '', signal = undefined) {
    const response = await fetch(url, {
        method: 'POST', mode: 'cors', // no-cors, *cors, same-origin
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        signal: signal, credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }, redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        body: data // body data type must match "Content-Type" header
    });

    if (response.status !== 200) {//enter user in infinite loading time
        return [false, response.status];
    }

    return [true, response];
}

async function CopyToClipboard(str) {
    navigator.clipboard.writeText(str).catch(async function (err) {
        logging.Log("Failed to copy to clipboard. Check console for more info.", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        console.error("copy to clipboard failed with: " + err);
    });
}

function funnyLoadingScreen(load = true) {
    let userchat = document.getElementById('user-messages');
    if (!userchat)//missing, page loading or something
        return;

    if (!load) {
        try {
            const items = userchat.getElementsByClassName("skeleton-row");
            for (let i = 0; i < items.length; i++) {
                userchat.removeChild(items[i]);
            }
        } catch {
            //stfu
        }
        return;
    }

    const skelly = ["<span class=\"prod-name skeleton-loader\"></span><span class=\"prod-id skeleton-loader\"></span><br><span class=\"prod-messagecontent skeleton-loader\"></span>", "<span class=\"prod-name skeleton-loader\"></span><span class=\"prod-id skeleton-loader\"></span><br><span class=\"prod-messagecontent-short skeleton-loader\"></span>", "<span class=\"prod-name skeleton-loader\"></span><span class=\"prod-id skeleton-loader\"></span><br><span class=\"prod-img skeleton-loader\"></span>"];

    const loadingDivWrapper = document.createElement('div');
    loadingDivWrapper.className = "skeleton-row";

    for (let i = 0; i < Math.floor(Math.random() * 5 + 1); i++) {
        loadingDivWrapper.innerHTML += skelly[Math.floor(Math.random() * skelly.length)]
    }

    userchat.innerHTML = loadingDivWrapper.outerHTML;
}

async function AppendChatMessage(chatData, appendToChat = false) {
    const userchat = document.getElementById('user-messages');
    const currentChatMessages = document.getElementById('currentChatMessages');
    if (!userchat)//missing, page loading or something
        return;
    if (!chatData) return;
    let result = "<span class=\"prod-name skeleton-loader\"></span><span class=\"prod-id skeleton-loader\"></span><br><span class=\"prod-messagecontent-short skeleton-loader\"></span>";
    //refresh the current chat message counter in top left
    try {
        const data = chatData;
        if (!data) throw "failed, missing data";
        const encText = data["content"];
        const decompressed = LZString.decompressFromEncodedURIComponent(encText);
        const clearMsg = await decrypt(decompressed, encryptionStuff);
        if (!clearMsg || clearMsg.length === 0) throw "failed to decrypt message";
        const createdDate = Date.parse(data['created_at'] + 'Z');
        const localDate = convertUTCDateToLocalDate(new Date(createdDate));
        const timeStamp = localDate.toLocaleString();
        const messageData = JSON.parse(clearMsg);
        const chatmessage = await formatChatMessage(messageData, timeStamp);
        if (!chatmessage) throw "failed to apply formatting to message";
        userchat.innerHTML += (chatmessage);
        result = chatmessage;
    } catch (e) {
        logging.Log("Failed to decrypt a message. Check console for more info.", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        console.log(e);
        result = "<p style=\"font-size: 11px; color: red; margin-bottom: 0; margin-top: 5px\"> failed to load this message </p><br><span class=\"prod-messagecontent-short skeleton-loader\"></span>";
    }
    return result;
}

let WebRequestCache = [];

async function FetchChatMessages(force = "0") {
    //check if we are displaying messages
    const userchat = document.getElementById('user-messages');
    const currentChannelName = document.getElementById('currentChannelName');
    const currentChatMessages = document.getElementById('currentChatMessages');

    if (!userchat)//missing, page loading or something
        return;

    //check if browser tab is active
    if (document.hidden) return;

    if (force === "1") {
        fetchingMessages = false;
        WebRequestCache.forEach((val, index) => {
            val[0].abort();
            WebRequestCache.splice(index, 1);
        });
    }

    if (!encryptionStuff || Object.keys(encryptionStuff).length === 0) {//no channel joined..
        return;
    }

    //if the interval is too fast for the internet connection | LEFTOVER - REMOVE ME!
    if (fetchingMessages && force === "0") {
        return;
    }

    fetchingMessages = true;
    //get new messages
    const chatRoomAddress = await GetChatRoomAddress();
    let chatData;
    let failed = false;
    let rateLimited = false;
    let nothing = false;

    const controller = new AbortController();
    const signal = controller.signal;
    const webrequestID = WebRequestCache.push([controller, "sicherheitsgefuehl.php", force, chatRoomAddress]);
    await SendPostData('sicherheitsgefuehl.php', 'read=1&force=' + force + '&chatroom=' + chatRoomAddress, signal)
        .then(response => {
            failed = !response[0];
            return !response[0] ? GetErrorPage(response[1]) : response[1].text()
        })
        .then(async data => {
            try {
                if (failed) {
                    userchat.innerHTML = "<div class=\"d-flex justify-content-start mb-4\"> <div class=\"msg_cotainer\"><span class=\"msg_username\">Senpaii <span class=\"msg_time\" onclick='PostMessageToUser(\"user id: " + 0 + "\")'>" + " UID: ADMIN </span></span> <p style='margin-bottom: 1px;'> Looks like you have been sending quite a bit of requests. I think you will have to chill for a bit now. </p></div></div>";
                    rateLimited = true;
                    return;
                }
                nothing = (data === "E");
                if (!nothing) chatData = JSON.parse(data);
                WebRequestCache = [];
            } catch (e) {
                logging.Log("Failed to to fetch user messages. Check console for more info.", LOG_TYPE_MSG["message"].LEVEL_ERROR);
                console.log(e);
                failed = true;
            }
        }).then(CheckForAlerts);


    if (rateLimited) {
        setTimeout(() => location.reload(), 12000);
        return;
    }


    if (nothing) {
        fetchingMessages = false;
        return;
    }


    if (failed) {
        userchat.innerHTML = "";
        fetchingMessages = false;
        return;
    }

    currentChannelName.innerText = (await GetChannelNameFromToken(encryptionStuff["key"])).slice(0, 32);
    currentChatMessages.innerText = chatData.length + " Messages";

    userchat.innerHTML = "";//clear previous chat messages


    if (chatData.length === 0) {
        userchat.innerHTML += "<div class=\"d-flex justify-content-start mb-4\"> <div class=\"msg_cotainer\"><span class=\"msg_username\">Senpaii <span class=\"msg_time\" onclick='PostMessageToUser(\"user id: " + 0 + "\")'>" + " UID: ADMIN </span></span> <p style='margin-bottom: 1px;'> Wow! This looks pretty dang empty! You can send a message with the input below. </p></div></div>";
    }
    let loadedResult = "";
    for (let i = chatData.length - 1; i >= 0; i--) {
        const result = await AppendChatMessage(chatData[i], false);
        if (result === undefined) {
            logging.Log("failed to format message", LOG_TYPE_MSG["message"].LEVEL_WARNING);
            console.log(chatData[i]);
            continue;
        }

        loadedResult += result;
    }
    userchat.innerHTML = loadedResult;
    fetchingMessages = false;

    scrollToBottom();
}

/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                          Event Listeners
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

async function doStuffOnEnter(htmlElementId, stuff) {
    let htmlElement = document.getElementById(htmlElementId);
    if (htmlElement) {
        htmlElement.addEventListener("keyup", ({key}) => {
            if (key === "Enter") stuff();
        });
    }
}

function scrollToBottom() {
    const usermessages = document.getElementById('user-messages');
    if (!usermessages) return;
    usermessages.scrollTop = 2147483647;//INT32 MAX
}

async function onPageLoad() {
    const askForDecrypt = document.getElementById("ask_for_decrypt");
    const newChannelToken = document.getElementById("new_channel_token_div");
    const helperText = document.getElementById("helptext");
    const channelsettings = document.getElementById("channelsettingsgroup");

    if (newChannelToken && askForDecrypt && channelsettings) {
        if ((await DecryptChannels())) {
            askForDecrypt.hidden = true;
            newChannelToken.hidden = false;
            channelsettings.hidden = false;
            await ReloadChannels();
        } else logging.Log("failed to decrypt channels from session token..", LOG_TYPE_MSG["message"].LEVEL_WARNING);
    }

    let username = localStorage.getItem("chat-username");
    //check username
    if (username && username.length > 0 && username !== "Anonymous") {
        if (username.length > 25) username.slice(0, 25);
        document.getElementById("chat-username").value = username;
    }

    if (helperText) {
        if (localStorage.getItem("savedChannelData")) {
            helperText.innerHTML = "<span style='font-weight: 700'>Please enter your encryption password.</span><br>Forgot your key?<br>You can reset your saved data in: <br> <span style='font-weight: 600'>Settings / Reset Everything</span>";
        } else {
            helperText.innerHTML = "<span style='font-weight: 700'>Please enter an encryption key to encrypt your channel data. </span> <br> We encrypt your channel data for safe keeping on your local machine. <br> Channel data contains the channel token, channel alias and chat secret. <br> The chat username is not encrypted!";
        }
    }

    await doStuffOnEnter("encryptkey", DecryptAccessTokens);
    await doStuffOnEnter("add_to_whitelist", AddToWhitelist);

    const imageHandling = new file_engine();
    imageHandling.EventHandler;

    let element = document.getElementById("chatmessage");
    if (element) {
        let hasShift = false;

        element.addEventListener("keydown", async ({key}) => {
            if (key === "Shift") hasShift = true;

        });

        element.addEventListener("keyup", async (event) => {
            if (event.key === "Shift") hasShift = false;

            if (event.key === "Enter") {
                if (!hasShift) {
                    event.preventDefault();
                    await PostChatMessage();
                }
            }
        });

        element.addEventListener("paste", (event) => {
            const items = (event.clipboardData || event.originalEvent.clipboardData).items;
            for (const index in items) {
                const item = items[index];
                if (item.kind === 'file') {
                    let blob = item.getAsFile();
                    let reader = new FileReader();
                    reader.onload = async function (event) {
                        await imageHandling.finishUpImage(reader.result).catch((err) => {
                            logging.Log(err, LOG_TYPE_MSG["message"].LEVEL_ERROR);
                        });
                    };
                    reader.readAsDataURL(blob);
                }
            }
        });

    }


    //https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events

    let eventSource = new EventSource("client_stream.php");
    const newMessage = async function (event) {
        if (!encryptionStuff || Object.keys(encryptionStuff).length === 0) {//no channel joined..
            return;
        }
        if (typeof event.data !== 'undefined') {
            if (event.data.trim() === "keepalive") return;
            const decoded = atob(event.data);
            const data = JSON.parse(decoded);
            await AppendChatMessage(data, true);
            scrollToBottom();
            logging.Log("new message!", LOG_TYPE_MSG["message"].LEVEL_NOTIFICATION);
        }
    };

    eventSource.addEventListener("message", newMessage);

    eventSource.addEventListener("open", () => {
        logging.Log("listening to server..", LOG_TYPE_MSG["message"].LEVEL_NOTIFICATION);
    });

    eventSource.addEventListener("error", (msg) => {
        logging.Log("lost connection to server..", LOG_TYPE_MSG["message"].LEVEL_ERROR);
        PostMessageToUser("Lost connection to server!");
        console.error(msg);
    });

    // 0 = connecting, 1 = open, 2 = closed
    setInterval(() => {
        const eventSourceStates = ["connecting", "open", "closed"];
        if (eventSource.readyState !== 1) logging.Log("Current connection state is unusual! Connection for " + eventSource.url + ": " + eventSourceStates[eventSource.readyState]);
    }, 1666)

    setInterval(() => {
        logging.DisplayLogs();
        CheckForAlerts();
    }, 500);
}

function onPageError(err) {
    console.log("was that an error just now?");
    console.log(err);

    const bodytag = document.getElementsByClassName('alert-container')[0];
    if (!bodytag)//page still loading
        return;

    const div = document.createElement('div');
    div.setAttribute('id', 'js-error-banner');

    div.innerHTML = "<div class=\"alert LEVEL_FATALERROR\"> <strong>Whoops!</strong> A javascript error has occurred. Please check the console for more details.</div>";
    bodytag.insertBefore(div, bodytag.firstChild);

    console.log(err);

    setTimeout(function () {
        let element = document.getElementById('js-error-banner');
        element.parentNode.removeChild(element);
    }, 2500)
}

window.onerror = function (err) {
    onPageError(err);
}

window.addEventListener("load", onPageLoad, false);
