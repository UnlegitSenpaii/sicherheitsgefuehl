/*
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                            Logging
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

const LOG_TYPE_MSG = {
    message: {
        LEVEL_DEBUG: 0, LEVEL_CONSOLE: 1, LEVEL_NOTIFICATION: 2, LEVEL_WARNING: 3, LEVEL_ERROR: 4, LEVEL_FATALERROR: 5
    }, style: {
        0: "LEVEL_DEBUG",
        1: "LEVEL_CONSOLE",
        2: "LEVEL_NOTIFICATION",
        3: "LEVEL_WARNING",
        4: "LEVEL_ERROR",
        5: "LEVEL_FATALERROR"
    }, print: {
        0: "DEBUG", 1: "CONSOLE", 2: "NOTIFICATION", 3: "WARNING", 4: "ERROR", 5: "FATALERROR"
    }, timeout: {
        0: 100,
        1: 100,
        2: 1500,
        3: 2000,
        4: 2500,
        5: 5000
    }
}

class logging_message {
    constructor(errormessage, messagelevel = LOG_TYPE_MSG["message"].LEVEL_CONSOLE) {
        this.errorMessage = errormessage;
        this.messageLevel = messagelevel;
        //emptiness
    }

    get GetErrorMessage() {
        return this.errorMessage;
    }

    get GetMessageLevel() {
        return this.messageLevel;
    }

    set SetMessageLevel(messagelvl) {
        this.messageLevel = messagelvl;
    }

    set SetErrorMessage(errormsg) {
        this.errorMessage = errormsg;
    }
}


class logging_engine {
    constructor(htmlEntity = "crypt-logs", hookToConsole = false) {
        this.HTMLElementID = htmlEntity;
        this.hookToConsole = false;
        this.notificationQueue = [];
    }

    get GetNotificationQueue() {
        return this.notificationQueue;
    }

    get ShouldHookToConsole() {
        return this.hookToConsole;
    }

    get LoggingHTMLElementID() {
        return this.HTMLElementID;
    }

    Log(message, messageLevel = LOG_TYPE_MSG["message"].LEVEL_CONSOLE) {
        const msg = new logging_message(message, messageLevel);

        //prioritize this.
        if (messageLevel === LOG_TYPE_MSG["message"].LEVEL_FATALERROR) this.ClearNotifications();

        this.notificationQueue.push(msg);
    }

    CreateElementForMessage(message, messageLevel) {
        const bodytag = document.getElementsByClassName('alert-container')[0];
        if (!bodytag)//page still loading
            return;

        const div = document.createElement('div');
        div.setAttribute('id', btoa(message + messageLevel));

        div.innerHTML = "<div class=\"alert " + LOG_TYPE_MSG["style"][messageLevel] + "\"> <strong> " + LOG_TYPE_MSG["print"][messageLevel] + "</strong> " + sanitize(message) + "</div>";
        bodytag.insertBefore(div, bodytag.firstChild);

        setTimeout(() => {
            let element = document.getElementById(btoa(message + messageLevel));
            element.parentNode.removeChild(element);
        }, LOG_TYPE_MSG["timeout"][messageLevel]);
    }

    DisplayLogs() {
        const debugLogElement = document.getElementById(this.HTMLElementID);
        if (!debugLogElement) return;

        this.notificationQueue.forEach((msg) => {
            console.log("[" + LOG_TYPE_MSG["style"][msg.messageLevel] + "] " + msg.errorMessage);
            this.CreateElementForMessage(msg.errorMessage, msg.messageLevel);
        })
        this.ClearNotifications();
    }

    ClearNotifications() {
        this.notificationQueue = [];
    }
}
