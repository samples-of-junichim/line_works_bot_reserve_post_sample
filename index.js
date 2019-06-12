
'use strict';

const API_ID = process.env.LINE_WORKS_API_ID;
const SERVER_CONSUMER_KEY = process.env.LINE_WORKS_SERVER_CONSUMER_KEY;
const SERVER_ID = process.env.LINE_WORKS_SERVER_ID;
// プライベートキーは開業を \n 文字に置換して一行にしておく
// Lambda コンソールで定義する際はダブルクォーテーションは不要
const PRIVATE_KEY = process.env.LINE_WORKS_PRIVATE_KEY.replace(/\\n/g, "\n");
const BOT_NO = process.env.LINE_WORKS_BOT_NO;


const TOKEN_PATH = "/b/" + API_ID + "/server/token";
const SANDBOX = process.env.sandbox ? "sandbox-" : "";

const TOKEN_URL = "https://" + SANDBOX + "auth.worksmobile.com" + TOKEN_PATH;
const SEND_URL = "https://apis.worksmobile.com/" + API_ID + "/message/sendMessage/v2";

const LAMBDA_ARN_SEND = process.env.LAMBDA_ARN_SEND;

const DST_ID = "宛先ユーザーのID";

const AWS = require("aws-sdk");
const jwt = require('jsonwebtoken');
const request = require("request-promise");
const crypto = require("crypto");


exports.reserveHandler = async (event) => {
    console.log("start");
    console.log(JSON.stringify(event));
    
    // メッセージチェック
    const body_str = event.body;
    const signiture = event.headers["x-works-signature"];

    if (! isValidMessage(body_str, signiture)) {
        console.warn("message is invalid");
        throw new Error("message is inivalid. maybe falsification.");
    }

    // 受信メッセージの確認
    const body = JSON.parse(body_str);
    if (body.type != "message") {
        console.log("no text message. type is: " + body.type);
        const response = {
            statusCode: 400,
            body: JSON.stringify('not target message'),
        };
        return response;
    }

    // CloudWatch Event 生成
    const id_from = body.source.accountId;
    const id_to = DST_ID;
    const org_msg = body.content.text;
    try {
        await createClodWatchEvent(id_from, id_to, org_msg);
    } catch (err) {
        handleError(err);
    }

    const response = {
        statusCode: 200,
        body: JSON.stringify('success'),
    };
    return response;
};
exports.postHandler = async (event) => {
    console.log("start");
    console.log(JSON.stringify(event));
    
    // パラメータ取得
    const id_from = event.id_from;
    const id_to = event.id_to;
    const org_msg = event.message;
    const rule_name = event.rule_name;

    // 予約送信
    // LINE WORKS API アクセス用 Server Token の取得
    let token;
    try {
        token = await getServerToken();
    } catch(err) {
        handleError(err, "getServerToken exception occured");
    }

    // 送信処理
    try {
        await sendMessage(token, id_to, "送信者: " + id_from);
        await sendMessage(token, id_to, org_msg);
    } catch(err) {
        handleError(err, "sendMessage exception occured");
    }

    // CloudWatch イベントの削除
    try {
        await removeCloudWatchEvent(rule_name);
    } catch(err) {
        handleError(err, "removeCloudWatchEvent exception occured");
    }

    const response = {
        statusCode: 200,
        body: JSON.stringify('success'),
    };
    return response;
};

function isValidMessage(body, signiture) {
    const hmac = crypto.createHmac("sha256", API_ID);
    hmac.update(body);
    const str = hmac.digest('base64');

    console.log("message body: " + body);
    console.log("message hmac: " + str);
    console.log("signiture   : " + signiture);

    return str === signiture;
}

async function createClodWatchEvent(id_from, id_to, message) {
    const rule_name = await createCloudWatchRule();
    await assignRuleToLambda(rule_name, id_from, id_to, message);
}
async function createCloudWatchRule() {
    let cwe = new AWS.CloudWatchEvents();
    let params = {
        Name: 'post_reservation', /* required */
        Description: 'LINE WORKS post reservation, from, to, at,',
        ScheduleExpression: getCronExpression(),
        State: "ENABLED"
    };
    return new Promise((resolve, reject) => {
        cwe.putRule(params, function(err, data) {
            if (err) {
                console.error("createCloudWatchRule err: " + JSON.stringify(err), err.stack);
                reject(err);
            } else {
                console.log("createCloudWatchRule: " + JSON.stringify(data));
                resolve(params.Name); // ルール名を返す
            }
        });
    });
}
function getCronExpression() {
    // cron 式の生成
    // UTC
    const nw = new Date(Date.now() + 3 * 60 * 1000); // 3分後

    const SP = " ";
    const minute = nw.getUTCMinutes();
    const hour = nw.getUTCHours();
    const date = nw.getUTCDate();
    const month = nw.getUTCMonth() + 1;
    const year = nw.getUTCFullYear();
    return "cron(" + minute + SP + hour + SP + date + SP + month + SP + "?" + SP + year + ")";
}
async function assignRuleToLambda(rule_name, id_from, id_to, message) {
    let cwe = new AWS.CloudWatchEvents();
    let params = {
        Rule: rule_name,
        Targets: [
          {
            Arn: LAMBDA_ARN_SEND,
            Id: '1', /* required */
            Input: "{ \"rule_name\": \"" + rule_name + "\", \"id_from\": \"" + id_from + "\", \"id_to\": \"" + id_to + "\", \"message\": \"" + message + "\" }",
          }
        ]
    };
    return new Promise((resolve, reject) => {
        cwe.putTargets(params, function(err, data) {
            if (err) {
                console.error("assignRuleToLambda error: " + JSON.stringify(err), err.stack);
                reject(err);
            } else {
                console.log("assignRuleToLambda: " + JSON.stringify(data));
                if (data.FailedEntryCount != 0) {
                    console.error("assignRuleToLambda has error: " + JSON.stringify(data));
                    reject(data);
                }
                resolve(data);
            }
          });    
    });      
}

async function removeCloudWatchEvent(rule_name) {
    console.log("removeCloudWatchEvent: " + rule_name);
    
    const targets = await listTargetsByRule(rule_name);
    await removeTargets(rule_name, targets);
    await deleteRule(rule_name);
}
async function listTargetsByRule(rule_name) {
    let cwe = new AWS.CloudWatchEvents();
    let params = {
        Rule: rule_name
    }
    return new Promise((resolve, reject) => {
        cwe.listTargetsByRule(params, (err, data) => {
            if (err) {
                console.error("listTargetsByRule error: " + JSON.stringify(err), err.stack);
                reject(err);
            } else {
                console.log("listTargetsByRule: " + JSON.stringify(data));
                // ID 配列の生成
                let ids = [];
                for (let elm of data.Targets) {
                    ids.push(elm.Id);
                }
                resolve(ids);
            }
        });
    });
}
async function removeTargets(rule_name, targets) {
    let cwe = new AWS.CloudWatchEvents();
    let params = {
        Ids: targets,
        Rule: rule_name
    }
    return new Promise((resolve, reject) => {
        cwe.removeTargets(params, (err, data) => {
            if (err) {
                console.error("removeTargets error: " + JSON.stringify(err), err.stack);
                reject(err);
            } else {
                console.log("removeTargets: " + JSON.stringify(data));
                if (data.FailedEntryCount != 0) {
                    console.error("removeTargets has error: " + JSON.stringify(data));
                    reject(data);
                }
                resolve(data);
            }
        });
    });
}
async function deleteRule(rule_name) {
    let cwe = new AWS.CloudWatchEvents();
    let params = {
        Name: rule_name
    }
    return new Promise((resolve, reject) => {
        cwe.deleteRule(params, (err, data) => {
            if (err) {
                console.error("deleteRule error: " + JSON.stringify(err), err.stack);
                reject(err);
            } else {
                console.log("deleteRule: " + JSON.stringify(data));
                resolve(data);
            }
        });
    });

}


function getJwt() {
    const iat = Math.floor(Date.now() / 1000); // msec-> sec
    const exp = iat + (60 * 30); // 30分後
    let token = jwt.sign({
        iss: SERVER_ID,
        iat: iat,
        exp: exp
    }, PRIVATE_KEY, {algorithm: 'RS256'});
    return token;
}

async function getServerToken() {
    const jwtoken = getJwt();
    console.log("jwtoken: " + jwtoken);

    const headers = {
        "Content-type": "application/x-www-form-uelencoded; charset=UTF-8"
    };
    const options = {
        url : TOKEN_URL,
        method : "POST",
        headers : headers,
        form : {
            "grant_type": encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            "assertion" : jwtoken
        },
        json : true
    };

    return request(options)
        .then((body) => {
            console.log("getServerToken:" + JSON.stringify(body));
            return body.access_token;
        });
}

async function sendMessage(serverToken, dst_id, org_msg) {
    const headers = {
        "Content-type": "application/json; charset=UTF-8",
        "consumerKey": SERVER_CONSUMER_KEY,
        "Authorization": "Bearer " + serverToken
    };
    const options = {
        url : SEND_URL,
        method : "POST",
        headers : headers,
        json : {
            "botNo": Number(BOT_NO),
            "accountId": dst_id,
            "content": {
                "type": "text",
                "text": org_msg
            }
        }
    };

    return request(options)
        .then((body) => {
            if (body.code != 200) {
                console.error("sendMessage error: " + JSON.stringify(body));
                throw new Error(body.errorMessage);
            }
            console.log("sendMessage success: " + JSON.stringify(body));
            return "finish";
        });

}

function handleError(err, base_message) {
    if (err instanceof Error) {
        console.error(base_message + ": " + err.name + ", " + err.message);
        throw err;
    } else {
        console.error(base_message + ": " + JSON.stringify(err));
        throw new Error(JSON.stringify(err));
    }
}