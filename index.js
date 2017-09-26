var admin = require("firebase-admin");

exports.handler =  (event, context, callback) => {
    var rawToken = event.authorizationToken;
    var token = event.authorizationToken && event.authorizationToken.replace('Bearer ',''); 

    verifyFirebaseToken(token)
    .then((uid) => callback(null, generatePolicy(uid, 'Allow', event.methodArn)))
    .catch((err) => callback("Error: Invalid token"))
};

var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; // default version
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; // default action
        statementOne.Effect = effect;
        //statementOne.Resource = resource;
        // We will allow all methods to avoid issues with cached athorizations
        statementOne.Resource = "*";
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    // Can optionally return a context object of your choosing.
    authResponse.context = {};
    authResponse.context.stringKey = "stringval";
    authResponse.context.numberKey = 123;
    authResponse.context.booleanKey = true;
    return authResponse;
}

var verifyFirebaseToken = function(token) {
    const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
    const FIREBASE_PRIVATE_KEY_ID = process.env.FIREBASE_PRIVATE_KEY_ID;
    const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
    const FIREBASE_CLIENT_ID = process.env.FIREBASE_CLIENT_ID;
    const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
    const FIREBASE_CLIENT_X509_CERT_URL = process.env.FIREBASE_CLIENT_X509_CERT_URL;
    const FIREBASE_DATABASEURL = process.env.FIREBASE_DATABASEURL;
    
    const resolver = (resolve, reject) => {
        var appName = "myApp" + (new Date()).getTime();

        var firebaseAppConfig = {
            credential: admin.credential.cert({
            "type": "service_account",
            "project_id": FIREBASE_PROJECT_ID,
            "private_key_id": FIREBASE_PRIVATE_KEY_ID,
            "private_key": FIREBASE_PRIVATE_KEY,
            "client_email": FIREBASE_CLIENT_EMAIL,
            "client_id": FIREBASE_CLIENT_ID,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://accounts.google.com/o/oauth2/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": FIREBASE_CLIENT_X509_CERT_URL  }, appName),
            'databaseURL': FIREBASE_DATABASEURL
        }
        
        var myApp = admin.initializeApp(firebaseAppConfig, appName);

        myApp.auth().verifyIdToken(token)
        .then((decodedToken) => {
            var uid = decodedToken.uid;
            resolve(uid);
        })
        .catch((err) => {
            reject(err);
        })


    }

    return new Promise(resolver);
  
};
