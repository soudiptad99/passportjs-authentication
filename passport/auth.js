module.exports = {
    // https://developers.facebook.com/apps/
    'facebook' : {
        'clientID'      : 'YOUR CLIENT ID HERE',            // your App ID
        'clientSecret'  : 'YOUR CLIENT SECRET HERE',        // your App Secret
        'callbackURL'   : 'http://localhost:3000/auth/facebook/callback'
    },
    // https://apps.twitter.com/
    'twitter' : {
        'consumerKey'       : 'YOUR CONSUMER KEY HERE',
        'consumerSecret'    : 'YOUR CONSUMER SECRET HERE',
        'callbackURL'       : 'http://localhost:3000/auth/twitter/callback'
    },
    // https://console.cloud.google.com/
    'google' : {
        'clientID'      : 'YOUR CLIENT ID HERE',
        'clientSecret'  : 'YOUR CLIENT SECRET HERE',
        'callbackURL'   : 'http://localhost:3000/auth/google/callback'
    }
};