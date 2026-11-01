const c = require('crypto');
console.log('MASTER_KEY=' + c.randomBytes(32).toString('base64'));
