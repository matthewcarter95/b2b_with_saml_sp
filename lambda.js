'use strict';

const serverless = require('serverless-http');
const app = require('./server');

const handler = serverless(app, {
  binary: ['image/*', 'font/*', 'application/octet-stream'],
});

module.exports.handler = async (event, context) => {
  if (event && event.requestContext && event.requestContext.http) {
    const cf = event.headers && (event.headers['cloudfront-forwarded-proto'] || event.headers['CloudFront-Forwarded-Proto']);
    const xfp = event.headers && (event.headers['x-forwarded-proto'] || event.headers['X-Forwarded-Proto']);
    if (cf || xfp) {
      event.headers['x-forwarded-proto'] = cf || xfp;
    }
  }
  return handler(event, context);
};
