/* eslint-__ENV node */
/* eslint no-use-before-define: [0, "nofunc"] */
"use strict";

var crypto = require("k6/crypto");

//v4Sign takes a standard http request object and returns the request signed with AWS V4 Signature
function v4Sign(req, awsCredentials) {
  options.timestamp = options.timestamp || Date.now();
  options.region = options.region || "eu-west-1";
  options.key = awsCredentials.accessKeyId;
  options.secret = awsCredentials.secretAccessKey;
  options.sessionToken = awsCredentials.sessionToken;
  options.doubleEscape = false;

  //Appending required X-Amz-Date header
  req.params.headers["X-Amz-Date"] = toTime(options.timestamp);

  var signedHeaders = createSignedHeaders(req.params.headers);

  var canonicalRequest = createCanonicalRequest(
    req.method,
    req.path,
    req.query,
    req.params.headers,
    signedHeaders,
    req.payload,
    options.doubleEscape
  );

  var scope = createCredentialScope(
    options.timestamp,
    options.region,
    req.service
  );

  var stringToSign = createStringToSign(
    options.timestamp,
    scope,
    canonicalRequest
  );

  var signature = createSignature(
    options.secret,
    options.timestamp,
    options.region,
    req.service,
    stringToSign
  );

  req.params.headers["Authorization"] = createAuthorizationHeader(
    options.key,
    scope,
    signedHeaders,
    signature
  );

  return req;
}

exports.v4Sign = v4Sign;

function createCanonicalRequest(
  method,
  pathname,
  query,
  headers,
  signedHeaders,
  payload,
  doubleEscape
) {
  return [
    method.toUpperCase(),
    createCanonicalURI(
      doubleEscape
        ? pathname
            .split(/\//g)
            .map((v) => encodeURIComponent(v))
            .join("/")
        : pathname
    ),
    createCanonicalQueryString(query),
    createCanonicalHeaders(headers),
    signedHeaders,
    createCanonicalPayload(payload),
  ].join("\n");
}

function createCanonicalURI(uri) {
  var url = uri;
  if (uri[uri.length - 1] == "/" && url[url.length - 1] != "/") {
    url += "/";
  }
  return url;
}

function queryParse(qs) {
  if (typeof qs !== "string" || qs.length === 0) {
    return {};
  }

  var result = {};

  var split = qs.split("&");
  for (let i = 0; i < split.length; i++) {
    let parts = split[i].split("=");
    if (parts.length === 2) {
      result[decodeURIComponent(parts[0])] = decodeURIComponent(parts[1]);
    } else {
      result[decodeURIComponent(split[i])] = "";
    }
  }
  return result;
}

function createCanonicalPayload(payload) {
  if (payload == "UNSIGNED-PAYLOAD") {
    return payload;
  }
  return hash(payload || "", "hex");
}

function createCanonicalQueryString(params) {
  if (!params) {
    return "";
  }
  if (typeof params == "string") {
    params = queryParse(params);
  }
  return Object.keys(params)
    .sort()
    .map(function (key) {
      var values = Array.isArray(params[key]) ? params[key] : [params[key]];
      return values
        .sort()
        .map(function (val) {
          return encodeURIComponent(key) + "=" + encodeURIComponent(val);
        })
        .join("&");
    })
    .join("&");
}
createCanonicalQueryString = createCanonicalQueryString;

function createCanonicalHeaders(headers) {
  return Object.keys(headers)
    .sort()
    .map(function (name) {
      var values = Array.isArray(headers[name])
        ? headers[name]
        : [headers[name]];
      return (
        name.toLowerCase().trim() +
        ":" +
        values
          .map(function (v) {
            return v.replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
          })
          .join(",") +
        "\n"
      );
    })
    .join("");
}

function createSignedHeaders(headers) {
  return Object.keys(headers)
    .sort()
    .map(function (name) {
      return name.toLowerCase().trim();
    })
    .join(";");
}

function createCredentialScope(time, region, service) {
  return [toDate(time), region, service, "aws4_request"].join("/");
}

exports.createCredentialScope = createCredentialScope;

function createStringToSign(time, scope, request) {
  return ["AWS4-HMAC-SHA256", toTime(time), scope, hash(request, "hex")].join(
    "\n"
  );
}

function createAuthorizationHeader(key, scope, signedHeaders, signature) {
  return [
    "AWS4-HMAC-SHA256 Credential=" + key + "/" + scope,
    "SignedHeaders=" + signedHeaders,
    "Signature=" + signature,
  ].join(", ");
}

function createSignature(secret, time, region, service, stringToSign) {
  var h1 = hmac("AWS4" + secret, toDate(time), "binary"); // date-key
  var h2 = hmac(h1, region, "binary"); // region-key
  var h3 = hmac(h2, service, "binary"); // service-key
  var h4 = hmac(h3, "aws4_request", "binary"); // signing-key
  return hmac(h4, stringToSign, "hex");
}

function toTime(time) {
  return new Date(time).toISOString().replace(/[:\-]|\.\d{3}/g, "");
}

function toDate(time) {
  return toTime(time).substring(0, 8);
}

function hmac(key, data, encoding) {
  return crypto.hmac("sha256", key, data, encoding);
}

function hash(string, encoding) {
  return crypto.sha256(string, encoding);
}
