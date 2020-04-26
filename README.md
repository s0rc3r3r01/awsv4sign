# awsv4sign
API calls to AWS resources need to be signed with [AWS V4 Signature](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html). 

This is a small library for [K6](https://k6.io/) to sign AWS V4 HTTP requests. 

The library, uses K6's native Go library rather than Javascript (browserifed) version of the documentation resulting in signifincatly higher speed (various orders of magnitude).

This resource is also useful when needed to parallelize requests with a high number of VUs


Example utilization:

```javascript
import awsv4sign from "./awsv4sign.js";

const AWSCREDENTIALS = {
  accessKeyId: __ENV.AWS_ACCESS_KEY_ID,
  secretAccessKey: __ENV.AWS_SECRET_ACCESS_KEY,
  region: __ENV.AWS_SECRET_ACCESS_KEY,
};
const ENDPOINT = "dynamodb.us-west-1.amazonaws.com";


  var dynamoPayload = `{
    "TableName": "Pets",
    "Key": {
        "AnimalType": {"S": "Dog"},
        "Name": {"S": "Fido"}
    }
  }`;
  var req = {
    hostname: ENDPOINT,
    method: "POST",
    params: {
      headers: {
        "Content-Type": "application/x-amz-json-1.1",
        Host: ENDPOINT,
        "X-Amz-Target": "DynamoDB_20120810.GetItem",
      },
    },
      path: "/",
      query: "",
      service : "dynamodb",
      payload : dynamoPayload,
  };
  
  var wrappedReq = awsv4sign.v4Sign(
    req,
    AWSCREDENTIALS,
  );

  let res = http.post(`https://${wrappedReq.hostname}`, wrappedReq.payload, wrappedReq.params);
```

# References
The library is a simplified and forked version from: https://gist.github.com/MStoykov/38cc1293daa9080b11e26053589a6865 
