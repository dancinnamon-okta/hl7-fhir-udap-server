'use strict';
const authorizeLib = require('../lib/authorize')
const AWS = require('aws-sdk');

AWS.config.update({
	region: process.env.AWS_REGION
})
const dynamoDB = new AWS.DynamoDB.DocumentClient()

//Authorize endpoint - AWS implementation.
//See the authorize library for full details.
module.exports.authorizeHandler = async (event, context) => {

	//TODO: it would be nice to check the key mapping cache early on so we know if this IDP is known yet or not.
	//Right now we're reaching out to okta every time to see if we know about this IDP yet.
	const resourceServerId = event.pathParameters.resourceServerId
	const authorizeResult = await authorizeLib.authorizeHandler(event.requestContext.path, event.queryStringParameters, event.headers, resourceServerId)



	//If we registered a new IDP, we need to store a mapping between the
	//OAuth public key and the intended /token endpoint, and the community private key.
	//We're doing this here to abstract out the data storage from the business logic.
	console.log("Authorize Result:")
	console.log(authorizeResult)

	//If we didn't get what we wanted from the authorize endpoint, let's return that instead of doing anything else.
	if(authorizeResult.statusCode >= 400) {
		return {
			statusCode: authorizeResult.statusCode,
			body: JSON.stringify(authorizeResult.body)
		}
	}

	try {
		if(authorizeResult.newIdpMapping) {
			await storeIdpMapping(authorizeResult.newIdpMapping, resourceServerId)
		}

		const outputHeaders = createHeaders(authorizeResult.headers)

		return {
			statusCode: authorizeResult.statusCode,
			headers: outputHeaders.headers,
			multiValueHeaders: outputHeaders.multiValueHeaders,
			body: authorizeResult.body
		}
	}
	catch(error) {
		console.error(error)
		return {
			statusCode: 500,
			body: 'Unable to store the new IDP mapping in our IDP database.'
		}
	}
}

//Stores the OAuth key<->Community key in a dynamoDB for future retrieval
//During tiered oauth.
async function storeIdpMapping(mapping, resourceServerId) {
	console.log('New IDP Registered- storing OAuth Public key in the database.')
	console.log('Item to put in the DB:')
	console.log(mapping)
	const result = await dynamoDB.put({
		TableName: process.env.IDP_MAPPING_TABLE_NAME,
		Item: {
			idp_id: mapping.idp_id,
			idp_name: mapping.idp_name,
			idp_base_url: mapping.idp_base_url,
			internal_credentials: mapping.internal_credentials,
			original_resource_server_id: resourceServerId
		}
	}).promise()
	console.log(result)
}

function createHeaders(headers) {
  const singleValueHeaders = {}
  const multiValueHeaders = {}
  Object.entries(headers).forEach(([key, value]) => {
    const targetHeaders = Array.isArray(value) ? multiValueHeaders : singleValueHeaders
    Object.assign(targetHeaders, { [key]: value })
  })

  return {
    headers: singleValueHeaders,
    multiValueHeaders: multiValueHeaders,
  }
}
