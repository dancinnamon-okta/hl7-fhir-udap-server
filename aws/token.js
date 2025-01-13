'use strict';
const tokenLib = require('../lib/token')

//Token proxy - AWS implementation.
//See the token library for full documentation.
module.exports.tokenHandler = async (event, context) => {
	var handlerResponse = await tokenLib.tokenHandler(event.requestContext.path, event.body, event.headers, event.pathParameters.resourceServerId)

	return {
		statusCode: handlerResponse.statusCode,
		body: JSON.stringify(handlerResponse.body),
		headers: {"Cache-Control": "no-store", "Pragma": "no-cache"}
	}
}
