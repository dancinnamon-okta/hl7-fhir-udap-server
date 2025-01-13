'use strict';
const fs = require('fs')
const udapCommon = require('hl7-fhir-udap-common')
const axios = require('axios')
const ResourceServerConfig = require('./resource_server_config')

//Added to handle UDAP meta data
module.exports.getUDAPConfiguration = (resourceServerId) => {
	try {
		//TODO: I'm assuming that the P12 file only has one private/public key pair. Perhaps there should be a config variable to pick which entry.
		const rsConfig = ResourceServerConfig.getResourceServerConfig(resourceServerId)

		if(rsConfig.role != 'idp') {
			return {"statusCode": 400, "body": {"error": "This resource server is not configured as an identity provider."}}
		}

		const certAndPrivateKey = udapCommon.parsePKCS12(rsConfig.identity.identity_store, rsConfig.identity.identity_store_pwd)
		const serverCertAndKey = getCertificateBySAN(certAndPrivateKey, rsConfig.identity.san)

		if(serverCertAndKey) {
			const claims = {
				iss: rsConfig.identity.san,
				sub: rsConfig.identity.san,
				authorize_endpoint: process.env.OAUTH_AUTHORIZE_ENDPOINT_PATTERN.replace("<resource_server_id>", rsConfig.id),
				token_endpoint: process.env.OAUTH_TOKEN_ENDPOINT_PATTERN.replace("<resource_server_id>", rsConfig.id),
				registration_endpoint: process.env.OAUTH_REGISTRATION_ENDPOINT_PATTERN.replace("<resource_server_id>", rsConfig.id)
			}
			return {
				"statusCode": 200,
				"body": {
					"udap_versions_supported": ["1"],
					"udap_profiles_supported": ["udap_dcr", "udap_authn", "udap_authz", "udap_to"],
					"udap_authorization_extensions_supported": [],
					"udap_authorization_extensions_required": [],
					"udap_certifications_supported": [],
					"udap_certifications_required": [],
					"grant_types_supported": ["authorization_code", "refresh_token",  "client_credentials"],
					"scopes_supported": ["openid", "fhirUser", "email", "profile","udap"],
					"registration_endpoint": claims.registration_endpoint,
					"registration_endpoint_jwt_signing_alg_values_supported": [rsConfig.signing_algorithm],
					"authorization_endpoint" : claims.authorize_endpoint,
					"token_endpoint":  claims.token_endpoint,
					"token_endpoint_auth_signing_alg_values_supported":[rsConfig.signing_algorithm],
					"token_endpoint_auth_methods_supported": ["private_key_jwt"],
					"signed_metadata": getSignedEndpointsJWT(serverCertAndKey, claims, rsConfig.signing_algorithm)
				}
			}
		}
		else {
			return {"statusCode": 500, "body": {"error": "The SAN configured to be used for IDP purposes does not exist within any of the certificates provided."}}
		}
	}
	catch(error) {
		console.error(error)
		return {"statusCode": 500, "body": {"error": "An unknown error has occurred while generating the UDAP metadata content."}}
	}
}

module.exports.getFHIRServerWellKnown = async (communityId) => {
	const udapMetaResponse = await axios.request({
		'url': `${process.env.FHIR_BASE_URL}/.well-known/udap?community=${communityId}`,
		'method': 'GET',
		'headers': {'Content-Type': 'application/fhir+json'},
	})
	
	return udapMetaResponse.data
}

function getSignedEndpointsJWT(certAndPrivateKey, signedMetaclaims, signingAlgorithm) {
	const claims = {
		"iss": signedMetaclaims.iss,
		"sub": signedMetaclaims.sub,
		"authorization_endpoint": signedMetaclaims.authorize_endpoint,
		"token_endpoint": signedMetaclaims.token_endpoint,
		"registration_endpoint": signedMetaclaims.registration_endpoint
	}
	return udapCommon.generateUdapSignedJwt(claims, certAndPrivateKey, signingAlgorithm)
}

function getCertificateBySAN(certArray, san) {
	for(var i=0; i<certArray.length; i++) {
		if(udapCommon.validateSanInCert(san, certArray[i].certChain[0])) {
			return certArray[i]
		}
	}
	return null
}