const {
	authenticate,
	init,
	signJWT,
	verifyJWT,
	hashPassword,
	isStrongPassword,
	logout,
	ensureAuth,
	sessionHandler,
} = require("./lib/functions");
const { generateJWTSecret } = require("./lib/utils");

module.exports = {
	authenticate,
	generateJWTSecret,
	hashPassword,
	init,
	signJWT,
	verifyJWT,
	isStrongPassword,
	logout,
	ensureAuth,
	sessionHandler,
};
