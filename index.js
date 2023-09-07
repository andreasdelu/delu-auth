const {
	authenticate,
	ensureAuth,
	init,
	signJWT,
	verifyJWT,
	hashPassword,
	isStrongPassword,
	logout,
} = require("./functions");
const { generateJWTSecret } = require("./utils");

module.exports = {
	authenticate,
	ensureAuth,
	generateJWTSecret,
	hashPassword,
	init,
	signJWT,
	verifyJWT,
	isStrongPassword,
	logout,
};
