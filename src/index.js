const {
	authenticate,
	init,
	signJWT,
	verifyJWT,
	hashPassword,
	isStrongPassword,
	logout,
} = require("./utils/functions");
const { generateJWTSecret } = require("./utils/utils");
const { ensureAuth } = require("./middleware/middleware");

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
};
