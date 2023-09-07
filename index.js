const {
	authenticate,
	ensureAuth,
	init,
	signJWT,
	verifyJWT,
	hashPassword,
} = require("./functions");
const { generateJWTSecret } = require("./utils");

hashPassword("password").then((hash) => {
	console.log(hash);
});

module.exports = {
	authenticate,
	ensureAuth,
	generateJWTSecret,
	hashPassword,
	init,
	signJWT,
	verifyJWT,
};
