const crypto = require("crypto");

//Generate JWT Secret
/**
 * Generates a random string of 16 bytes (32 characters) to use as a JWT secret
 * @returns {string} A random 32 character string
 * @example
 * const secret = generateJWTSecret();
 * console.log(secret); //8ac93046d3a59b16f49a533797d6d6f3
 */
function generateJWTSecret() {
	try {
		return crypto.randomBytes(16).toString("hex");
	} catch (error) {
		console.log("COULD NOT GENERATE JWT SECRET: ", error);
		throw new Error("Failed to generate JWT secret");
	}
}

module.exports = { generateJWTSecret };
