const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//GLOBAL VARIABLES
let JWT_SECRET = null;

let CONFIG = {
	passwordRequirements: {
		enabled: false,
		minLength: 8,
		maxLength: 32,
		requireUppercase: true,
		requireLowercase: true,
		requireNumbers: true,
		requireSpecialCharacters: true,
	},
	passwordSaltRounds: 10,
	tokenExpiration: 8 * 60 * 60,
	tokenAudience: "",
	tokenIssuer: "",
	tokenCookieName: "token",
};

/**
 * Initializes the auth module
 * @param {string} jwtSecret - String
 * @param {object} config - Object
 * @returns true if successful
 * @example
 * //Default config
 * const config = {
 * 	tokenExpiration: 8 * 60 * 60, // 8 hours in seconds
 * 	passwordSaltRounds: 10, // bcrypt salt rounds
 * 	tokenAudience: "", // JWT audience
 * 	tokenIssuer: "", // JWT issuer
 * 	tokenCookieName: "token", // Name of the cookie to store the JWT
 * 	passwordRequirements: { // Password requirements
 * 		enabled: false, // Enable password requirements
 * 		minLength: 8, // Minimum length
 * 		maxLength: 32, // Maximum length
 * 		requireUppercase: true, // Require uppercase letters
 * 		requireLowercase: true, // Require lowercase letters
 * 		requireNumbers: true, // Require numbers
 * 		requireSpecialCharacters: true, // Require special characters
 * 	},
 * };
 */
function init(jwtSecret, config) {
	if (!jwtSecret) {
		throw new Error("Missing JWT Secret");
	}
	if (JWT_SECRET !== null) {
		throw new Error("Already initialized");
	}
	if (typeof jwtSecret !== "string" || jwtSecret.length !== 32) {
		throw new Error("Invalid JWT Secret");
	}
	if (config) {
		if (typeof config !== "object") {
			throw new Error("Invalid config");
		}
		if (config.tokenExpiration) {
			if (typeof config.tokenExpiration !== "number") {
				throw new Error("Invalid tokenExpiration");
			}
			CONFIG.tokenExpiration = config.tokenExpiration;
		}
		if (config.passwordSaltRounds) {
			if (typeof config.passwordSaltRounds !== "number") {
				throw new Error("Invalid passwordSaltRounds");
			}
			CONFIG.passwordSaltRounds = config.passwordSaltRounds;
		}
		if (config.tokenAudience) {
			if (typeof config.tokenAudience !== "string") {
				throw new Error("Invalid tokenAudience");
			}
			CONFIG.tokenAudience = config.tokenAudience;
		}
		if (config.tokenIssuer) {
			if (typeof config.tokenIssuer !== "string") {
				throw new Error("Invalid tokenIssuer");
			}
			CONFIG.tokenIssuer = config.tokenIssuer;
		}
		if (config.tokenCookieName) {
			if (typeof config.tokenCookieName !== "string") {
				throw new Error("Invalid tokenCookieName");
			}
			CONFIG.tokenCookieName = config.tokenCookieName;
		}
		if (config?.passwordRequirements?.enabled) {
			if (typeof config.passwordRequirements.enabled !== "boolean") {
				throw new Error("Invalid passwordRequirements.enabled");
			}

			CONFIG.passwordRequirements.enabled = config.passwordRequirements.enabled;

			if (config?.passwordRequirements?.minLength) {
				if (typeof config.passwordRequirements.minLength !== "number") {
					throw new Error("Invalid passwordRequirements.minLength");
				}
				CONFIG.passwordRequirements.minLength =
					config.passwordRequirements.minLength;
			}
			if (config?.passwordRequirements?.maxLength) {
				if (typeof config.passwordRequirements.maxLength !== "number") {
					throw new Error("Invalid passwordRequirements.maxLength");
				}
				CONFIG.passwordRequirements.maxLength =
					config.passwordRequirements.maxLength;
			}
			if (config?.passwordRequirements?.requireUppercase) {
				if (typeof config.passwordRequirements.requireUppercase !== "boolean") {
					throw new Error("Invalid passwordRequirements.requireUppercase");
				}
				CONFIG.passwordRequirements.requireUppercase =
					config.passwordRequirements.requireUppercase;
			}
			if (config?.passwordRequirements?.requireLowercase) {
				if (typeof config.passwordRequirements.requireLowercase !== "boolean") {
					throw new Error("Invalid passwordRequirements.requireLowercase");
				}
				CONFIG.passwordRequirements.requireLowercase =
					config.passwordRequirements.requireLowercase;
			}
			if (config?.passwordRequirements?.requireNumbers) {
				if (typeof config.passwordRequirements.requireNumbers !== "boolean") {
					throw new Error("Invalid passwordRequirements.requireNumbers");
				}
				CONFIG.passwordRequirements.requireNumbers =
					config.passwordRequirements.requireNumbers;
			}
			if (config?.passwordRequirements?.requireSpecialCharacters) {
				if (
					typeof config.passwordRequirements.requireSpecialCharacters !==
					"boolean"
				) {
					throw new Error(
						"Invalid passwordRequirements.requireSpecialCharacters"
					);
				}
				CONFIG.passwordRequirements.requireSpecialCharacters =
					config.passwordRequirements.requireSpecialCharacters;
			}
		}
	}

	JWT_SECRET = jwtSecret;

	return true;
}

/**
 * Hashes a password
 * @param {string} password - String
 * @returns {string} A hashed password
 * @example
 * const hash = await hashPassword("password");
 */
async function hashPassword(password) {
	try {
		if (!password) {
			throw new Error("Missing password");
		}
		const salt = await bcrypt.genSalt(CONFIG.passwordSaltRounds);
		const hash = await bcrypt.hash(password, salt);

		return hash;
	} catch (error) {
		console.log("COULD NOT HASH PASSWORD: ", error);
		return null;
	}
}

/**
 * Authenticates a password
 * @param {string} password - String
 * @param {string} hashedPassword - String
 * @param {object} tokenContent - Object
 * @param {object} hooks - Object **Optional**
 * @returns {string} A JWT token
 * @example
 * const token = await authenticate("password", "hashedPassword", { id: 1 }, {
 * 	beforeAuthenticate: () => {
 * 		// Do something before authenticating
 * 		return true; // Return false to abort the authentication process
 * 	},
 * 	onSuccess: (token) => {
 * 		// Do something on success
 * 	},
 * 	onFailure: (error) => {
 * 		// Do something on failure
 * 	},
 * );
 */
async function authenticate(
	password,
	hashedPassword,
	tokenContent,
	hooks = {}
) {
	try {
		if (hooks && typeof hooks !== "object") {
			throw new Error("Invalid hooks");
		}
		const { beforeAuthenticate, onSuccess } = hooks;
		// Before authenticate hook
		if (beforeAuthenticate && typeof beforeAuthenticate === "function") {
			const shouldContinue = beforeAuthenticate(); // can return false to abort the authentication process
			if (typeof shouldContinue === "boolean" && !shouldContinue) {
				console.log("Authentication aborted by beforeAuthenticate hook");
				return null;
			}
		}
		if (!password) {
			throw new Error("Missing password");
		}
		if (!hashedPassword) {
			throw new Error("Missing hashedPassword");
		}
		if (!tokenContent) {
			throw new Error("Missing tokenContent");
		}
		if (typeof tokenContent !== "object") {
			throw new Error("Invalid tokenContent");
		}
		if (Object.keys(tokenContent).length === 0) {
			throw new Error("Invalid tokenContent");
		}
		if (typeof hashedPassword !== "string") {
			throw new Error("Invalid hashedPassword");
		}
		if (typeof password !== "string") {
			throw new Error("Invalid password");
		}

		const passwordValid = await bcrypt.compare(password, hashedPassword);

		if (!passwordValid) {
			throw new Error("Invalid password");
		}

		const sessionToken = signJWT(tokenContent);

		if (!sessionToken) {
			throw new Error("Could not sign JWT");
		}

		// On success hook
		if (onSuccess && typeof onSuccess === "function") {
			onSuccess(sessionToken);
		}

		return sessionToken;
	} catch (error) {
		console.log("COULD NOT AUTHENTICATE: ", error);
		const { onFailure } = hooks;
		// On failure hook
		if (onFailure && typeof onFailure === "function") {
			onFailure(error);
		}
		return null;
	}
}

/**
 * Signs a JWT token
 * @param {object} tokenContent - Object
 * @returns {string} A JWT token
 * @example
 * const token = signJWT({ id: 1 });
 * console.log(token) //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 */
function signJWT(tokenContent) {
	try {
		if (!tokenContent) {
			throw new Error("Missing tokenContent");
		}
		if (typeof tokenContent !== "object") {
			throw new Error("Invalid tokenContent");
		}
		if (Object.keys(tokenContent).length === 0) {
			throw new Error("Invalid tokenContent");
		}
		if (!JWT_SECRET) {
			throw new Error("No JWT Secret");
		}
		if (typeof JWT_SECRET !== "string" || JWT_SECRET.length !== 32) {
			throw new Error("Invalid JWT Secret");
		}

		const secret = JWT_SECRET;

		const token = jwt.sign(tokenContent, secret, {
			expiresIn: CONFIG.tokenExpiration,
			audience: CONFIG.tokenAudience,
			issuer: CONFIG.tokenIssuer,
		});

		if (!token) {
			throw new Error("Could not sign JWT");
		}

		return token;
	} catch (error) {
		console.log("COULD NOT SIGN JWT: ", error);
		return null;
	}
}

/**
 * Verifies a JWT token
 * @param {string} token - JWT token as a string
 * @returns {object} The decoded token
 * @example
 * const verified = verifyJWT("token");
 * console.log(verified); //{ id: 1, iat: 1621234567, exp: 1621234567 }
 */
function verifyJWT(token) {
	try {
		if (!token) {
			throw new Error("Missing token");
		}
		if (typeof token !== "string") {
			throw new Error("Invalid token");
		}
		if (!JWT_SECRET) {
			throw new Error("No JWT Secret");
		}
		if (typeof JWT_SECRET !== "string" || JWT_SECRET.length !== 32) {
			throw new Error("Invalid JWT Secret");
		}
		const secret = JWT_SECRET;
		const verified = jwt.verify(token, secret);
		return verified;
	} catch (error) {
		//console.log("COULD NOT VERIFY JWT: ", error);
		return null;
	}
}

/**
 * Middleware to ensure that a user is authenticated, and adds the user to the request object
 * Checks if a JWT token is present in the Authorization header or in the cookies
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Express next function
 * @returns {object} Express response object
 * @example
 * app.get("/", auth.ensureAuth, (req, res, next) => {
 * 	res.status(200).json({
 * 		user: req.user,
 * 		});
 * });
 */
function ensureAuth(req, res, next) {
	try {
		let token;

		// Check for token in cookies
		if (req?.cookies?.[CONFIG.tokenCookieName]) {
			token = req.cookies[CONFIG.tokenCookieName];
		}

		// Check for Bearer token in Authorization header
		const authHeader = req.headers.authorization;
		if (authHeader && authHeader.startsWith("Bearer ")) {
			token = authHeader.split(" ")[1]; // Extract the token
		}

		if (!token) {
			return res.status(401).json({ error: "No token found" });
		}

		const verified = verifyJWT(token);
		if (!verified) {
			return res.status(401).json({ error: "Token signature mismatch" });
		}
		req.user = verified;
		next();
	} catch (error) {
		console.log("COULD NOT ENSURE AUTH: ", error);
		return res.status(500).json({ error: error.message });
	}
}

function endSession(req, res) {
	try {
		res.clearCookie(CONFIG.tokenCookieName);
	} catch (error) {}
}

module.exports = {
	init,
	hashPassword,
	authenticate,
	ensureAuth,
	signJWT,
	verifyJWT,
};
