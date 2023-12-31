const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

/* 
TO DO:
	- INTEGRATE SIMPLE OAUTH2!!! 

*/

let CONFIG = require("./delu-auth.config.json");

let tokenBlacklist = [
	/* Array of blacklisted tokens */
];

/**
 * Initializes the auth module
 * @param {object} config - Object
 * @returns true if successful
 * @example
 * //Default config
 * const config = {
 * 	jwtSecret: null, // JWT secret
 * 	tokenExpiration: 8 * 60 * 60, // 8 hours in seconds
 * 	loginRedirectPath: "/login", // Redirect path if user is not authenticated
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
function init(config) {
	if (CONFIG.jwtSecret !== null) {
		throw new Error("Already initialized");
	}
	if (config) {
		if (typeof config !== "object") {
			throw new Error("Invalid config");
		}
		if (config.jwtSecret) {
			if (typeof config.jwtSecret !== "string") {
				throw new Error("Invalid jwtSecret");
			}
			CONFIG.jwtSecret = config.jwtSecret;
		}
		if (config.defaultRedirectPath) {
			if (typeof config.defaultRedirectPath !== "string") {
				throw new Error("Invalid defaultRedirectPath");
			}
			CONFIG.defaultRedirectPath = config.defaultRedirectPath;
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

	return true;
}

/**
 * Checks if password passes the password requirements set in the config
 * @param {string} password - String
 * @returns {boolean} True if the password is valid
 * @example
 * const valid = await verifyPassword("Password123!");
 * console.log(valid); //true
 * @example
 * const valid = await verifyPassword("password");
 * console.log(valid); //false
 */
function isStrongPassword(password) {
	try {
		if (!password) {
			throw new Error("Missing password");
		}
		if (typeof password !== "string") {
			throw new Error("Invalid password");
		}

		const errors = [];
		if (CONFIG.passwordRequirements.enabled) {
			if (password.length < CONFIG.passwordRequirements.minLength) {
				errors.push(
					`Password must be at least ${CONFIG.passwordRequirements.minLength} characters long`
				);
			}
			if (password.length > CONFIG.passwordRequirements.maxLength) {
				errors.push(
					`Password must be at most ${CONFIG.passwordRequirements.maxLength} characters long`
				);
			}
			if (CONFIG.passwordRequirements.requireUppercase) {
				if (!/[A-Z]/.test(password)) {
					errors.push("Password must contain at least one uppercase letter");
				}
			}
			if (CONFIG.passwordRequirements.requireLowercase) {
				if (!/[a-z]/.test(password)) {
					errors.push("Password must contain at least one lowercase letter");
				}
			}
			if (CONFIG.passwordRequirements.requireNumbers) {
				if (!/[0-9]/.test(password)) {
					errors.push("Password must contain at least one number");
				}
			}
			if (CONFIG.passwordRequirements.requireSpecialCharacters) {
				if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
					errors.push("Password must contain at least one special character");
				}
			}
		} else {
			throw new Error(
				"Password requirements are disabled, enable them in the config"
			);
		}
		if (errors.length > 0) {
			throw new Error(errors.join(", "));
		}
		return true;
	} catch (error) {
		console.log("COULD NOT VERIFY PASSWORD: ", error);
		return false;
	}
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
		if (!salt) {
			throw new Error("Could not generate salt");
		}
		const hash = await bcrypt.hash(password, salt);
		if (!hash) {
			throw new Error("Could not hash password");
		} else {
			return hash;
		}
	} catch (error) {
		console.log("COULD NOT HASH PASSWORD: ", error);
		return null;
	}
}

/**
 * Authenticates a password
 * If authentication is successful, a JWT token is signed and set as a cookie and a 200 response is sent
 * If the onSuccess hook is provided with a return, it will be called instead of sending a response (useful for redirecting);
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {string} password - String
 * @param {string} hashedPassword - String
 * @param {object} tokenContent - Object
 * @param {object} hooks - Object **Optional**
 * @returns {object} Express response object
 * @example
 * app.post("/login", async (req, res) => {
 * 	const { password } = req.body;
 *
 * 	const hashedPassword = await getHashedPasswordFromDB(); // Get hashed password from database
 *
 * 	const tokenContent = { id: 1 };
 *
 * 	await authenticate(req, res, password, hashedPassword, tokenContent); // Returns a 200 response with a JWT token
 * });
 *
 * @example
 * app.post("/login", async (req, res) => {
 * 	const { password } = req.body;
 *
 * 	const hashedPassword = await getHashedPasswordFromDB(); // Get hashed password from database
 *
 * 	const tokenContent = { id: 1 };
 *
 * 	await authenticate(req, res, password, hashedPassword, tokenContent,
 * 	{
 * 		beforeAuthenticate: () => {
 * 			// Do something before authenticating
 * 			return true; // Return false to abort the authentication process
 * 		},
 * 		onSuccess: (token, res) => {
 * 			// Do something on success (redirect, etc.)
 * 			// Reminder if using post: To handle redirects properly, route needs to be requested from a form
 * 			return res.redirect("/");
 * 		},
 * 		onFailure: (error) => {
 * 			// Do something on failure
 * 		},
 * 	});
 * });
 */
async function authenticate(
	req,
	res,
	password,
	hashedPassword,
	tokenContent,
	hooks = {}
) {
	try {
		if (hooks && typeof hooks !== "object") {
			throw new Error("Invalid hooks");
		}
		// Before authenticate hook
		if (
			hooks?.beforeAuthenticate &&
			typeof hooks?.beforeAuthenticate === "function"
		) {
			const shouldContinue = hooks?.beforeAuthenticate(); // can return false to abort the authentication process
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

		// Set the authentication cookie
		res.cookie(CONFIG.tokenCookieName, sessionToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			maxAge: CONFIG.tokenExpiration * 1000,
		});

		// On success hook
		if (hooks?.onSuccess && typeof hooks?.onSuccess === "function") {
			hooks?.onSuccess(sessionToken, res);
			return;
		}

		return res.status(200).json({
			message: "Logged in",
			token: sessionToken,
			redirectPath: CONFIG.defaultRedirectPath,
		});
	} catch (error) {
		console.log("COULD NOT AUTHENTICATE: ", error);
		// On failure hook
		if (hooks?.onFailure && typeof hooks?.onFailure === "function") {
			hooks?.onFailure(error);
		}
		return res.status(500).json({ error: error.message });
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
		if (!CONFIG.jwtSecret) {
			throw new Error("No JWT Secret");
		}
		if (
			typeof CONFIG.jwtSecret !== "string" ||
			CONFIG.jwtSecret.length !== 32
		) {
			throw new Error("Invalid JWT Secret");
		}

		const secret = CONFIG.jwtSecret;

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
		if (!CONFIG.jwtSecret) {
			throw new Error("No JWT Secret");
		}
		if (
			typeof CONFIG.jwtSecret !== "string" ||
			CONFIG.jwtSecret.length !== 32
		) {
			throw new Error("Invalid JWT Secret");
		}
		const secret = CONFIG.jwtSecret;
		const verified = jwt.verify(token, secret);

		// Check if token is blacklisted
		if (!CONFIG.customTokenBlacklisting) {
			if (tokenBlacklist.find((t) => t.token === token)) {
				throw new Error("Token blacklisted");
			}
		}

		return verified;
	} catch (error) {
		//console.log("COULD NOT VERIFY JWT: ", error);
		return false;
	}
}

function addToTokenBlacklist(token) {
	try {
		const tokenData = verifyJWT(token);
		if (token) {
			if (tokenBlacklist.length > 500) {
				tokenBlacklist.shift();
			}
			tokenBlacklist.push({
				token,
				exp: tokenData.exp,
			});
			const currentUnixTime = Math.floor(Date.now() / 1000);

			tokenBlacklist = tokenBlacklist.filter((t) => t.exp > currentUnixTime);
		}
		return true;
	} catch (error) {
		console.log("COULD NOT CHECK TOKEN BLACKLIST: ", error);
		return false;
	}
}

/**
 * Logs out a user by clearing the token cookie
 * OPTIONAL: Add a redirectPath query parameter to redirect the user after logging out
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @returns {object} Express response object
 * @example
 * app.post("/logout", auth.logout);
 */
function logout(req, res) {
	try {
		// Add token to blacklist
		if (!CONFIG.customTokenBlacklisting) {
			addToTokenBlacklist(req.cookies[CONFIG.tokenCookieName]);
		}

		res.clearCookie(CONFIG.tokenCookieName);
		const redirectPath = req.query.redirectPath || CONFIG.loginRedirectPath;
		return res.status(200).json({ redirectPath });
	} catch (error) {
		console.log("COULD NOT LOGOUT: ", error);
		return res.status(500).json({ error: error.message });
	}
}

/**
 * Checks for a JWT token in the Authorization header or in the cookies
 * @param {object} req - Express request object
 * @returns {object} The decoded token
 * @example
 * const token = checkToken(req);
 * console.log(token); //{ id: 1, iat: 1621234567, exp: 1621234567 }
 */
function checkToken(req, res) {
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
			throw new Error("No token");
		}

		const verified = verifyJWT(token);
		if (!verified) {
			throw new Error("Invalid token");
		}

		return verified;
	} catch (error) {
		res.clearCookie(CONFIG.tokenCookieName);
		return false;
	}
}

// MIDDLEWARE

/**
 * Middleware to handle sessions.
 * Checks if a JWT token is present in the Authorization header or in the cookies
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Express next function
 * @returns {object} Express response object
 * @example
 * app.use(auth.handleSession);
 * app.get("/", (req, res, next) => {
 * 	res.status(200).json({
 * 		user: req.user,
 * 		});
 * });
 * app.get("/login", (req, res) => {
 * 	if (req.user) {
 * 		return res.redirect("/");
 * 	}
 * 	return res.sendFile(__dirname + "/views/login.html");
 * });
 */
function sessionHandler(req, res, next) {
	try {
		const token = checkToken(req, res);

		if (!token) {
			return next();
		}

		req.user = token;

		next();
	} catch (error) {
		return false;
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
		const token = checkToken(req, res);

		if (token) {
			req.user = token;
		} else {
			// If it's an API request
			if (req.headers["content-type"] === "application/json") {
				return res.status(401).json({ error: "Not authenticated" });
			}

			// For web requests, redirect
			return res.redirect(CONFIG.loginRedirectPath);
		}

		next();
	} catch (error) {
		console.log("COULD NOT ENSURE AUTH: ", error);
		return res.status(500).json({ error: error.message });
	}
}

module.exports = {
	init,
	hashPassword,
	authenticate,
	signJWT,
	verifyJWT,
	isStrongPassword,
	logout,
	ensureAuth,
	sessionHandler,
};
