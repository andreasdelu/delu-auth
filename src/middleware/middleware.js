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
		let authorized = false;

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
			/* return res.status(401).json({ error: "No token found" }); */
			authorized = false;
		}

		const verified = verifyJWT(token);
		if (!verified) {
			/* return res.status(401).json({ error: "Token signature mismatch" }); */
			authorized = false;
		}
		req.user = verified;
		authorized = true;

		if (!authorized) {
			// If it's an API request
			if (req.headers.accept === "application/json") {
				return res.status(401).json({ error: "Not authenticated" });
			}

			// For web requests, redirect
			const redirectPath = CONFIG.noAuthRedirectPath;
			return res.redirect(redirectPath);
		}

		next();
	} catch (error) {
		console.log("COULD NOT ENSURE AUTH: ", error);
		return res.status(500).json({ error: error.message });
	}
}

module.exports = { ensureAuth };
