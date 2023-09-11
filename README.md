# DeluAuth

### A simple authentication package for Node and Express

This authentication package provides a set of utilities for handling user authentication in Node.js applications using Express. It includes functions for hashing passwords, verifying passwords, signing JWT tokens, verifying JWT tokens, and middleware to ensure authentication.

## Table of Contents

- [Installation](#installation)
- [Initialization](#initialization)
- [Generating a JWT Secret](#generating-a-jwt-secret)
- [Usage](#usage)
  - [Hashing Passwords](#hashing-passwords)
  - [Verifying Passwords](#verifying-passwords)
  - [Authenticating Users](#authenticating-users)
  - [Authenticating Users with HOOKS](#authenticating-users-with-hooks)
  - [Verifying JWT Tokens](#verifying-jwt-tokens)
  - [Middleware for Authentication](#middleware-for-authentication)
  - [Middleware for Sessions](#middleware-for-sessions)
- [Configuration](#configuration)
- [Conclusion](#conclusion)
- [Examples](#examples)

## Installation

```zsh
npm install delu-auth
```

## Initialization

Before using any of the package's functionalities, you need to initialize it:

```javascript
const auth = require("delu-auth");
const jwtSecret = process.env.JWT_SECRET;

auth.init({
	jwtSecret,
	// Other configuration options
});
```

**Important**: Do not hard-code your JWT secret in your codebase. Always use environment variables or some other form of secure configuration management.

## Generating a JWT Secret

This package provides a utility function to generate a cryptographically secure JWT secret. To generate a secret:

```javascript
const { generateJWTSecret } = require("delu-auth");
const secret = generateJWTSecret();
console.log(secret);
```

**Note**: Run this function once, save the generated secret in your `.env` file or other secure location, and use it to initialize the authentication module. Do not regenerate the secret frequently, as it will invalidate all existing tokens.

## Usage

### Hashing Passwords

To hash a password:

```javascript
const hashedPassword = await auth.hashPassword("yourPassword");
```

### Verifying Passwords

To verify a password:

```javascript
const strongPassword = auth.isStrongPassword("yourPassword");
```

**Note**: This function only works when password requirements are enabled. See the [configuration section](#configuration) for more information.

### Authenticating Users

To authenticate a user:

```javascript
app.post("/login", async (req, res) => {
	const { password } = req.body;

	// Get hashed password from database
	const hashedPassword = await getHashedPasswordFromDB();

	const tokenContent = { id: 1 };

	await authenticate(req, res, password, hashedPassword, tokenContent);
	// returns res.status(200).json({ message: "Authentication successful" });
});
```

### Authenticating Users with HOOKS

To authenticate a user using hooks:

```javascript
app.post("/login", async (req, res) => {
	const { password } = req.body;

	// Get hashed password from database
	const hashedPassword = await getHashedPasswordFromDB();

	const tokenContent = { id: 1 };

	await authenticate(req, res, password, hashedPassword, tokenContent, {
		beforeAuthenticate: () => {
			// Do something before authenticating
			return true; // Return false to abort the authentication process
		},
		onSuccess: (token, res) => {
			// Do something on success (redirect, etc.)
		},
		onFailure: (error) => {
			// Do something on failure
		},
	});
});
```

### Verifying JWT Tokens

To verify a JWT token:

```javascript
const decoded = auth.verifyJWT("yourToken");
```

### Middleware for Authentication

To ensure a route is accessed only by authenticated users:

```javascript
app.get("/protected", auth.ensureAuth, (req, res) => {
	// Your route logic here
});
```

The middleware will check for a token in a cookie (by default named "token") or in the `Authorization` header as a Bearer token.

### Middleware for Sessions

Check the JWT and set the `user` property on the request object for each request:

```javascript
app.use(auth.sessionHandler);
```

This middleware does NOT handle redirecting the user or ensuring authentication. The purpose of this middleware is to have a global middleware that makes sure the `req.user` property is persistent on all routes, even if the route is not protected.

### Logging Out

To log out a user:

```javascript
app.post("/logout", auth.logout);
```

This will clear the token cookie and redirect the user to the `noAuthRedirectPath` which can be set in the [config](#configuration).

## Configuration

You can provide additional configuration when initializing:

```javascript
auth.init({
	jwtSecret: null, // JWT secret
	loginRedirectPath: "/login", // Default redirect path for the login route
	defaultRedirectPath: "/", // Default redirect path for the application
	tokenExpiration: 28800, // 8 hours (Must be in seconds)
	passwordSaltRounds: 10, // bcrypt salt rounds
	tokenAudience: "", // JWT audience
	tokenIssuer: "", // JWT issuer
	tokenCookieName: "token", // Name of the cookie to store the JWT
	customTokenBlacklisting: true, // How to handle token invalidation.
	//True(default): User handles blacklisting with custom code.
	//False: Invalidation is handled in the package. (WARNING This method might be the simplest but is not recommended for larger applications as the blacklisted tokens are stored in-memory)

	// Password requirements
	passwordRequirements: {
		enabled: false, // Enable password requirements
		minLength: 8, // Minimum length
		maxLength: 32, // Maximum length
		requireUppercase: true, // Require uppercase letters
		requireLowercase: true, // Require lowercase letters
		requireNumbers: true, // Require numbers
		requireSpecialCharacters: true, // Require special characters
	},
});
```

## Conclusion

This package aims to simplify authentication processes in Node.js applications. If you have any issues or suggestions, please open an issue on our GitHub repository.

## Examples

Check out the example repo to see the package implemented:
COMING SOON
