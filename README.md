# DeluAuth
### A simple authentication package for Node and Express

This authentication package provides a set of utilities for handling user authentication in Node.js applications using Express. It includes functions for hashing passwords, verifying passwords, signing JWT tokens, verifying JWT tokens, and middleware to ensure authentication.

## Installation

```
npm install delu-auth
```

## Initialization

Before using any of the package's functionalities, you need to initialize it:

```javascript
const auth = require('delu-auth');
const jwtSecret = process.env.JWT_SECRET;

auth.init(jwtSecret);
```

**Important**: Do not hard-code your JWT secret in your codebase. Always use environment variables or some other form of secure configuration management.

## Generating a JWT Secret

This package provides a utility function to generate a cryptographically secure JWT secret. To generate a secret:

```javascript
const { generateJWTSecret } = require('delu-auth');
const secret = generateJWTSecret();
console.log(secret);
```

**Note**: Run this function once, save the generated secret in your `.env` file or other secure location, and use it to initialize the authentication module. Do not regenerate the secret frequently, as it will invalidate all existing tokens.

## Usage

### Hashing Passwords

To hash a password:

```javascript
const hashedPassword = await auth.hashPassword('yourPassword');
```

### Authenticating Users

To authenticate a user and get a JWT token:

```javascript
const token = await auth.authenticate('password', 'hashedPassword', { userId: 123 });
```

### Verifying JWT Tokens

To verify a JWT token:

```javascript
const decoded = auth.verifyJWT('yourToken');
```

### Middleware for Authentication

To ensure a route is accessed only by authenticated users:

```javascript
app.get('/protected', auth.ensureAuth, (req, res) => {
    // Your route logic here
});
```

The middleware will check for a token in a cookie (by default named "token") or in the `Authorization` header as a Bearer token.

## Configuration

You can provide additional configuration when initializing:

```javascript
auth.init(jwtSecret, {
    tokenCookieName: 'myToken', // Name of the cookie containing the JWT token
    passwordSaltRounds: 10, // Number of salt rounds used in bcrypt hashing
    tokenExpiration: 8 * 60 * 60, // Token expiration in seconds
    tokenAudience: "", // Token audience
    tokenIssuer: "", // Token issuer
});
```

## Conclusion

This package aims to simplify authentication processes in Node.js applications. If you have any issues or suggestions, please open an issue on our GitHub repository.
