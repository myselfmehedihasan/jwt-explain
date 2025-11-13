# 🔐 JWT Authentication Demo

**Learn JWT authentication by actually seeing how it works!**

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![React](https://img.shields.io/badge/React-18+-blue.svg)

> Stop reading boring docs. Start **playing** with JWT tokens and understand them in minutes!

## 🎯 What's This?

Ever wondered how apps know you're logged in? This interactive demo shows you **exactly** how JWT (JSON Web Tokens) work - no boring theory, just hands-on learning!

**Try it live:** [Demo Link](#) *(add your link)*

## ✨ What You'll Learn

- 🎫 How login creates a JWT token
- 🔍 What's actually inside a JWT
- 🚀 How to send tokens with requests
- ✅ How servers verify you're legit
- ⏰ Why tokens expire

## 🚀 Quick Start

```bash
# Clone it
git clone https://github.com/yourusername/jwt-authentication-demo.git

# Install stuff
npm install

# Run it
npm start
```

Open `http://localhost:3000` and start learning! 🎉

## 🎮 How to Use

1. **Login** with demo credentials:
   - Username: `demo` / Password: `password123`
   - Or: `admin` / `admin123`

2. **See your JWT token** - it's that long string!

3. **Decode it** - see what data is inside

4. **Access protected stuff** - use your token to get secret data

5. **Watch the magic** - see every step in the activity log

## 💡 JWT in 30 Seconds

```
You login → Server gives you a JWT token → You store it
   ↓
You want data → Send token with request → Server checks token
   ↓
Token valid? → You get the data! 🎉
```

**A JWT looks like:** `header.payload.signature`

Example:
```
eyJhbGci.eyJ1c2Vy.SflKxwRJ
  ↓        ↓         ↓
Header  Payload  Signature
```

## 🛠️ For Real Projects

Want to use JWT in your actual app? Here's the real code:

**Server (Node.js):**
```javascript
const jwt = require('jsonwebtoken');

// Login
app.post('/login', (req, res) => {
  const token = jwt.sign({ userId: user.id }, 'SECRET_KEY', { expiresIn: '1h' });
  res.json({ token });
});

// Protect routes
app.get('/protected', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  jwt.verify(token, 'SECRET_KEY', (err, user) => {
    if (err) return res.sendStatus(403);
    res.json({ data: 'Secret stuff!' });
  });
});
```

**Client (React):**
```javascript
// Store token
localStorage.setItem('token', token);

// Use it
fetch('/protected', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## 🎨 Features

- ✅ Interactive UI - click and learn
- ✅ Token decoder - see inside your JWT
- ✅ Activity log - track every step
- ✅ Real code examples - copy and use
- ✅ No backend needed - runs in browser!

## 🔒 Security Tips

- Never put secrets in tokens (no passwords!)
- Always use HTTPS
- Store tokens securely
- Set short expiration times
- Keep your SECRET_KEY actually secret!

## 🤝 Want to Help?

Found a bug? Have an idea? Contributions welcome!

1. Fork it
2. Create your branch (`git checkout -b cool-feature`)
3. Commit (`git commit -m 'Add cool feature'`)
4. Push (`git push origin cool-feature`)
5. Open a Pull Request

## 📚 Learn More

- [JWT.io](https://jwt.io/) - Official JWT site
- [Auth0 Guide](https://auth0.com/docs/secure/tokens/json-web-tokens) - Detailed JWT docs

## 📝 License

MIT - do whatever you want with this!

## 🙌 Credits

Made with ❤️ by [Your Name](https://github.com/yourusername)

Built with React, Tailwind CSS, and lots of coffee ☕

---

**⭐ If this helped you understand JWT, give it a star!**

*Questions? Open an issue or DM me on [Twitter](https://twitter.com/yourhandle)*
