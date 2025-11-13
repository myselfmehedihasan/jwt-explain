import React, { useState } from 'react';
import { Lock, User, CheckCircle, XCircle, Key, Shield } from 'lucide-react';

// ============================================
// SIMULATED SERVER CODE (Normally in Node.js)
// ============================================

// Secret key for signing JWTs (in real app, this is in environment variable)
const SECRET_KEY = 'my-super-secret-key-123';

// Mock user database
const users = [
  { id: 1, username: 'demo', password: 'password123', role: 'user' },
  { id: 2, username: 'admin', password: 'admin123', role: 'admin' }
];

// Simple Base64 encoding/decoding (JWT uses this)
function base64Encode(str) {
  return btoa(str);
}

function base64Decode(str) {
  return atob(str);
}

// Create JWT Token (SERVER SIDE)
function createJWT(payload) {
  // JWT has 3 parts: Header.Payload.Signature
  
  // 1. Header
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  // 2. Payload (user data)
  const jwtPayload = {
    ...payload,
    iat: Date.now(), // issued at
    exp: Date.now() + 3600000 // expires in 1 hour
  };
  
  // 3. Encode header and payload
  const encodedHeader = base64Encode(JSON.stringify(header));
  const encodedPayload = base64Encode(JSON.stringify(jwtPayload));
  
  // 4. Create signature (simplified - real JWT uses HMAC SHA256)
  const signature = base64Encode(`${encodedHeader}.${encodedPayload}.${SECRET_KEY}`);
  
  // 5. Combine all parts
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Verify JWT Token (SERVER SIDE)
function verifyJWT(token) {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    
    // Verify signature
    const expectedSignature = base64Encode(`${encodedHeader}.${encodedPayload}.${SECRET_KEY}`);
    
    if (signature !== expectedSignature) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    // Decode payload
    const payload = JSON.parse(base64Decode(encodedPayload));
    
    // Check expiration
    if (payload.exp < Date.now()) {
      return { valid: false, error: 'Token expired' };
    }
    
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: 'Invalid token format' };
  }
}

// Login endpoint (SERVER SIDE)
function loginUser(username, password) {
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) {
    return { success: false, message: 'Invalid credentials' };
  }
  
  // Create JWT with user info
  const token = createJWT({
    userId: user.id,
    username: user.username,
    role: user.role
  });
  
  return { success: true, token, user: { id: user.id, username: user.username, role: user.role } };
}

// Protected endpoint (SERVER SIDE)
function getProtectedData(token) {
  const verification = verifyJWT(token);
  
  if (!verification.valid) {
    return { success: false, message: verification.error };
  }
  
  // Token is valid, return protected data
  return {
    success: true,
    data: {
      message: 'This is protected data!',
      secretInfo: '🎉 You have access!',
      user: verification.payload
    }
  };
}

// ============================================
// CLIENT SIDE (React Component)
// ============================================

export default function JWTDemo() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [user, setUser] = useState(null);
  const [protectedData, setProtectedData] = useState(null);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);

  const addLog = (message, type = 'info') => {
    setLogs(prev => [...prev, { message, type, time: new Date().toLocaleTimeString() }]);
  };

  // CLIENT: Handle Login
  const handleLogin = () => {
    setError('');
    setProtectedData(null);
    
    addLog(`🔄 Sending login request for: ${username}`, 'info');
    
    // Call server login function
    const result = loginUser(username, password);
    
    if (result.success) {
      setToken(result.token);
      setUser(result.user);
      addLog(`✅ Login successful! JWT token received`, 'success');
      addLog(`📝 Token stored in client`, 'success');
    } else {
      setError(result.message);
      addLog(`❌ Login failed: ${result.message}`, 'error');
    }
  };

  // CLIENT: Access Protected Resource
  const handleAccessProtected = () => {
    if (!token) {
      setError('Please login first!');
      return;
    }
    
    addLog(`🔄 Sending request with JWT token`, 'info');
    
    // Call server with JWT token
    const result = getProtectedData(token);
    
    if (result.success) {
      setProtectedData(result.data);
      addLog(`✅ Access granted! Data received`, 'success');
    } else {
      setError(result.message);
      setProtectedData(null);
      addLog(`❌ Access denied: ${result.message}`, 'error');
    }
  };

  // CLIENT: Logout
  const handleLogout = () => {
    setToken('');
    setUser(null);
    setProtectedData(null);
    addLog(`🚪 Logged out - JWT token removed`, 'info');
  };

  // Decode token to show its contents
  const decodeToken = (token) => {
    try {
      const [header, payload] = token.split('.');
      return {
        header: JSON.parse(base64Decode(header)),
        payload: JSON.parse(base64Decode(payload))
      };
    } catch {
      return null;
    }
  };

  const decodedToken = token ? decodeToken(token) : null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-800 mb-2 flex items-center justify-center gap-2">
            <Shield className="w-10 h-10 text-indigo-600" />
            JWT Authentication Demo
          </h1>
          <p className="text-gray-600">Learn how JWT works with a working example</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Login Section */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Lock className="w-6 h-6 text-indigo-600" />
              Step 1: Login
            </h2>
            
            {!user ? (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
                    placeholder="Try: demo or admin"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium mb-2">Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
                    placeholder="password123 or admin123"
                  />
                </div>
                
                <button
                  onClick={handleLogin}
                  className="w-full bg-indigo-600 text-white py-2 rounded-lg hover:bg-indigo-700 transition"
                >
                  Login & Get JWT Token
                </button>
                
                <div className="bg-blue-50 p-3 rounded text-sm">
                  <p className="font-semibold mb-1">Demo Credentials:</p>
                  <p>• demo / password123</p>
                  <p>• admin / admin123</p>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <span className="font-semibold text-green-800">Logged in as {user.username}</span>
                  </div>
                  <p className="text-sm text-gray-600">Role: {user.role}</p>
                </div>
                
                <button
                  onClick={handleLogout}
                  className="w-full bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 transition"
                >
                  Logout
                </button>
              </div>
            )}
            
            {error && (
              <div className="mt-4 bg-red-50 p-3 rounded-lg flex items-center gap-2 text-red-800">
                <XCircle className="w-5 h-5" />
                {error}
              </div>
            )}
          </div>

          {/* JWT Token Display */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Key className="w-6 h-6 text-indigo-600" />
              JWT Token
            </h2>
            
            {token ? (
              <div className="space-y-4">
                <div>
                  <p className="text-sm font-medium mb-2">Your Token:</p>
                  <div className="bg-gray-100 p-3 rounded text-xs break-all font-mono">
                    {token}
                  </div>
                </div>
                
                {decodedToken && (
                  <>
                    <div>
                      <p className="text-sm font-medium mb-2">Decoded Header:</p>
                      <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
                        {JSON.stringify(decodedToken.header, null, 2)}
                      </pre>
                    </div>
                    
                    <div>
                      <p className="text-sm font-medium mb-2">Decoded Payload:</p>
                      <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
                        {JSON.stringify(decodedToken.payload, null, 2)}
                      </pre>
                    </div>
                  </>
                )}
                
                <button
                  onClick={handleAccessProtected}
                  className="w-full bg-green-600 text-white py-2 rounded-lg hover:bg-green-700 transition"
                >
                  Step 2: Access Protected Data
                </button>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-400">
                <Key className="w-16 h-16 mx-auto mb-2 opacity-50" />
                <p>Login first to get your JWT token</p>
              </div>
            )}
          </div>

          {/* Protected Data */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold mb-4">Protected Data</h2>
            
            {protectedData ? (
              <div className="space-y-3">
                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                  <p className="font-semibold text-green-800 mb-2">✅ Access Granted!</p>
                  <p className="text-sm">{protectedData.message}</p>
                  <p className="text-2xl mt-2">{protectedData.secretInfo}</p>
                </div>
                
                <div className="bg-gray-50 p-3 rounded">
                  <p className="text-sm font-medium mb-1">Verified User Info:</p>
                  <pre className="text-xs overflow-auto">
                    {JSON.stringify(protectedData.user, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-400">
                <Shield className="w-16 h-16 mx-auto mb-2 opacity-50" />
                <p>Login and click "Access Protected Data" to see secret content</p>
              </div>
            )}
          </div>

          {/* Activity Log */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold mb-4">Activity Log</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {logs.length === 0 ? (
                <p className="text-gray-400 text-center py-4">No activity yet</p>
              ) : (
                logs.map((log, idx) => (
                  <div 
                    key={idx}
                    className={`p-2 rounded text-sm ${
                      log.type === 'success' ? 'bg-green-50 text-green-800' :
                      log.type === 'error' ? 'bg-red-50 text-red-800' :
                      'bg-blue-50 text-blue-800'
                    }`}
                  >
                    <span className="text-xs opacity-75">[{log.time}]</span> {log.message}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* How It Works */}
        <div className="mt-8 bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-2xl font-bold mb-4">📚 How This Works</h2>
          <div className="grid md:grid-cols-3 gap-4 text-sm">
            <div className="border-l-4 border-indigo-500 pl-4">
              <h3 className="font-bold mb-2">1. Login (Server)</h3>
              <p className="text-gray-600">Server verifies credentials and creates a JWT token containing user info. Token is signed with secret key.</p>
            </div>
            <div className="border-l-4 border-green-500 pl-4">
              <h3 className="font-bold mb-2">2. Store (Client)</h3>
              <p className="text-gray-600">Client receives and stores the JWT token in memory (or localStorage). No session needed on server!</p>
            </div>
            <div className="border-l-4 border-blue-500 pl-4">
              <h3 className="font-bold mb-2">3. Verify (Server)</h3>
              <p className="text-gray-600">Client sends JWT with each request. Server verifies signature and checks expiration to authenticate user.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}