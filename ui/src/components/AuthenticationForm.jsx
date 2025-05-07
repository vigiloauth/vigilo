import { useState } from 'react';

export default function AuthenticationForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const urlParams = new URLSearchParams(window.location.search);
  const clientId = urlParams.get('client_id');
  const redirectUri = urlParams.get('redirect_uri');
  const state = urlParams.get('state');
  const scope = urlParams.get('scope');
  const responseType = urlParams.get('response_type');

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/identity/oauth2/authenticate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username,
          password,
          client_id: clientId,
          redirect_uri: redirectUri,
          state,
          scope,
          response_type: responseType
        }),
      });

      const data = await response.json();
      console.log(data)

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      if (data.oauth_redirect_url) {
        console.log(data.oauth_redirect_url)
        window.location.href = data.oauth_redirect_url;
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50">
      <div className="w-full max-w-md">
        <div className="rounded-lg bg-white p-8 shadow-md">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-bold text-gray-900">Sign In</h1>
          </div>

          {error && (
            <div className="mb-4 rounded-md bg-red-50 p-4">
              <div className="flex">
                <div className="text-sm text-red-700">{error}</div>
              </div>
            </div>
          )}

          <div className="space-y-6">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500"
              />
            </div>

            <div>
              <button
                onClick={handleSubmit}
                disabled={isLoading}
                className="w-full rounded-md bg-blue-600 py-2 px-4 text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:bg-blue-300"
              >
                {isLoading ? 'Signing in...' : 'Sign in'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}