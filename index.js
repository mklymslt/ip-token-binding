// A simple function to parse a specific cookie from the full Cookie header string.
function getCookie(cookieString, cookieName) {
  if (!cookieString) {
    return null;
  }
  
  const cookies = cookieString.split(';');
  for (const cookie of cookies) {
    
    if (cookie.trim().startsWith(`${cookieName}=`)) {
       
        return cookie.trim().substring(cookieName.length + 1);
    }
  }
  return null;
}

/**
 * Helper to decode the JWT payload without verification and extract the 'exp' claim.
 * Throws an error if the token is invalid or missing the 'exp' claim.
 * @param {string} token The raw JWT string.
 * @returns {{exp: number, payload: Object}} Decoded payload and expiration time.
 */
function decodeJWT(token) {
    if (!token) throw new Error("Token is null.");
    
    // JWT parts: Header.Payload.Signature
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Value did not look like a standard JWT (expected 3 parts).');
    }
    
    const base64UrlPayload = parts[1];
    
    // Convert Base64Url to Base64 (replace URL-safe chars)
    let base64 = base64UrlPayload.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding '=' signs
    while (base64.length % 4) {
        base64 += '=';
    }
    
    // Decode and parse the payload
    const payloadJson = atob(base64);
    const payload = JSON.parse(payloadJson);
    
    if (typeof payload.exp !== 'number') {
        throw new Error("JWT is missing the mandatory 'exp' (expiration) claim.");
    }

    return {
        exp: payload.exp,
        payload: payload
    };
}

/**
 * Main request handler logic.
 * @param {Request} request The incoming request object.
 * @param {Object} env The environment variables (including KV bindings).
 */
async function handleRequest(request, env) {
  
  

  // --- Configuration ---
  const KV_STORE_NAME = 'SESSION_STORE';
  const kvStore = env[KV_STORE_NAME];
  
  // 1. Get required values
  const clientIP = request.headers.get('cf-connecting-ip');
  const cookieString = request.headers.get('Cookie');
  const appSessionCookieValue = getCookie(cookieString, 'CF_AppSession');
  const authCookieValue = getCookie(cookieString, 'CF_Authorization');
  const host = request.headers.get('host');

  // --- Initial Checks ---

  if (!kvStore) {
    return new Response(`Configuration Error: KV Binding '${KV_STORE_NAME}' not found. Cannot enforce security policy.`, { status: 500 });
  }

  if (!appSessionCookieValue || !clientIP) {
    return new Response(`Forbidden`, { status: 403 });
  }

  // --- Core Security Flow  ---

  try {
    const storedIP = await kvStore.get(appSessionCookieValue);

    if (storedIP === null) {
      // --- Session NOT in KV: New IP Binding ---
      
      if (!authCookieValue) {
        return new Response("Forbidden", { status: 403 });
      }

      const decoded = decodeJWT(authCookieValue);
      const expirationTimestamp = decoded.exp;

      const currentTimeSeconds = Math.floor(Date.now() / 1000);
      const ttlSeconds = expirationTimestamp - currentTimeSeconds;

      if (ttlSeconds > 0) {
        // Store the client IP as the KV value, with TTL set to JWT expiration.
        await kvStore.put(appSessionCookieValue, clientIP, { expirationTtl: ttlSeconds });
      } else {
        return new Response(`Forbidden`, { status: 403 });
      }

    } else {
      // --- Session IS in KV: IP Check ---
      
      if (storedIP !== clientIP) {
        // IP Mismatch: Block Request (Session Hijacking Detected)
        const destinationURL = `https://${host}/cdn-cgi/access/logout`;
        //return new Response.redirect(destinationURL, { status: 302 }); // BLOCK IS FINAL for ALL paths
        //return new Response(`Forbidden`, { status: 403 });
        return Response.redirect(destinationURL, 302);
      }
    }

  } catch (e) {
    // Catch any unexpected KV or decoding errors
    return new Response(`Error`, { status: 500 });
  }

  // --- Final Action: Proxy Request to Origin ---
  // If execution reaches this point, the request is ALLOWED for ALL paths.
  return fetch(request);
}

// Bind the main request handler to the fetch event
export default {
    async fetch(request, env, ctx) {
        return handleRequest(request, env);
    }
};