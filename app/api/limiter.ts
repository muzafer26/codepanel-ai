const ipCache = new Map<string, { count: number; resetTime: number }>();

/**
 * Basic IP-based rate limiting helper.
 * Defaults to 30 requests per minute.
 */
export function rateLimit(ip: string | null, limit = 30, windowMs = 60 * 1000): boolean {
  if (!ip) return true; // If IP can't be resolved, permit request rather than block

  const now = Date.now();
  const userData = ipCache.get(ip) || { count: 0, resetTime: now + windowMs };

  if (now > userData.resetTime) {
    userData.count = 1;
    userData.resetTime = now + windowMs;
  } else {
    userData.count++;
  }

  ipCache.set(ip, userData);

  return userData.count <= limit;
}
