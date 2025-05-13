import { SignJWT } from "jose";
import { WEBSITE_URL } from "@calcom/lib/constants";

/**
 * signJwt - Audit & Documentation
 *
 * - Uses HS256 (HMAC SHA-256) for signing short-lived tokens.
 * - Signing secret is sourced from CALENDSO_ENCRYPTION_KEY (must be kept secure and random).
 * - Issued tokens have "sub", "iat", "iss", "aud", and short expiry ("exp": 2m).
 * - All JWT handling is performed by the `jose` library for robust standards compliance.
 *
 * Security notes:
 * - If CALENDSO_ENCRYPTION_KEY is missing or weak, token security is at risk.
 * - HS256 is secure for single-server/trusted infra, but use RS256 for multi-service/public-token scenarios.
 * - Tokens are short-lived to mitigate replay risks, but must be handled over HTTPS only.
 *
 * To upgrade to RS256:
 *   - Generate an RSA keypair (use openssl or node-forge).
 *   - Replace `.sign(secret)` with `.sign(privateKey)` and ensure public key is used for verification.
 *   - Update consuming services to verify using public key.
 *
 * All signing/validation errors must be handled gracefully -- do NOT leak token details/errors to clients.
 */
const signJwt = async (payload: { email: string }) => {
  const jwtSecret = process.env.CALENDSO_ENCRYPTION_KEY;
  if (!jwtSecret || jwtSecret.length < 32) {
    throw new Error(
      "CALENDSO_ENCRYPTION_KEY must be set to a strong (at least 32 chars) random string for JWT signing."
    );
  }
  const secret = new TextEncoder().encode(jwtSecret);

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(payload.email)
    .setIssuedAt()
    .setIssuer(WEBSITE_URL)
    .setAudience(`${WEBSITE_URL}/auth/login`)
    .setExpirationTime("2m")
    .sign(secret);
};

export default signJwt;
