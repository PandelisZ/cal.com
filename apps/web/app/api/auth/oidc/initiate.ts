import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

// This endpoint initiates the OIDC login flow.
// It generates a random state, stores it in a secure cookie, and redirects to the OIDC provider.
export async function GET(req: NextRequest) {
  // Generate a secure random state parameter (base64url)
  const state = crypto.randomBytes(32).toString("base64url");

  // Build authorization URL (replace with actual OIDC provider/logic)
  // Example:
  const OIDC_AUTHORIZE_URL = process.env.OIDC_AUTHORIZE_URL;
  const client_id = process.env.OIDC_CLIENT_ID;
  const redirect_uri = process.env.OIDC_REDIRECT_URI;

  // Real implementation should add scope and any required params
  const authorizeUrl = new URL(OIDC_AUTHORIZE_URL ?? "");
  authorizeUrl.searchParams.set("client_id", client_id ?? "");
  authorizeUrl.searchParams.set("redirect_uri", redirect_uri ?? "");
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", "openid email profile");
  authorizeUrl.searchParams.set("state", state);

  // Set the state in a secure, HttpOnly, SameSite cookie to verify later
  const response = NextResponse.redirect(authorizeUrl.toString(), 302);
  response.cookies.set("oidc_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "lax", // or "strict" if possible
    maxAge: 60 * 5, // 5 minute expiry
    path: "/",
  });

  return response;
}