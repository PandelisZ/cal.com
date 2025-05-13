import { defaultResponderForAppDir } from "app/api/defaultResponderForAppDir";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import jackson from "@calcom/features/ee/sso/lib/jackson";
import { HttpError } from "@calcom/lib/http-error";

// This is the callback endpoint for the OIDC provider
// A team must set this endpoint in the OIDC provider's configuration
import { cookies } from "next/headers";

async function handler(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const code = searchParams.get("code");
  const state = searchParams.get("state");

  if (!code || !state) {
    return NextResponse.json({ message: "Code and state are required" }, { status: 400 });
  }

  // --- CSRF State Verification ---
  // Get the stored cookie (if using app/dir API, use next/headers cookies, else use req.cookies)
  const cookieStore = cookies();
  const storedState = cookieStore.get("oidc_state")?.value;

  if (!storedState || storedState !== state) {
    return NextResponse.json({ message: "Invalid or expired state parameter (possible CSRF)" }, { status: 400 });
  }

  // Clear state cookie after verification
  const res = NextResponse.next();
  res.cookies.set("oidc_state", "", { httpOnly: true, secure: true, sameSite: "lax", maxAge: 0, path: "/" });

  const { oauthController } = await jackson();

  try {
    const { redirect_url } = await oauthController.oidcAuthzResponse({ code, state });

    if (!redirect_url) {
      throw new HttpError({
        message: "No redirect URL found",
        statusCode: 500,
      });
    }

    // Forward with cleared cookies
    const redirectRes = NextResponse.redirect(redirect_url, 302);
    redirectRes.cookies.set("oidc_state", "", { httpOnly: true, secure: true, sameSite: "lax", maxAge: 0, path: "/" });
    return redirectRes;
  } catch (err) {
    const { message, statusCode = 500 } = err as HttpError;

    return NextResponse.json({ message }, { status: statusCode });
  }
}

export const GET = defaultResponderForAppDir(handler);
