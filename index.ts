/*
  yandex-auth — вход через Яндекс ID для проектов на Supabase,
  где нет встроенного провайдера «Яндекс».

  Схема:
    браузер → /yandex-auth/start      → редирект на oauth.yandex.ru
    Яндекс  → /yandex-auth/callback   → обмен кода на токен, профиль,
                                        выдача одноразового токена Supabase
    браузер ← редирект на сайт с #ya=<token_hash>
    сайт    → POST /auth/v1/verify    → обычная сессия Supabase

  Переменные окружения (Supabase → Edge Functions → Secrets):
    YANDEX_CLIENT_ID       — ID приложения с oauth.yandex.ru
    YANDEX_CLIENT_SECRET   — его секрет
    ALLOWED_REDIRECTS      — адреса сайта через запятую, куда можно вернуть
                             человека, например:
                             https://aywamarket.ru/
  SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY платформа подставляет сама.

  Деплой:
    supabase functions deploy yandex-auth --no-verify-jwt

  В приложении на oauth.yandex.ru укажите Redirect URI:
    https://<ваш-проект>.supabase.co/functions/v1/yandex-auth/callback
  и права «Доступ к адресу почты» + «Доступ к имени и фамилии».
*/

const YA_ID = Deno.env.get("YANDEX_CLIENT_ID") ?? "";
const YA_SECRET = Deno.env.get("YANDEX_CLIENT_SECRET") ?? "";
const SB_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const ALLOWED = (Deno.env.get("ALLOWED_REDIRECTS") ?? "")
  .split(",").map((s) => s.trim()).filter(Boolean);

const admin = {
  apikey: SERVICE_KEY,
  Authorization: `Bearer ${SERVICE_KEY}`,
  "Content-Type": "application/json",
};

/* назад на сайт: результат передаём в хэше, чтобы он не попал в логи сервера */
function back(target: string, params: Record<string, string>) {
  const hash = new URLSearchParams(params).toString();
  return new Response(null, { status: 302, headers: { Location: `${target}#${hash}` } });
}

const isAllowed = (r: string) => ALLOWED.some((a) => r === a || r.startsWith(a));

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const base = `${url.origin}${url.pathname.replace(/\/(start|callback)\/?$/, "")}`;

  /* ── шаг 1: уводим человека в Яндекс ──────────────────────────── */
  if (!url.pathname.endsWith("/callback")) {
    const redirect = url.searchParams.get("redirect") ?? ALLOWED[0] ?? "";
    if (!isAllowed(redirect)) {
      return new Response("Этот адрес возврата не разрешён", { status: 400 });
    }
    const state = btoa(JSON.stringify({ r: redirect, n: crypto.randomUUID() }));
    const ya = new URL("https://oauth.yandex.ru/authorize");
    ya.searchParams.set("response_type", "code");
    ya.searchParams.set("client_id", YA_ID);
    ya.searchParams.set("redirect_uri", `${base}/callback`);
    ya.searchParams.set("state", state);
    return Response.redirect(ya.toString(), 302);
  }

  /* ── шаг 2: Яндекс вернул код ─────────────────────────────────── */
  let target = ALLOWED[0] ?? "";
  try {
    const st = JSON.parse(atob(url.searchParams.get("state") ?? ""));
    if (typeof st.r === "string" && isAllowed(st.r)) target = st.r;
  } catch { /* адрес возьмём первый разрешённый */ }

  const denied = url.searchParams.get("error_description") ?? url.searchParams.get("error");
  if (denied) return back(target, { ya_error: denied });

  const code = url.searchParams.get("code");
  if (!code) return back(target, { ya_error: "Яндекс не вернул код авторизации" });

  try {
    /* код → токен Яндекса */
    const tokRes = await fetch("https://oauth.yandex.ru/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: YA_ID,
        client_secret: YA_SECRET,
      }),
    });
    const tok = await tokRes.json();
    if (!tokRes.ok) throw new Error(tok.error_description ?? tok.error ?? "обмен кода не удался");

    /* токен → профиль */
    const infoRes = await fetch("https://login.yandex.ru/info?format=json", {
      headers: { Authorization: `OAuth ${tok.access_token}` },
    });
    const info = await infoRes.json();
    if (!infoRes.ok) throw new Error("не удалось прочитать профиль Яндекса");

    const email: string = info.default_email ?? info.emails?.[0] ?? `${info.id}@yandex.uid`;
    const name: string = info.real_name || info.display_name || info.first_name ||
      info.login || email.split("@")[0];
    const meta = { name, auth_provider: "yandex", yandex_id: String(info.id) };

    /* профиль → пользователь Supabase + одноразовый токен.
       generate_link с типом magiclink заводит пользователя, если его ещё нет. */
    const linkRes = await fetch(`${SB_URL}/auth/v1/admin/generate_link`, {
      method: "POST",
      headers: admin,
      body: JSON.stringify({ type: "magiclink", email, data: meta }),
    });
    const link = await linkRes.json();
    if (!linkRes.ok) throw new Error(link.msg ?? link.error_description ?? "Supabase отказал в выдаче сессии");

    /* если аккаунт уже был — освежаем имя и отметку провайдера */
    const uid = link.user?.id ?? link.id;
    if (uid) {
      await fetch(`${SB_URL}/auth/v1/admin/users/${uid}`, {
        method: "PUT",
        headers: admin,
        body: JSON.stringify({ email_confirm: true, user_metadata: meta }),
      });
    }

    const hashed = link.hashed_token ?? link.properties?.hashed_token;
    if (!hashed) throw new Error("Supabase не вернул одноразовый токен");

    return back(target, { ya: hashed });
  } catch (e) {
    return back(target, { ya_error: String((e as Error).message ?? e) });
  }
});
