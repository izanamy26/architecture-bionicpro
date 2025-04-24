const express = require("express");
const cors = require("cors");
const Keycloak = require("keycloak-connect");
const crypto = require("crypto");
const session = require("express-session");
const jwt = require("jsonwebtoken");

const app = express();

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_URL || "http://localhost:8080";
const REALM = process.env.KEYCLOAK_REALM || "reports-realm";

const CLIENT_ID = "reports-frontend";

const keycloak = new Keycloak(
  {},
  {
    serverUrl: KEYCLOAK_BASE_URL,
    realm: REALM,
    clientId: CLIENT_ID,
  }
);

app.use(
  cors({
    origin: "*",
  })
);
app.use(express.json());

app.use(
  session({
    secret: "public-client-secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(keycloak.middleware());

const generateCodeVerifier = (length = 128) => {
  const possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from({ length }, () =>
    possible.charAt(Math.floor(Math.random() * possible.length))
  ).join("");
};

const generateCodeChallenge = (code_verifier) => {
  return crypto.createHash("sha256").update(code_verifier).digest("base64url");
};

const requireAuth = (req, res, next) => {
  // Если у нас нет access_token в сессии — значит пользователь не авторизован
  if (!req.session?.access_token) {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Сохраняем в сессии — чтобы потом при /callback сравнить
    req.session.codeVerifier = codeVerifier;

    // Формируем ссылку на Keycloak /authorize
    const authorizeUrl =
      `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/auth` +
      `?client_id=${encodeURIComponent(CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent("http://localhost:8001/callback")}` +
      "&response_type=code" +
      "&scope=openid" +
      `&code_challenge=${encodeURIComponent(codeChallenge)}` +
      "&code_challenge_method=S256";

    // Редиректим для авторизации
    return res.redirect(authorizeUrl);
  } else {
    // Декодируем JWT токен, чтобы проверить роли пользователя
    const accessToken = req.session.access_token;

    const decodedToken = jwt.decode(accessToken);

    // Предполагается, что роли хранятся в `realm_access.roles`
    const roles = decodedToken?.realm_access?.roles || [];

    if (roles.includes("prothetic_user")) {
      next();
    } else {
      res.status(403).send("Доступ запрещен: недостаточно привилегий");
    }
  }
  // Если токен есть — пропускаем дальше
  next();
};

const generateRandomReports = (count = 5) => {
  const reportTypes = ["sales", "inventory", "users", "performance", "errors"];
  const statuses = ["completed", "failed", "pending", "processing"];

  return Array.from({ length: count }, (_, i) => ({
    id: `report-${Date.now()}-${i}`,
    type: reportTypes[Math.floor(Math.random() * reportTypes.length)],
    status: statuses[Math.floor(Math.random() * statuses.length)],
    createdAt: new Date(
      Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000
    ).toISOString(),
    metrics: {
      processedItems: Math.floor(Math.random() * 1000),
      successRate: Math.random().toFixed(2),
      executionTime: (Math.random() * 10).toFixed(2) + "s",
    },
  }));
};

app.get("/reports", requireAuth, (req, res) => {
  const reports = generateRandomReports();

  res.json({
    success: true,
    data: reports,
    meta: {
      generatedAt: new Date().toISOString(),
      count: reports.length,
    },
  });
});

app.get("/callback", async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.send(`Ошибка при авторизации: ${error}`);
  }

  if (!code) {
    return res.send('Не получен параметр "code"');
  }

  try {
    // Обмениваем code на токен
    const tokenUrl = `${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/token`;

    const params = new URLSearchParams();

    params.append("client_id", CLIENT_ID);
    params.append("code", code);
    params.append("redirect_uri", "http://localhost:8001/callback");
    params.append("code_verifier", req.session.codeVerifier);

    const tokenResponse = await axios.post(tokenUrl, params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    console.log("tokenResponse: ", tokenResponse);

    // Сохраняем полученные токены в сессию
    const { access_token, refresh_token } = tokenResponse.data;
    req.session.access_token = access_token;
    req.session.refresh_token = refresh_token;

    // Перенаправляем обратно на /reports или куда нужно
    res.redirect("/reports");
  } catch (err) {
    console.error("Ошибка при обмене code на токен:", err.message);
    res.send(`Ошибка при получении токена: ${err.message}`);
  }
});

app.listen(8001, () => {
  console.log(`API server running on port 8001`);
});
