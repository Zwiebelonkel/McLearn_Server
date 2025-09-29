import { createClient } from "@libsql/client";

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

await db.sync();

export default db;