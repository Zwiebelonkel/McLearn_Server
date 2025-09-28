import { createClient } from "@libsql/client";

export const db = createClient({
  url: process.env.DATABASE_URL || process.env.TURSO_URL,
  authToken: process.env.DATABASE_AUTH_TOKEN || process.env.TURSO_TOKEN,
});

export async function all(sql, params = []) {
  const { rows } = await db.execute({ sql, args: params });
  return rows;
}
export async function one(sql, params = []) {
  const { rows } = await db.execute({ sql, args: params });
  return rows[0] || null;
}
export async function run(sql, params = []) {
  return db.execute({ sql, args: params });
}
