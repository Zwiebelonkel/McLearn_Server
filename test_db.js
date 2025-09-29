import "dotenv/config";
import { createClient } from "@libsql/client";

async function testDatabaseConnection() {
  console.log("--- Starting Database Connection Test ---");

  if (!process.env.TURSO_URL || !process.env.TURSO_AUTH_TOKEN) {
    console.error("--- TEST FAILED ---");
    console.error("TURSO_URL or TURSO_AUTH_TOKEN is not defined in the environment.");
    return;
  }

  console.log("URL:", process.env.TURSO_URL);
  console.log("Auth Token Length:", process.env.TURSO_AUTH_TOKEN.length);

  const db = createClient({
    url: process.env.TURSO_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
  });

  try {
    console.log("Attempting to connect and execute a query...");
    const result = await db.execute("SELECT 1 as result;");
    console.log("--- TEST SUCCEEDED ---");
    console.log("Query result:", result.rows);
  } catch (error) {
    console.error("--- TEST FAILED ---");
    console.error("Error connecting to the database:", error);
  } finally {
    console.log("--- Database Connection Test Finished ---");
  }
}

testDatabaseConnection();
