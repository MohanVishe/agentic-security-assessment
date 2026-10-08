/* The one place that talks to the backend. Every address starts with /api/. */

/** Call the backend and return the JSON answer. Throws an Error with a readable message when it refuses. */
export async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json" },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try { detail = (await response.json()).detail || detail; } catch { /* not JSON */ }
    throw new Error(typeof detail === "string" ? detail : "Please check the values you entered.");
  }
  return response.json();
}
