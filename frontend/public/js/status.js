/* The small label at the top right: are all parts of the system running, and which AI model is in use? */

import { api } from "./api.js";
import { state } from "./ui.js";
import { updateStartButton } from "./views/new-check.js";

export async function refreshStatus() {
  const pill = document.getElementById("status");
  try {
    state.status = await api("/api/status");
    const { ready, services, llm } = state.status;
    const down = Object.entries(services).filter(([, up]) => !up).map(([name]) => name);
    if (ready) {
      pill.className = "pill pill-ok";
      pill.textContent = `Ready · ${llm.model}`;
      pill.title = "All parts are running.";
    } else if (!llm.key_set) {
      pill.className = "pill pill-bad";
      pill.textContent = "No LLM key set";
      pill.title = "Put your key in LLM_API_KEY in the .env file, then run: docker compose up -d";
    } else {
      pill.className = "pill pill-wait";
      pill.textContent = `Starting: ${down.join(", ")}`;
      pill.title = "The containers are still starting. This can take a minute or two.";
    }
  } catch {
    pill.className = "pill pill-bad";
    pill.textContent = "Backend not reachable";
  }
  updateStartButton();
  // Ask again soon while things are starting, and only now and then once everything is up.
  setTimeout(refreshStatus, state.status?.ready ? 30000 : 4000);
}
