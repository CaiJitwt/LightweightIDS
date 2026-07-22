const scenarios = [
  {
    id: "benign",
    title: "Benign request",
    description: "Normal form data for comparison.",
    expected: "No web attack alert expected",
    body: () => "message=demo-health-check&status=ok",
  },
  {
    id: "sql-injection",
    title: "SQL injection signature",
    description: "Inert SQL-like text; no database is connected.",
    expected: "Expected: SQL_INJECTION",
    body: () => "query=1%27+UNI" + "ON+SEL" + "ECT+username%2Cpassword+FROM+demo_users--",
  },
  {
    id: "xss",
    title: "XSS signature",
    description: "Encoded markup sent as text and never rendered.",
    expected: "Expected: XSS",
    body: () => "comment=%3C" + "script%3Eal" + "ert%28document.cookie%29%3C%2F" + "script%3E",
  },
  {
    id: "path-traversal",
    title: "Path traversal signature",
    description: "A path marker that never reaches the filesystem.",
    expected: "Expected: HTTP_SUSPICIOUS, WEB_ATTACK",
    body: () => "file=." + ".%2F." + ".%2F." + ".%2Fetc%2Fpass" + "wd",
  },
  {
    id: "command",
    title: "Command execution signature",
    description: "A command marker that is never executed.",
    expected: "Expected: MALICIOUS_COMMAND, WEB_ATTACK",
    body: () => "command=power" + "shell+-" + "enc+DEMO_ONLY_NOT_EXECUTABLE",
  },
  {
    id: "template-injection",
    title: "Template injection signature",
    description: "A template expression that is never evaluated.",
    expected: "Expected: WEB_ATTACK",
    body: () => "template=%7B%7B" + "7%2A7" + "%7D%7D",
  },
  {
    id: "ssrf",
    title: "SSRF signature",
    description: "An address marker that is never requested or forwarded.",
    expected: "Expected: HTTP_SUSPICIOUS, WEB_ATTACK",
    body: () => "url=http%3A%2F%2F169.254." + "169.254%2Flatest%2Fmeta-data%2F",
  },
];

const token = decodeURIComponent(window.location.hash.slice(1));
const state = document.querySelector("#session-state");
const list = document.querySelector("#scenario-list");
const log = document.querySelector("#activity-log");
const sequenceButton = document.querySelector("#send-sequence");
const customButton = document.querySelector("#send-custom");

state.textContent = token ? "Protected session ready" : "Classroom session ready";

for (const scenario of scenarios) {
  const article = document.createElement("article");
  const text = document.createElement("div");
  const title = document.createElement("h3");
  const description = document.createElement("p");
  const expected = document.createElement("small");
  const button = document.createElement("button");
  title.textContent = scenario.title;
  description.textContent = scenario.description;
  expected.textContent = scenario.expected;
  button.type = "button";
  button.textContent = "Send sample";
  button.addEventListener("click", () => sendScenario(scenario, button));
  text.append(title, description, expected);
  article.append(text, button);
  list.append(article);
}

sequenceButton.addEventListener("click", async () => {
  sequenceButton.disabled = true;
  for (const scenario of scenarios) {
    await sendScenario(scenario);
    await delay(650);
  }
  sequenceButton.disabled = false;
});

customButton.addEventListener("click", async () => {
  const input = document.querySelector("#custom-payload");
  if (!input.value.trim()) {
    addLog("Custom sample", false, "Enter text before sending.");
    return;
  }
  customButton.disabled = true;
  await send("custom", `text=${encodeURIComponent(input.value)}`, "Custom sample");
  customButton.disabled = false;
});

async function sendScenario(scenario, button) {
  if (button) button.disabled = true;
  await send(scenario.id, scenario.body(), scenario.title);
  if (button) button.disabled = false;
}

async function send(id, body, title) {
  try {
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (token) headers["X-Demo-Token"] = token;
    const response = await fetch(`/sink/${encodeURIComponent(id)}`, {
      method: "POST",
      headers,
      body,
    });
    const result = await response.json();
    const message = response.ok
      ? `Accepted as request #${result.sequence}; ${result.receivedBytes} bytes discarded.`
      : result.error;
    addLog(title, response.ok, message);
  } catch (error) {
    addLog(title, false, error instanceof Error ? error.message : "Request failed.");
  }
}

function addLog(title, success, message) {
  if (log.children.length === 1 && log.firstElementChild.textContent.startsWith("No requests")) log.textContent = "";
  const item = document.createElement("li");
  const time = new Date().toLocaleTimeString();
  item.className = success ? "success" : "failure";
  item.textContent = `${time} - ${title}: ${message}`;
  log.prepend(item);
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}
