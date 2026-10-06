import { ADMIN_SECTIONS, AdminClientError, createAdminClient, type AdminSection } from "./admin-client.js";

function requiredElement<T extends HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (element === null) throw new Error("Orbit Admin document is missing a required element.");
  return element;
}

const navigation = requiredElement<HTMLElement>("#section-navigation");
const title = requiredElement<HTMLElement>("#view-title");
const description = requiredElement<HTMLElement>("#view-description");
const dataTitle = requiredElement<HTMLElement>("#data-title");
const dataView = requiredElement<HTMLElement>("#data-view");
const connection = requiredElement<HTMLElement>("#connection-state");
const updated = requiredElement<HTMLElement>("#last-updated");
const refreshButton = requiredElement<HTMLButtonElement>("#refresh-button");
const notice = requiredElement<HTMLElement>("#notice");
const noticeTitle = requiredElement<HTMLElement>("#notice-title");
const noticeMessage = requiredElement<HTMLElement>("#notice-message");
const signInLink = requiredElement<HTMLAnchorElement>("#sign-in-link");

const client = createAdminClient();
let selected: AdminSection = "state";
let busy = false;

function setConnection(state: "connecting" | "connected" | "error", label: string): void {
  connection.dataset["state"] = state;
  connection.textContent = label;
}

function showNotice(error: unknown): void {
  notice.hidden = false;
  signInLink.hidden = true;
  if (error instanceof AdminClientError) {
    noticeTitle.textContent = error.status === 401 ? "Authentication required" : "Admin request failed";
    noticeMessage.textContent = error.message;
    signInLink.hidden = error.status !== 401;
    setConnection("error", error.status === 401 ? "Authentication required" : "Unavailable");
    return;
  }
  noticeTitle.textContent = "Unable to load Admin data";
  noticeMessage.textContent = "The response could not be displayed. Try refreshing the section.";
  setConnection("error", "Unavailable");
}

function hideNotice(): void {
  notice.hidden = true;
  signInLink.hidden = true;
}

async function loadSection(section: AdminSection): Promise<void> {
  if (busy) return;
  busy = true;
  selected = section;
  refreshButton.disabled = true;
  setConnection("connecting", "Refreshing");
  const definition = ADMIN_SECTIONS[section];
  title.textContent = definition.label;
  dataTitle.textContent = definition.label;
  description.textContent = "Current values reported by Orbit Core.";
  for (const button of navigation.querySelectorAll<HTMLButtonElement>("button[data-section]")) {
    if (button.dataset["section"] === section) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  try {
    const result = await client.read(section);
    dataView.textContent = JSON.stringify(result, null, 2) ?? "null";
    updated.textContent = `Updated ${new Intl.DateTimeFormat(undefined, {
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(new Date())}`;
    setConnection("connected", "Connected");
    hideNotice();
  } catch (error) {
    showNotice(error);
  } finally {
    busy = false;
    refreshButton.disabled = false;
  }
}

for (const [key, definition] of Object.entries(ADMIN_SECTIONS)) {
  const section = key as AdminSection;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "section-button";
  button.dataset["section"] = section;
  button.setAttribute("aria-current", section === selected ? "page" : "false");
  const icon = document.createElement("span");
  icon.className = "section-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = definition.icon;
  const label = document.createElement("span");
  label.textContent = definition.label;
  button.append(icon, label);
  button.addEventListener("click", () => void loadSection(section));
  navigation.append(button);
}

refreshButton.addEventListener("click", () => void loadSection(selected));
void loadSection(selected);
