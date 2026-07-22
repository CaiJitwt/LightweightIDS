import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

import App from "./App";

describe("modern IDS frontend", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders persisted dashboard data when the local API is available", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({
        capture: { state: "running", interface: "Loopback", filterExpression: "", savePackets: true, detectionEnabled: true, packetTotal: 0, alertTotal: 0, skippedTotal: 0, savedPacketTotal: 0, savedAlertTotal: 0, packetsPerSecond: 0, error: "", nextSequence: 0 },
        statistics: { packetTotal: 128, alertTotal: 2, openAlerts: 1, highPriorityAlerts: 1, highRiskHosts: 1, lastHourPackets: 16 },
        trend: [
          { time: "11:59", bucket: "2026-07-13 11:59", alerts: 0, packets: 0, spike: false },
          { time: "12:00", bucket: "2026-07-13 12:00", alerts: 1, packets: 16, spike: false },
        ],
        trendBucket: "minute",
        severityDistribution: [{ name: "High", value: 2, color: "#e5484d" }],
        highRiskHosts: [{ ip: "10.0.0.42", name: "Lab host", role: "Workstation", risk: 82, importance: 0, packets: 128, alerts: 2, lastSeen: "2026-07-13 12:00" }],
        recentAlerts: [{ id: 7, timestamp: "2026-07-13 12:00", severity: "HIGH", ruleId: "HOST_SCAN", ruleName: "Host scan", source: "10.0.0.42:51000", destination: "10.0.0.10:22", protocol: "TCP", description: "Repeated connections", evidence: "targets=2", status: "unconfirmed" }],
      }),
    } as Response);

    render(<App />);

    expect(await screen.findByText("128", {}, { timeout: 3000 })).toBeInTheDocument();
    expect(screen.getByText("Local SQLite data - recent observed minutes")).toBeInTheDocument();
    expect(screen.getByText("Lab host")).toBeInTheDocument();
    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(await within(navigation).findByTitle("1 unconfirmed alerts")).toHaveTextContent("1");
    expect(within(navigation).getByRole("button", { name: /Alert Center/ })).not.toHaveTextContent("9");
  });

  it("navigates from the dashboard to alert evidence", async () => {
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("button", { name: /Alert Center/ }));

    expect(await screen.findByRole("heading", { name: "Alert center" })).toBeInTheDocument();
    expect(await screen.findByRole("complementary", { name: "Selected alert details" })).toHaveTextContent("Related packets");
    expect(screen.getByText("TLS metadata indicates a weak protocol fingerprint.")).toBeInTheDocument();
    const language = screen.getByRole("group", { name: "Response" });
    expect(within(language).getByRole("button", { name: "English" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(within(language).getByRole("button", { name: "Chinese" }));
    expect(within(language).getByRole("button", { name: "Chinese" })).toHaveAttribute("aria-pressed", "true");
  });

  it("filters the traffic table by protocol", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Traffic Monitor" }));
    const packetRows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(packetRows[1]).toHaveTextContent("8421");
    fireEvent.change(await screen.findByRole("combobox", { name: "Protocol" }), { target: { value: "DNS" } });

    expect(screen.getByText(/1 packets shown/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Query A api.internal.example"));
    expect(screen.getByRole("complementary", { name: "Selected packet details" })).toHaveTextContent("Packet #8419");
    expect(screen.getByText("Complete stored metadata")).toBeInTheDocument();
  });

  it("opens the Windows security event workspace from the sidebar", async () => {
    render(<App />);

    fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("button", { name: "Security Events" }));

    expect(await screen.findByRole("heading", { name: "Security events" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Start monitoring" })).toBeInTheDocument();
  });

  it("defaults to the system theme and keeps the persisted LLM key masked", async () => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: () => ({ matches: true, addEventListener: () => undefined, removeEventListener: () => undefined }),
    });
    render(<App />);

    expect(document.querySelector(".app-shell")).toHaveAttribute("data-theme", "dark");
    fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("button", { name: "Settings" }));
    expect(await screen.findByRole("heading", { name: "LLM defense guidance" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Enter API key")).toHaveAttribute("type", "password");
    expect(screen.queryByTitle("Show API key")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^System$/ })).toHaveClass("selected");
  });

  it("switches the help language and opens a page from quick navigation", async () => {
    render(<App />);

    fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("button", { name: "Help Center" }));
    expect(await screen.findByRole("heading", { name: "Help center" })).toBeInTheDocument();
    // Wait for the HelpPage to finish lazy-loading
    expect(await screen.findByText("Help language")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "中文" }));
    expect(screen.getByRole("heading", { name: "帮助中心", level: 2 })).toBeInTheDocument();
    expect(localStorage.getItem("ids-prototype-locale")).toBe("zh");

    const quickNavigation = screen.getByRole("heading", { name: "快速导航" }).closest("section");
    expect(quickNavigation).not.toBeNull();
    fireEvent.click(within(quickNavigation as HTMLElement).getByRole("button", { name: "仪表盘" }));
    expect(await screen.findByRole("heading", { name: "安全概览" })).toBeInTheDocument();
  });

  it("renders and clears a persisted workspace wallpaper", async () => {
    localStorage.setItem("ids-prototype-personalization", JSON.stringify({
      background: "data:image/png;base64,wallpaper",
      backgroundPosition: "top-left",
      backgroundSize: "contain",
      backgroundOpacity: 60,
    }));

    render(<App />);

    const wallpaper = await screen.findByTestId("workspace-wallpaper");
    expect(wallpaper).toHaveStyle({
      backgroundImage: "url(data:image/png;base64,wallpaper)",
      backgroundPosition: "top-left",
      backgroundSize: "contain",
      opacity: "0.6",
    });

    fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("button", { name: "Personalization" }));
    fireEvent.click(await screen.findByTitle("Clear wallpaper"));
    expect(screen.queryByTestId("workspace-wallpaper")).not.toBeInTheDocument();
  });

  it("applies and updates persisted glass surface controls", async () => {
    render(<App />);

    const shell = document.querySelector(".app-shell") as HTMLElement;
    expect(shell.style.getPropertyValue("--component-opacity")).toBe("92%");
    expect(shell.style.getPropertyValue("--component-blur")).toBe("6px");
    expect(shell.style.getPropertyValue("--table-opacity")).toBe("94%");
    expect(shell.style.getPropertyValue("--table-blur")).toBe("4px");

    fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("button", { name: "Personalization" }));
    fireEvent.change(await screen.findByLabelText("Component opacity"), { target: { value: "78" } });
    fireEvent.change(screen.getByLabelText("Component blur"), { target: { value: "12" } });
    fireEvent.change(screen.getByLabelText("Table opacity"), { target: { value: "82" } });
    fireEvent.change(screen.getByLabelText("Table blur"), { target: { value: "9" } });
    fireEvent.change(screen.getByLabelText("Surface tint"), { target: { value: "#446688" } });

    expect(shell.style.getPropertyValue("--component-opacity")).toBe("78%");
    expect(shell.style.getPropertyValue("--component-blur")).toBe("12px");
    expect(shell.style.getPropertyValue("--component-tint")).toBe("#446688");
    expect(shell.style.getPropertyValue("--table-opacity")).toBe("82%");
    expect(shell.style.getPropertyValue("--table-blur")).toBe("9px");

    await waitFor(() => {
      const saved = JSON.parse(localStorage.getItem("ids-prototype-personalization") ?? "{}");
      expect(saved.componentOpacity).toBe(78);
      expect(saved.componentBlur).toBe(12);
      expect(saved.tableOpacity).toBe(82);
      expect(saved.tableBlur).toBe(9);
    });
  });
});
