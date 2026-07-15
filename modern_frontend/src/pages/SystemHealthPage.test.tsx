import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SystemHealthPage } from "./SystemHealthPage";

describe("SystemHealthPage", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("renders local API metrics instead of generated preview values", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({
      system: { hostname: "LAB-PC", platform: "Windows-11", cpuPercent: 17.5, logicalProcessors: 12, memoryUsedBytes: 8_589_934_592, memoryTotalBytes: 17_179_869_184, diskUsedBytes: 107_374_182_400, diskTotalBytes: 536_870_912_000, diskFreeBytes: 429_496_729_600 },
      engine: { apiVersion: 3, uptimeSeconds: 3670, databaseBytes: 1_048_576, rulesLoaded: 20, activeRules: 18, packetsStored: 321, alertsStored: 4, captureState: "running", captureInterface: "Ethernet", packetsPerSecond: 12.5, sessionPackets: 45, sessionAlerts: 2 },
      detectors: [{ id: "HOST_SCAN", name: "Host scan", enabled: true, severity: "HIGH", hits: 3 }],
    })));

    render(<SystemHealthPage refreshVersion={0} />);
    expect(await screen.findByText(/Local host: LAB-PC/)).toBeInTheDocument();
    expect(screen.getByText("17.5%")).toBeInTheDocument();
    expect(screen.getByText("12.5/s")).toBeInTheDocument();
    expect(screen.getByText("Host scan")).toBeInTheDocument();
    expect(screen.queryByText("2.8 GB")).not.toBeInTheDocument();
  });
});

function response(payload: object) {
  return { ok: true, json: async () => payload } as Response;
}
