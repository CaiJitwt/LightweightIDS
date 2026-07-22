import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { NetworkTopologyPage } from "./NetworkTopologyPage";

describe("NetworkTopologyPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders observed API connections and clears them after a reset refresh", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({
        nodes: [
          { id: "10.0.0.2", label: "Workstation 2", ip: "10.0.0.2", kind: "workstation", role: "Workstation", risk: 12, importance: 40, packets: 2, alerts: 0, lastSeen: "2026-07-15 09:00:01" },
          { id: "8.8.8.8", label: "8.8.8.8", ip: "8.8.8.8", kind: "external", role: "Other", risk: 0, importance: 0, packets: 2, alerts: 0, lastSeen: "2026-07-15 09:00:01" },
        ],
        edges: [
          { source: "10.0.0.2", target: "8.8.8.8", protocol: "DNS", packets: 2, bytes: 160, lastSeen: "2026-07-15 09:00:01" },
        ],
      }))
      .mockResolvedValueOnce(response({ nodes: [], edges: [] }));
    vi.stubGlobal("fetch", fetchMock);

    const { rerender } = render(<NetworkTopologyPage refreshVersion={0} />);
    expect(await screen.findByLabelText("Observed packet topology")).toBeInTheDocument();
    expect(screen.getByText("Workstation 2")).toBeInTheDocument();
    expect(screen.getAllByText("8.8.8.8")).toHaveLength(2);

    rerender(<NetworkTopologyPage refreshVersion={1} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/No packet connections are stored yet/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Observed packet topology")).not.toBeInTheDocument();
  });
});

function response(payload: object) {
  return { ok: true, json: async () => payload } as Response;
}
