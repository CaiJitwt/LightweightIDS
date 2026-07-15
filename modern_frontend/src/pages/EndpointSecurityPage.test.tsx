import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndpointSecurityPage } from "./EndpointSecurityPage";

describe("EndpointSecurityPage", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("keeps successful local checks when process collection fails", async () => {
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes("/api/security/posture")) return Promise.resolve(response({ checks: [{ identifier: "uac", title: "User Account Control", state: "pass", value: "Enabled", detail: "Read from local policy.", recommendation: "Keep UAC enabled." }] }));
      if (path.includes("/api/security/processes")) return Promise.reject(new Error("Access denied"));
      if (path.includes("/api/security/integrity/status")) return Promise.resolve(response({ available: false, paths: [], fileCount: 0, createdAt: "" }));
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    }));

    render(<EndpointSecurityPage refreshVersion={0} />);
    expect(await screen.findByText("User Account Control")).toBeInTheDocument();
    expect(screen.getByText(/Processes: Access denied/)).toBeInTheDocument();
    expect(screen.getByText("1/1")).toBeInTheDocument();
  });
});

function response(payload: object) {
  return { ok: true, json: async () => payload } as Response;
}
